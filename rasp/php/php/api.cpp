#include "api.h"
#include "hash.h"
#include <iomanip>
#include <zero/strings/strings.h>
#include <Zend/zend_builtin_functions.h>
#include <Zend/zend_constants.h>

bool callUserFunction(
        HashTable *table,
        zval *object,
        const char *name,
        zval *ret,
        uint32_t argc,
        zval argv[]
#if PHP_MAJOR_VERSION <= 5
        TSRMLS_DC
#endif
) {
    zval function;

#if PHP_MAJOR_VERSION > 5
    ZVAL_STRING(&function, name);

    if (call_user_function(table, object, &function, ret, argc, argv) != SUCCESS) {
        zval_ptr_dtor(&function);
        return false;
    }

    zval_ptr_dtor(&function);
#else
    INIT_ZVAL(function)
    ZVAL_STRING(&function, name, 0); // "duplicate" is 0, no need to free.

    std::unique_ptr<zval *[]> params = std::make_unique<zval *[]>(argc);

    for (uint32_t i = 0; i < argc; i++)
        params[i] = &argv[i];

    if (call_user_function(table, &object, &function, ret, argc, params.get() TSRMLS_CC) != SUCCESS)
        return false;
#endif

    return true;
}

std::string curlInfo(
        zval *val
#if PHP_MAJOR_VERSION <= 5
        TSRMLS_DC
#endif
) {
    std::string info;

#if PHP_MAJOR_VERSION > 5
    zval *opt = zend_get_constant_str(ZEND_STRL("CURLINFO_EFFECTIVE_URL"));

    if (!opt)
        return "";

    zval url;
    ZVAL_NULL(&url);

    zval args[] = {*val, *opt};

    if (!callUserFunction(EG(function_table), nullptr, "curl_getinfo", &url, 2, args)) {
        zval_ptr_dtor(&url);
        return "";
    }

    info = toString(&url);
    zval_ptr_dtor(&url);
#else
    zval opt;

    if (!zend_get_constant(ZEND_STRL("CURLINFO_EFFECTIVE_URL"), &opt TSRMLS_CC))
        return "";

    zval url;
    INIT_ZVAL(url)

    zval args[] = {*val, opt};

    if (!callUserFunction(EG(function_table), nullptr, "curl_getinfo", &url, 2, args TSRMLS_CC)) {
        zval_dtor(&opt);
        zval_dtor(&url);
        return "";
    }

    info = toString(&url TSRMLS_CC);

    zval_dtor(&opt);
    zval_dtor(&url);
#endif

    return info;
}

std::string toString(
        zval *val
#if PHP_MAJOR_VERSION <= 5
        TSRMLS_DC
#endif
) {
    if (!val)
        return "";

    switch (Z_TYPE_P(val)) {
        case IS_NULL:
            return "null";

#if PHP_MAJOR_VERSION > 5
        case IS_FALSE:
            return "false";

        case IS_TRUE:
            return "true";
#else
        case IS_BOOL:
            return Z_BVAL_P(val) ? "true" : "false";
#endif

        case IS_LONG:
            return std::to_string(Z_LVAL_P(val));

        case IS_DOUBLE:
            return std::to_string(Z_DVAL_P(val));

        case IS_STRING:
            return {Z_STRVAL_P(val), (std::size_t) Z_STRLEN_P(val)};

        case IS_ARRAY: {
            auto quoted = [](const std::string &str) -> std::string {
                std::stringstream ss;
                ss << std::quoted(str);

                return ss.str();
            };

            bool uneven = false;
            std::map<std::string, std::string> kv;

            for (const auto &e: Z_ARRVAL_P(val)) {
                switch (e.type) {
                    case HASH_KEY_IS_LONG:
                        kv.insert({
                            std::to_string(std::get<unsigned long>(e.key)),
                            toString(
                                    e.value
#if PHP_MAJOR_VERSION <= 5
                                    TSRMLS_CC
#endif
                            )
                        });

                        break;

                    case HASH_KEY_IS_STRING:
                        uneven = true;

                        kv.insert({
                            quoted(std::get<std::string>(e.key)),
                            toString(
                                    e.value
#if PHP_MAJOR_VERSION <= 5
                                    TSRMLS_CC
#endif
                            )
                        });

                        break;

                    default:
                        break;
                }
            }

            std::list<std::string> items;

            if (!uneven) {
                std::transform(
                        kv.begin(),
                        kv.end(),
                        std::back_inserter(items),
                        [](const auto &it) {
                            return it.second;
                        }
                );

                return zero::strings::join(items, " ");
            }

            std::transform(
                    kv.begin(),
                    kv.end(),
                    std::back_inserter(items),
                    [&](const auto &it) {
                        return it.first + ": " + quoted(it.second);
                    }
            );

            return zero::strings::format("{%s}", zero::strings::join(items, ", ").c_str());
        }

#if PHP_MAJOR_VERSION >= 8
        case IS_OBJECT: {
            const char *type = ZSTR_VAL(Z_OBJ_P(val)->ce->name);
            if (!type)
                break;

            if (strcmp(type, "CurlHandle") == 0)
                return curlInfo(
                        val
#if PHP_MAJOR_VERSION <= 5
                        TSRMLS_CC
#endif
                );
            return zero::strings::format("object(%s)", type);
        }
#endif

        case IS_RESOURCE: {
            const char *type = zend_rsrc_list_get_rsrc_type(
#if PHP_MAJOR_VERSION > 5
                    Z_RES_P(val)
#else
                    Z_LVAL_P(val) TSRMLS_CC
#endif
            );

            if (!type)
                break;

            if (strcmp(type, "curl") == 0)
                return curlInfo(
                        val
#if PHP_MAJOR_VERSION <= 5
                        TSRMLS_CC
#endif
                );

            return zero::strings::format("resource(%s)", type);
        }

        default:
            break;
    }

    return "unknown";
}

std::vector<std::string> traceback(
#if PHP_MAJOR_VERSION <= 5
        TSRMLS_D
#endif
) {
    zval array = {};
    std::vector<std::string> stackTrace;

#if PHP_MAJOR_VERSION == 5
#if PHP_MINOR_VERSION <= 3
    zend_fetch_debug_backtrace(&array, 0, 0 TSRMLS_CC);
#else
    zend_fetch_debug_backtrace(&array, 0, 0, 0 TSRMLS_CC);
#endif
#else
    zend_fetch_debug_backtrace(&array, 0, 0, 0);
#endif

    if (Z_TYPE(array) != IS_ARRAY) {
        zval_dtor(&array);
        return stackTrace;
    }

    for (const auto &e: Z_ARRVAL(array)) {
        if (Z_TYPE_P(e.value) != IS_ARRAY)
            continue;

        zval *file = hashFind(Z_ARRVAL_P(e.value), "file");
        zval *function = hashFind(Z_ARRVAL_P(e.value), "function");
        zval *line = hashFind(Z_ARRVAL_P(e.value), "line");

        if (!file || !function || !line || Z_TYPE_P(file) != IS_STRING || Z_TYPE_P(function) != IS_STRING ||
            Z_TYPE_P(line) != IS_LONG)
            continue;

        stackTrace.push_back(
                zero::strings::format(
                        "%s(%s:%ld)",
                        Z_STRVAL_P(function),
                        Z_STRVAL_P(file),
                        Z_LVAL_P(line)
                )
        );
    }

    zval_dtor(&array);

    return stackTrace;
}
