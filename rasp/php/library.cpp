#include "library.h"
#include "php/api.h"
#include "php/hash.h"
#include "client/smith_probe.h"
#include <php.h>
#include <standard/info.h>
#include <zero/log.h>

constexpr auto TRACKS = std::array{
        "_POST",
        "_GET",
        "_COOKIE",
        "_SERVER",
        "_ENV",
        "_FILES",
        "_REQUEST"
};

zval *HTTPGlobals(
        int id
#if PHP_MAJOR_VERSION <= 5
        TSRMLS_DC
#endif
) {
    if (id >= TRACKS.size())
        return nullptr;

#if PHP_MAJOR_VERSION > 5
    if (Z_TYPE(PG(http_globals)[id]) != IS_ARRAY && !zend_is_auto_global_str((char *) TRACKS[id], strlen(TRACKS[id])))
        return nullptr;

    return &PG(http_globals)[id];
#else
    if ((!PG(http_globals)[id] || Z_TYPE_P(PG(http_globals)[id]) != IS_ARRAY) &&
        !zend_is_auto_global((char *) TRACKS[id], strlen(TRACKS[id]) TSRMLS_CC))
        return nullptr;

    return PG(http_globals)[id];
#endif
}

void prepare() {
    pid_t pid = getpid();

    if (pid != getpgid(0))
        return;

    static pid_t initialized = 0;

    if (initialized && initialized == pid)
        return;

    initialized = pid;
    startProbe();
}

PHP_GINIT_FUNCTION (php_probe) {
#ifdef ZTS
    new (php_probe_globals) _zend_php_probe_globals();
#endif
};

PHP_GSHUTDOWN_FUNCTION (php_probe) {
#ifdef ZTS
    php_probe_globals->~_zend_php_probe_globals();
#endif
}

ZEND_DECLARE_MODULE_GLOBALS(php_probe)

PHP_MINIT_FUNCTION (php_probe) {
    ZEND_INIT_MODULE_GLOBALS(php_probe, PHP_GINIT(php_probe), PHP_GSHUTDOWN(php_probe))

    if (!gProbe)
        return FAILURE;

    auto nodes = (Policy *) allocShared(sizeof(Policy) * (PREPARED_POLICY_COUNT - 1));

    if (!nodes)
        return FAILURE;

    for (int i = 0; i < PREPARED_POLICY_COUNT - 1; i++) {
        if (!gProbe->pushNode(nodes + i)) {
            freeShared(nodes);
            return FAILURE;
        }
    }

    prepare();
    pthread_atfork(prepare, nullptr, nullptr);

    for (const auto &api: PHP_API) {
        HashTable *hashTable = CG(function_table);

        if (api.cls) {
#if PHP_MAJOR_VERSION > 5
            auto cls = (zend_class_entry *) zend_hash_str_find_ptr(CG(class_table), api.cls, strlen(api.cls));

            if (!cls) {
                LOG_WARNING("can't found class: %s", api.cls);
                continue;
            }

            hashTable = &cls->function_table;
#else
            zend_class_entry **cls;

            if (zend_hash_find(CG(class_table), api.cls, strlen(api.cls) + 1, (void **) &cls) != SUCCESS) {
                LOG_WARNING("can't found class: %s", api.cls);
                continue;
            }

            hashTable = &(*cls)->function_table;
#endif
        }

#if PHP_MAJOR_VERSION > 5
        auto func = (zend_function *) zend_hash_str_find_ptr(hashTable, api.name, strlen(api.name));

        if (!func) {
            LOG_WARNING("can't found function: %s", api.name);
            continue;
        }
#else
        zend_function *func;

        if (zend_hash_find(hashTable, api.name, strlen(api.name) + 1, (void **) &func) != SUCCESS) {
            LOG_WARNING("can't found function: %s", api.name);
            continue;
        }
#endif

#if PHP_MAJOR_VERSION < 8
        if (func->internal_function.handler == ZEND_FN(display_disabled_function)) {
            LOG_WARNING("disabled function: %s", api.name);
            continue;
        }
#endif

        *api.metadata.origin = func->internal_function.handler;
        func->internal_function.handler = api.metadata.entry;
    }

    for (const auto &opcode: PHP_OPCODE)
        zend_set_user_opcode_handler(opcode.op, opcode.handler);

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION (php_probe) {
    for (const auto &api: PHP_API) {
        HashTable *hashTable = CG(function_table);

        if (api.cls) {
#if PHP_MAJOR_VERSION > 5
            auto cls = (zend_class_entry *) zend_hash_str_find_ptr(CG(class_table), api.cls, strlen(api.cls));

            if (!cls) {
                LOG_WARNING("can't found class: %s", api.cls);
                continue;
            }

            hashTable = &cls->function_table;
#else
            zend_class_entry **cls;

            if (zend_hash_find(CG(class_table), api.cls, strlen(api.cls) + 1, (void **) &cls) != SUCCESS) {
                LOG_WARNING("can't found class: %s", api.cls);
                continue;
            }

            hashTable = &(*cls)->function_table;
#endif
        }

#if PHP_MAJOR_VERSION > 5
        auto func = (zend_function *) zend_hash_str_find_ptr(hashTable, api.name, strlen(api.name));

        if (!func) {
            LOG_WARNING("can't found function: %s", api.name);
            continue;
        }
#else
        zend_function *func;

        if (zend_hash_find(hashTable, api.name, strlen(api.name) + 1, (void **) &func) != SUCCESS) {
            LOG_WARNING("can't found function: %s", api.name);
            continue;
        }
#endif

#if PHP_MAJOR_VERSION < 8
        if (func->internal_function.handler == ZEND_FN(display_disabled_function)) {
            LOG_WARNING("disabled function: %s", api.name);
            continue;
        }
#endif

        if (!*api.metadata.origin) {
            LOG_WARNING("null origin handler");
            continue;
        }

        func->internal_function.handler = *api.metadata.origin;
    }

    for (const auto &opcode: PHP_OPCODE)
        zend_set_user_opcode_handler(opcode.op, nullptr);

#ifdef ZTS
    ts_free_id(php_probe_globals_id);
#else
    PHP_GSHUTDOWN(php_probe)(&php_probe_globals);
#endif

    return SUCCESS;
}

PHP_RINIT_FUNCTION (php_probe) {
    zval *server = HTTPGlobals(
            TRACK_VARS_SERVER
#if PHP_MAJOR_VERSION <= 5
            TSRMLS_CC
#endif
    );

    if (!server || Z_TYPE_P(server) != IS_ARRAY)
        return SUCCESS;

    auto fetch = [=](const HashTable *hashTable, const char *key) -> std::string {
        zval *val = hashFind(hashTable, key);

        if (!val)
            return "";

        return toString(
                val
#if PHP_MAJOR_VERSION <= 5
                TSRMLS_CC
#endif
        );
    };

    strncpy(PHP_PROBE_G(request).scheme, fetch(Z_ARRVAL_P(server), "REQUEST_SCHEME").c_str(), FIELD_LENGTH - 1);
    strncpy(PHP_PROBE_G(request).host, fetch(Z_ARRVAL_P(server), "HTTP_HOST").c_str(), FIELD_LENGTH - 1);
    strncpy(PHP_PROBE_G(request).serverName, fetch(Z_ARRVAL_P(server), "SERVER_NAME").c_str(), FIELD_LENGTH - 1);

    strncpy(
            PHP_PROBE_G(request).serverAddress,
            fetch(Z_ARRVAL_P(server), "SERVER_ADDR").c_str(),
            FIELD_LENGTH - 1
    );

    strncpy(PHP_PROBE_G(request).uri, fetch(Z_ARRVAL_P(server), "REQUEST_URI").c_str(), FIELD_LENGTH - 1);
    strncpy(PHP_PROBE_G(request).query, fetch(Z_ARRVAL_P(server), "QUERY_STRING").c_str(), FIELD_LENGTH - 1);
    strncpy(PHP_PROBE_G(request).method, fetch(Z_ARRVAL_P(server), "REQUEST_METHOD").c_str(), FIELD_LENGTH - 1);

    strncpy(
            PHP_PROBE_G(request).remoteAddress,
            fetch(Z_ARRVAL_P(server), "REMOTE_ADDR").c_str(),
            FIELD_LENGTH - 1
    );

    strncpy(
            PHP_PROBE_G(request).documentRoot,
            fetch(Z_ARRVAL_P(server), "DOCUMENT_ROOT").c_str(),
            FIELD_LENGTH - 1
    );

    std::optional<short> port = zero::strings::toNumber<short>(fetch(Z_ARRVAL_P(server), "SERVER_PORT"));

    if (port)
        PHP_PROBE_G(request).port = *port;

    int index = 0;

    for (const auto &e: Z_ARRVAL_P(server)) {
        if (e.type != HASH_KEY_IS_STRING || Z_TYPE_P(e.value) != IS_STRING)
            continue;

        std::string override;
        std::string key = std::get<std::string>(e.key);

        if (key == "HTTP_CONTENT_TYPE" || key == "CONTENT_TYPE") {
            override = "content-type";
        } else if (key == "HTTP_CONTENT_LENGTH" || key == "CONTENT_LENGTH") {
            override = "content-length";
        } else if (zero::strings::startsWith(key, "HTTP_")) {
            override = zero::strings::tolower(key.substr(5));
            std::replace(override.begin(), override.end(), '_', '-');
        } else {
            continue;
        }

        strncpy(PHP_PROBE_G(request).headers[index][0], override.c_str(), FIELD_LENGTH - 1);
        strncpy(PHP_PROBE_G(request).headers[index][1], Z_STRVAL_P(e.value), FIELD_LENGTH - 1);

        if (++index >= HEADER_COUNT)
            break;
    }

    if (strcasecmp(PHP_PROBE_G(request).method, "post") != 0 && strcasecmp(PHP_PROBE_G(request).method, "put") != 0)
        return SUCCESS;

    auto begin = PHP_PROBE_G(request).headers;
    auto end = begin + index;

    if (std::find_if(begin, end, [](const auto &header) {
        if (strcmp(header[0], "content-type") != 0)
            return false;

        return strncmp(header[1], "multipart/form-data", 19) == 0;
    }) != end) {
        strncpy(
                PHP_PROBE_G(request).body,
                toString(
                        HTTPGlobals(
                                TRACK_VARS_POST
#if PHP_MAJOR_VERSION <= 5
                                TSRMLS_CC
#endif
                        )
#if PHP_MAJOR_VERSION <= 5
                        TSRMLS_CC
#endif
                ).c_str(),
                FIELD_LENGTH - 1
        );

        zval *files = HTTPGlobals(
                TRACK_VARS_FILES
#if PHP_MAJOR_VERSION <= 5
                TSRMLS_CC
#endif
        );

        if (!files || Z_TYPE_P(files) != IS_ARRAY)
            return SUCCESS;

        index = 0;

        for (const auto &e: Z_ARRVAL_P(files)) {
            if (Z_TYPE_P(e.value) != IS_ARRAY)
                continue;

            strncpy(
                    PHP_PROBE_G(request).files[index].name,
                    fetch(Z_ARRVAL_P(e.value), "name").c_str(),
                    FIELD_LENGTH - 1
            );

            strncpy(
                    PHP_PROBE_G(request).files[index].type,
                    fetch(Z_ARRVAL_P(e.value), "type").c_str(),
                    FIELD_LENGTH - 1
            );

            strncpy(
                    PHP_PROBE_G(request).files[index].tmp_name,
                    fetch(Z_ARRVAL_P(e.value), "tmp_name").c_str(),
                    FIELD_LENGTH - 1
            );

            if (++index >= FILE_COUNT)
                break;
        }

        return SUCCESS;
    }

    php_stream *stream = php_stream_open_wrapper("php://input", "rb", REPORT_ERRORS, nullptr);

    if (!stream)
        return SUCCESS;

    char buffer[1024] = {};

    int n = php_stream_read(stream, buffer, sizeof(buffer));

    if (n < 0) {
        php_stream_close(stream);
        return SUCCESS;
    }

    for (int i = 0, j = 0; i < n && j < FIELD_LENGTH - 1; i++) {
        if (!isprint(buffer[i]))
            continue;

        PHP_PROBE_G(request).body[j++] = buffer[i];
    }

    php_stream_close(stream);

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION (php_probe) {
    PHP_PROBE_G(request) = {};
    return SUCCESS;
}

PHP_MINFO_FUNCTION (php_probe) {
    php_info_print_table_start();
    php_info_print_table_header(2, "php probe support", "enabled");
    php_info_print_table_end();
}

zend_module_dep php_probe_module_dep[] = {
        ZEND_MOD_REQUIRED("standard")
        ZEND_MOD_CONFLICTS("xdebug")
        ZEND_MOD_END
};

zend_module_entry php_probe_module_entry = {
        STANDARD_MODULE_HEADER_EX,
        nullptr,
        php_probe_module_dep,
        "php probe",
        nullptr,
        PHP_MINIT(php_probe),
        PHP_MSHUTDOWN(php_probe),
        PHP_RINIT(php_probe),
        PHP_RSHUTDOWN(php_probe),
        PHP_MINFO(php_probe),
        "1.0.0",
        STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(php_probe)