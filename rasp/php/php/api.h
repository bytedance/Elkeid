#ifndef PHP_PROBE_API_H
#define PHP_PROBE_API_H

#include <library.h>
#include <client/smith_probe.h>
#include <Zend/zend_API.h>
#include <Zend/zend_exceptions.h>
#include <php_version.h>
#include <tiny-regex-c/re.h>
#include <sys/eventfd.h>

using handler = void (*)(INTERNAL_FUNCTION_PARAMETERS);

struct APIMetadata {
    handler entry;
    handler *origin;
};

struct API {
    const char *name;
    const char *cls;
    APIMetadata metadata;
};

struct Opcode {
    int op;
    user_opcode_handler_t handler;
};

std::string toString(
        zval *val
#if PHP_MAJOR_VERSION <= 5
        TSRMLS_DC
#endif
);

std::vector<std::string> traceback(
#if PHP_MAJOR_VERSION <= 5
        TSRMLS_D
#endif
);

template<int ClassID, int MethodID>
struct TraceBase {
    static bool surplus() {
        std::atomic<int> &quota = gProbe->quotas[ClassID][MethodID];
        int n = quota;

        do {
            if (n <= 0)
                return false;
        } while (!quota.compare_exchange_weak(n, n - 1));

        return true;
    }

    static bool pass(Trace &trace) {
        z_rwlock_t *lock = gProbe->locks[ClassID] + MethodID;
        z_rwlock_read_lock(lock);

        auto &[size, policies] = gProbe->policies[ClassID][MethodID];

        if (std::any_of(policies, policies + size, [&](const Policy *policy) {
            if (policy->ruleCount > 0 && std::none_of(
                    policy->rules,
                    policy->rules + policy->ruleCount,
                    [&](const auto &rule) {
                        if (rule.first >= trace.count)
                            return false;

                        int length = 0;

                        return re_match(rule.second, trace.args[rule.first], &length) != -1;
                    }))
                return false;

            if (policy->KeywordCount == 0) {
                trace.blocked = true;
                strncpy(trace.policyID, policy->policyID, sizeof(Trace::policyID) - 1);
                return true;
            }

            auto pred = [&](const auto &keyword) {
                return std::any_of(trace.stackTrace, trace.stackTrace + FRAME_COUNT, [=](const auto &frame) {
                    if (!frame)
                        return false;

                    int length = 0;

                    return re_match(keyword, frame, &length) != -1;
                });
            };

            const auto &[logicalOperator, keywords] = policy->stackFrame;

            if (logicalOperator == OR && std::any_of(keywords, keywords + policy->KeywordCount, pred)) {
                trace.blocked = true;
                strncpy(trace.policyID, policy->policyID, sizeof(Trace::policyID) - 1);
                return true;
            }

            if (logicalOperator == AND && std::all_of(keywords, keywords + policy->KeywordCount, pred)) {
                trace.blocked = true;
                strncpy(trace.policyID, policy->policyID, sizeof(Trace::policyID) - 1);
                return true;
            }

            return false;
        })) {
            z_rwlock_read_unlock(lock);
            return false;
        }

        z_rwlock_read_unlock(lock);
        return true;
    }

    static void post(const Trace &trace) {
        std::optional<size_t> index = gProbe->buffer.reserve();

        if (!index)
            return;

        gProbe->buffer[*index] = trace;
        gProbe->buffer.commit(*index);

        if (gProbe->buffer.size() < TRACE_BUFFER_SIZE / 2)
            return;

        bool expected = true;

        if (!gProbe->waiting.compare_exchange_strong(expected, false))
            return;

        eventfd_t value = 1;
        eventfd_write(gProbe->efd, value);
    }
};

template<int ClassID, int MethodID, bool CanBlock, bool Ret, int Required, int Optional = 0>
struct APIEntry : TraceBase<ClassID, MethodID> {
    static constexpr auto getTypeSpec() {
        constexpr size_t length = Required + (Optional > 0 ? Optional + 1 : 0);
        std::array<char, length + 1> buffer = {};

        for (size_t i = 0; i < length; i++) {
            if (i == Required) {
                buffer[i] = '|';
                continue;
            }

            buffer[i] = 'z';
        }

        return buffer;
    }

    static void entry(INTERNAL_FUNCTION_PARAMETERS) {
        entry(std::make_index_sequence<Required + Optional>{}, INTERNAL_FUNCTION_PARAM_PASSTHRU);
    }

    template<size_t ...Index>
    static void entry(std::index_sequence<Index...>, INTERNAL_FUNCTION_PARAMETERS) {
        if constexpr (!CanBlock) {
            if (!TraceBase<ClassID, MethodID>::surplus()) {
                origin(INTERNAL_FUNCTION_PARAM_PASSTHRU);
                return;
            }
        }

        zval *args[sizeof...(Index)] = {};
        int argc = std::min(Required + Optional, (int) ZEND_NUM_ARGS());

#if PHP_MAJOR_VERSION > 5
        constexpr
#endif
        auto spec = getTypeSpec();

        if (zend_parse_parameters(
#if PHP_MAJOR_VERSION > 5
                argc,
#else
                argc TSRMLS_CC,
#endif
                spec.data(),
                &args[Index]...) != SUCCESS) {
            origin(INTERNAL_FUNCTION_PARAM_PASSTHRU);
            return;
        }

        Trace trace = {
                ClassID,
                MethodID
        };

        while (trace.count < std::min(argc, ARG_COUNT)) {
            zval *arg = args[trace.count];

            if (!arg)
                continue;

            strncpy(
                    trace.args[trace.count++],
                    toString(
                            arg
#if PHP_MAJOR_VERSION <= 5
                            TSRMLS_CC
#endif
                    ).c_str(),
                    ARG_LENGTH - 1
            );
        }

        std::vector<std::string> stackTrace = traceback(
#if PHP_MAJOR_VERSION <= 5
                TSRMLS_C
#endif
        );

        for (int i = 0; i < stackTrace.size() && i < FRAME_COUNT; i++) {
            strncpy(trace.stackTrace[i], stackTrace[i].c_str(), FRAME_LENGTH - 1);
        }

        trace.request = PHP_PROBE_G(request);

        if constexpr (CanBlock) {
            if (!TraceBase<ClassID, MethodID>::pass(trace)) {
                TraceBase<ClassID, MethodID>::post(trace);

                zend_throw_exception(
                        nullptr,
                        "API blocked by RASP",
                        0
#if PHP_MAJOR_VERSION <= 5
                        TSRMLS_CC
#endif
                );

                return;
            }

            if (!TraceBase<ClassID, MethodID>::surplus()) {
                origin(INTERNAL_FUNCTION_PARAM_PASSTHRU);
                return;
            }
        }

        origin(INTERNAL_FUNCTION_PARAM_PASSTHRU);

        if constexpr (Ret) {
            strncpy(
                    trace.ret,
                    toString(
                            return_value
#if PHP_MAJOR_VERSION <= 5
                            TSRMLS_CC
#endif
                    ).c_str(),
                    ARG_LENGTH - 1
            );
        }

        TraceBase<ClassID, MethodID>::post(trace);
    }

    static constexpr APIMetadata metadata() {
        return {entry, &origin};
    }

    static handler origin;
};

template<int ClassID, int MethodID, bool CanBlock, bool Ret, int Required, int Optional>
handler APIEntry<ClassID, MethodID, CanBlock, Ret, Required, Optional>::origin = nullptr;

template<int ClassID, int MethodID, bool Extended = false>
struct OpcodeEntry : TraceBase<ClassID, MethodID> {
    static int entry(
            zend_execute_data *execute_data
#if PHP_MAJOR_VERSION <= 5
            TSRMLS_DC
#endif
    ) {
        if (!TraceBase<ClassID, MethodID>::surplus())
            return ZEND_USER_OPCODE_DISPATCH;

#if PHP_VERSION_ID >= 80000
        zval *op1 = zend_get_zval_ptr(execute_data->opline, execute_data->opline->op1_type, &execute_data->opline->op1, execute_data);
        zval *op2 = zend_get_zval_ptr(execute_data->opline, execute_data->opline->op2_type, &execute_data->opline->op2, execute_data);
#elif PHP_VERSION_ID >= 70300
        zend_free_op should_free;
        zval *op1 = zend_get_zval_ptr(execute_data->opline, execute_data->opline->op1_type, &execute_data->opline->op1, execute_data, &should_free, BP_VAR_IS);
        zval *op2 = zend_get_zval_ptr(execute_data->opline, execute_data->opline->op2_type, &execute_data->opline->op2, execute_data, &should_free, BP_VAR_IS);
#elif PHP_VERSION_ID >= 70000
        zend_free_op should_free;
        zval *op1 = zend_get_zval_ptr(execute_data->opline->op1_type, &execute_data->opline->op1, execute_data, &should_free, BP_VAR_IS);
        zval *op2 = zend_get_zval_ptr(execute_data->opline->op2_type, &execute_data->opline->op2, execute_data, &should_free, BP_VAR_IS);
#elif PHP_VERSION_ID >= 50500
        auto extract = [&](zend_uchar type, znode_op *node) {
            switch (type) {
                case IS_TMP_VAR:
                    return &EX_TMP_VAR(execute_data, node->var)->tmp_var;

                case IS_VAR:
                    return EX_TMP_VAR(execute_data, node->var)->var.ptr;

                default:
                    break;
            }

            zend_free_op should_free;

            return zend_get_zval_ptr(type, node, execute_data, &should_free, BP_VAR_IS TSRMLS_CC);
        };

        zval *op1 = extract(execute_data->opline->op1_type, &execute_data->opline->op1);
        zval *op2 = extract(execute_data->opline->op2_type, &execute_data->opline->op2);
#elif PHP_VERSION_ID >= 50400
        auto extract = [&](zend_uchar type, znode_op *node) {
            switch (type) {
                case IS_TMP_VAR:
                    return &((temp_variable *) ((char *) execute_data->Ts + node->var))->tmp_var;

                case IS_VAR:
                    return ((temp_variable *) ((char *) execute_data->Ts + node->var))->var.ptr;

                default:
                    break;
            }

            zend_free_op should_free;

            return zend_get_zval_ptr(type, node, execute_data->Ts, &should_free, BP_VAR_IS TSRMLS_CC);
        };

        zval *op1 = extract(execute_data->opline->op1_type, &execute_data->opline->op1);
        zval *op2 = extract(execute_data->opline->op2_type, &execute_data->opline->op2);
#else
        auto extract = [&](int type, znode *node) {
            switch (type) {
                case IS_TMP_VAR:
                    return &((temp_variable *) ((char *) execute_data->Ts + node->u.var))->tmp_var;

                case IS_VAR:
                    return ((temp_variable *) ((char *) execute_data->Ts + node->u.var))->var.ptr;

                default:
                    break;
            }

            zend_free_op should_free;

            return zend_get_zval_ptr(node, execute_data->Ts, &should_free, BP_VAR_IS TSRMLS_CC);
        };

        zval *op1 = extract(execute_data->opline->op1.op_type, &execute_data->opline->op1);
        zval *op2 = extract(execute_data->opline->op2.op_type, &execute_data->opline->op2);
#endif

        Trace trace = {
                ClassID,
                MethodID
        };

        strncpy(
                trace.args[trace.count++],
                toString(
                        op1
#if PHP_MAJOR_VERSION <= 5
                        TSRMLS_CC
#endif
                ).c_str(),
                ARG_LENGTH - 1
        );

        strncpy(
                trace.args[trace.count++],
                toString(
                        op2
#if PHP_MAJOR_VERSION <= 5
                        TSRMLS_CC
#endif
                ).c_str(),
                ARG_LENGTH - 1
        );

        if constexpr (Extended) {
#if PHP_VERSION_ID >= 50400
            strncpy(trace.args[trace.count++], std::to_string(execute_data->opline->extended_value).c_str(), ARG_LENGTH - 1);
#else
            strncpy(trace.args[trace.count++], std::to_string(Z_LVAL(execute_data->opline->op2.u.constant)).c_str(),
                    ARG_LENGTH - 1);
#endif
        }

        std::vector<std::string> stackTrace = traceback(
#if PHP_MAJOR_VERSION <= 5
                TSRMLS_C
#endif
        );

        for (int i = 0; i < stackTrace.size() && i < FRAME_COUNT; i++) {
            strncpy(trace.stackTrace[i], stackTrace[i].c_str(), FRAME_LENGTH - 1);
        }

        trace.request = PHP_PROBE_G(request);
        TraceBase<ClassID, MethodID>::post(trace);

        return ZEND_USER_OPCODE_DISPATCH;
    }
};

constexpr auto PHP_API = {
        API{
                "passthru",
                nullptr,
                APIEntry<0, 0, true, false, 1>::metadata()
        }, {
                "system",
                nullptr,
                APIEntry<0, 1, true, false, 1>::metadata()
        }, {
                "exec",
                nullptr,
                APIEntry<0, 2, true, false, 1>::metadata()
        }, {
                "shell_exec",
                nullptr,
                APIEntry<0, 3, true, false, 1>::metadata()
        }, {
                "proc_open",
                nullptr,
                APIEntry<0, 4, true, false, 1>::metadata()
        }, {
                "popen",
                nullptr,
                APIEntry<0, 5, true, false, 2>::metadata()
        }, {
                "pcntl_exec",
                nullptr,
                APIEntry<0, 6, true, false, 1, 2>::metadata()
        }, {
                "file",
                nullptr,
                APIEntry<1, 0, false, false, 1, 1>::metadata()
        }, {
                "readfile",
                nullptr,
                APIEntry<1, 1, false, false, 1, 1>::metadata()
        }, {
                "file_get_contents",
                nullptr,
                APIEntry<1, 2, false, false, 1, 1>::metadata()
        }, {
                "file_put_contents",
                nullptr,
                APIEntry<1, 3, false, false, 1>::metadata()
        }, {
                "copy",
                nullptr,
                APIEntry<1, 4, false, false, 2>::metadata()
        }, {
                "rename",
                nullptr,
                APIEntry<1, 5, false, false, 2>::metadata()
        }, {
                "unlink",
                nullptr,
                APIEntry<1, 6, false, false, 1>::metadata()
        }, {
                "dir",
                nullptr,
                APIEntry<1, 7, false, false, 1>::metadata()
        }, {
                "opendir",
                nullptr,
                APIEntry<1, 8, false, false, 1>::metadata()
        }, {
                "scandir",
                nullptr,
                APIEntry<1, 9, false, false, 1, 1>::metadata()
        }, {
                "fopen",
                nullptr,
                APIEntry<1, 10, false, false, 2, 1>::metadata()
        }, {
                "move_uploaded_file",
                nullptr,
                APIEntry<1, 11, false, false, 2>::metadata()
        }, {
                "__construct",
                "splfileobject",
                APIEntry<1, 12, false, false, 1, 2>::metadata()
        }, {
                "socket_connect",
                nullptr,
                APIEntry<2, 0, false, false, 2, 1>::metadata()
        }, {
                "gethostbyname",
                nullptr,
                APIEntry<3, 0, false, false, 1>::metadata()
        }, {
                "dns_get_record",
                nullptr,
                APIEntry<3, 1, false, false, 1, 1>::metadata()
        }, {
                "assert",
                nullptr,
                APIEntry<4, 0, false, false, 1>::metadata()
        }, {
                "putenv",
                nullptr,
                APIEntry<4, 1, false, false, 1>::metadata()
        }, {
                "curl_exec",
                nullptr,
                APIEntry<5, 0, false, false, 1>::metadata()
        }
};

constexpr auto PHP_OPCODE = {
        Opcode{
                ZEND_INCLUDE_OR_EVAL,
                OpcodeEntry<10, 0, true>::entry
        }
};

#endif //PHP_PROBE_API_H
