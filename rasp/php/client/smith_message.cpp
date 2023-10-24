#include "smith_message.h"
#include <unistd.h>
#include <ctime>
#include <php_version.h>
#include <Zend/zend.h>
#include <Zend/zend_constants.h>

constexpr auto RUNTIME = "php";
constexpr auto PROBE_VERSION = "1.0.0";

std::string getVersion() {
#if PHP_MAJOR_VERSION > 5
    zval *val = zend_get_constant_str(ZEND_STRL("PHP_VERSION"));

    if (!val || Z_TYPE_P(val) != IS_STRING)
        return "";

    return {Z_STRVAL_P(val), Z_STRLEN_P(val)};
#else
    TSRMLS_FETCH();

    zval val;
    std::string version;

    if (!zend_get_constant(ZEND_STRL("PHP_VERSION"), &val TSRMLS_CC))
        return "";

    if (Z_TYPE(val) != IS_STRING) {
        zval_dtor(&val);
        return "";
    }

    version = {Z_STRVAL(val), (std::size_t) Z_STRLEN(val)};
    zval_dtor(&val);

    return version;
#endif
}

void to_json(nlohmann::json &j, const SmithMessage &message) {
    static pid_t pid = getpid();
    static std::string version = getVersion();

    j = {
            {"pid",             pid},
            {"runtime",         RUNTIME},
            {"runtime_version", version},
            {"time",            std::time(nullptr)},
            {"message_type",    message.operate},
            {"probe_version",   PROBE_VERSION},
            {"data",            message.data}
    };
}

void from_json(const nlohmann::json &j, SmithMessage &message) {
    j.at("message_type").get_to(message.operate);
    j.at("data").get_to(message.data);
}

void to_json(nlohmann::json &j, const Heartbeat &heartbeat) {
    j = {
            {"filter", heartbeat.filter},
            {"block",  heartbeat.block},
            {"limit",  heartbeat.limit}
    };
}

void to_json(nlohmann::json &j, const UploadFile &uploadFile) {
    j = {
            {"name",     uploadFile.name},
            {"type",     uploadFile.type},
            {"tmp_name", uploadFile.tmp_name}
    };
}

void to_json(nlohmann::json &j, const Request &request) {
    j = {
            {"port",          request.port},
            {"scheme",        request.scheme},
            {"host",          request.host},
            {"serverName",    request.serverName},
            {"serverAddress", request.serverAddress},
            {"uri",           request.uri},
            {"query",         request.query},
            {"body",          request.body},
            {"method",        request.method},
            {"remoteAddress", request.remoteAddress},
            {"documentRoot",  request.documentRoot}
    };

    for (const auto &header: request.headers) {
        if (!*header[0])
            break;

        j["headers"][header[0]] = header[1];
    }

    for (const auto &file: request.files) {
        if (!*file.name)
            break;

        j["files"].push_back(file);
    }
}

void to_json(nlohmann::json &j, const Trace &trace) {
    j = {
            {"class_id",  trace.classID},
            {"method_id", trace.methodID},
            {"blocked",   trace.blocked},
            {"request",   trace.request}
    };

    if (*trace.policyID)
        j["policy_id"] = trace.policyID;

    if (*trace.ret)
        j["ret"] = trace.ret;

    for (int i = 0; i < trace.count; i++)
        j["args"].push_back(trace.args[i]);

    for (const auto &stackTrace: trace.stackTrace) {
        if (!*stackTrace)
            break;

        j["stack_trace"].push_back(stackTrace);
    }
}

void from_json(const nlohmann::json &j, MatchRule &rule) {
    j.at("index").get_to(rule.index);
    j.at("regex").get_to(rule.regex);
}

void from_json(const nlohmann::json &j, Filter &filter) {
    j.at("class_id").get_to(filter.classID);
    j.at("method_id").get_to(filter.methodID);
    j.at("include").get_to(filter.include);
    j.at("exclude").get_to(filter.exclude);
}

void from_json(const nlohmann::json &j, FilterConfig &config) {
    j.at("uuid").get_to(config.uuid);
    j.at("filters").get_to(config.filters);
}

void from_json(const nlohmann::json &j, StackFrame &stackFrame) {
    j.at("keywords").get_to(stackFrame.keywords);
    j.at("operator").get_to(stackFrame.logicalOperator);
}

void from_json(const nlohmann::json &j, Block &block) {
    j.at("class_id").get_to(block.classID);
    j.at("method_id").get_to(block.methodID);
    if (j.contains("policy_id") && !j.at("policy_id").is_null())
        j.at("policy_id").get_to(block.policyID);
    j.at("rules").get_to(block.rules);

    if (j.contains("stack_frame") && !j.at("stack_frame").is_null())
        block.stackFrame = j.at("stack_frame").get<StackFrame>();
}

void from_json(const nlohmann::json &j, BlockConfig &config) {
    j.at("uuid").get_to(config.uuid);
    j.at("blocks").get_to(config.blocks);
}

void from_json(const nlohmann::json &j, Limit &limit) {
    j.at("class_id").get_to(limit.classID);
    j.at("method_id").get_to(limit.methodID);
    j.at("quota").get_to(limit.quota);
}

void from_json(const nlohmann::json &j, LimitConfig &config) {
    j.at("uuid").get_to(config.uuid);
    j.at("limits").get_to(config.limits);
}
