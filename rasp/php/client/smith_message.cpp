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

    version = {Z_STRVAL(val), (std::size_t)Z_STRLEN(val)};
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

    for (int i = 0; i < request.header_count; i++)
        j["headers"][request.headers[i][0]] = request.headers[i][1];

    for (int i = 0; i < request.file_count; i++)
        j["files"].push_back(request.files[i]);
}

void to_json(nlohmann::json &j, const Trace &trace) {
    j = {
            {"class_id",  trace.classID},
            {"method_id", trace.methodID},
            {"blocked",   trace.blocked},
            {"request",   trace.request}
    };

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

void from_json(const nlohmann::json &j, MatchRule &matchRule) {
    j.at("index").get_to(matchRule.index);
    j.at("regex").get_to(matchRule.regex);
}

void from_json(const nlohmann::json &j, Filter &filter) {
    j.at("class_id").get_to(filter.classId);
    j.at("method_id").get_to(filter.methodID);
    j.at("include").get_to(filter.include);
    j.at("exclude").get_to(filter.exclude);
}

void from_json(const nlohmann::json &j, Block &block) {
    j.at("class_id").get_to(block.classId);
    j.at("method_id").get_to(block.methodID);
    j.at("rules").get_to(block.rules);
}

void from_json(const nlohmann::json &j, Limit &limit) {
    j.at("class_id").get_to(limit.classId);
    j.at("method_id").get_to(limit.methodID);
    j.at("quota").get_to(limit.quota);
}

void from_json(const nlohmann::json &j, FilterConfig &config) {
    j.at("uuid").get_to(config.uuid);
    j.at("filters").get_to(config.filters);
}

void from_json(const nlohmann::json &j, BlockConfig &config) {
    j.at("uuid").get_to(config.uuid);
    j.at("blocks").get_to(config.blocks);
}

void from_json(const nlohmann::json &j, LimitConfig &config) {
    j.at("uuid").get_to(config.uuid);
    j.at("limits").get_to(config.limits);
}
