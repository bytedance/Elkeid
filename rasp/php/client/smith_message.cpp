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

void to_json(nlohmann::json &j, const SmithRequest &r) {
    j = nlohmann::json {
            {"port", r.port},
            {"scheme", r.scheme},
            {"host", r.host},
            {"serverName", r.serverName},
            {"serverAddress", r.serverAddress},
            {"uri", r.uri},
            {"query", r.query},
            {"body", r.body},
            {"method", r.method},
            {"remoteAddress", r.remoteAddress},
            {"documentRoot", r.documentRoot}
    };

    for (int i = 0; i < r.header_count; i++)
        j["headers"][r.headers[i][0]] = r.headers[i][1];

    for (int i = 0; i < r.file_count; i++)
        j["files"].push_back({
            {"name", r.files[i].name},
            {"type", r.files[i].type},
            {"tmp_name", r.files[i].tmp_name}
        });
}

void to_json(nlohmann::json &j, const SmithMessage &m) {
    static pid_t pid = getpid();
    static std::string version = getVersion();

    j = nlohmann::json {
        {"pid", pid},
        {"runtime", RUNTIME},
        {"runtime_version", version},
        {"time", std::time(nullptr)},
        {"message_type", m.operate},
        {"probe_version", PROBE_VERSION},
        {"data", m.data}
    };
}

void from_json(const nlohmann::json &j, SmithMessage &m) {
    j.at("message_type").get_to(m.operate);
    j.at("data").get_to(m.data);
}

void to_json(nlohmann::json &j, const SmithTrace &t) {
    j = nlohmann::json {
        {"class_id", t.classID},
        {"method_id", t.methodID},
        {"blocked", t.blocked},
        {"request", t.request}
    };

    if (*t.ret)
        j["ret"] = t.ret;

    for (int i = 0; i < t.count; i++)
        j["args"].push_back(t.args[i]);

    for (const auto& stackTrace: t.stackTrace) {
        if (!*stackTrace)
            break;

        j["stack_trace"].push_back(stackTrace);
    }
}

void from_json(const nlohmann::json &j, MatchRule &r) {
    j.at("index").get_to(r.index);
    j.at("regex").get_to(r.regex);
}

void from_json(const nlohmann::json &j, Filter &f) {
    j.at("class_id").get_to(f.classId);
    j.at("method_id").get_to(f.methodID);
    j.at("include").get_to(f.include);
    j.at("exclude").get_to(f.exclude);
}

void from_json(const nlohmann::json &j, Block &b) {
    j.at("class_id").get_to(b.classId);
    j.at("method_id").get_to(b.methodID);
    j.at("rules").get_to(b.rules);
}

void from_json(const nlohmann::json &j, Limit &l) {
    j.at("class_id").get_to(l.classId);
    j.at("method_id").get_to(l.methodID);
    j.at("quota").get_to(l.quota);
}
