#include "smith_message.h"

constexpr auto RUNTIME = "golang";
constexpr auto PROBE_VERSION = "1.0.0";

void to_json(nlohmann::json &j, const SmithMessage &message) {
    j = {
            {"pid",             message.pid},
            {"runtime",         RUNTIME},
            {"runtime_version", message.version},
            {"time",            std::time(nullptr)},
            {"message_type",    message.operate},
            {"probe_version",   PROBE_VERSION},
            {"data",            message.data}
    };
}

void from_json(const nlohmann::json &j, SmithMessage &message) {
    j.at("pid").get_to(message.pid);
    j.at("message_type").get_to(message.operate);
    j.at("data").get_to(message.data);
}

void to_json(nlohmann::json &j, const Heartbeat &heartbeat) {
    j = {
            {"filter", heartbeat.filter}
    };
}

void to_json(nlohmann::json &j, const Request &request) {
    j = {
            {"method",  request.method},
            {"uri",     request.uri},
            {"host",    request.host},
#ifndef DISABLE_HTTP_HEADER
            {"headers", request.headers},
#endif
            {"remote",  request.remote}
    };
}

void to_json(nlohmann::json &j, const Trace &trace) {
    j = {
            {"class_id",    trace.classID},
            {"method_id",   trace.methodID},
#ifdef ENABLE_HTTP
            {"request",     trace.request},
#endif
            {"args",        trace.args},
            {"stack_trace", trace.stackTrace}
    };
}

void from_json(const nlohmann::json &j, MatchRule &matchRule) {
    j.at("index").get_to(matchRule.index);
    j.at("regex").get_to(matchRule.regex);
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

void from_json(const nlohmann::json &j, Limit &limit) {
    j.at("class_id").get_to(limit.classID);
    j.at("method_id").get_to(limit.methodID);
    j.at("quota").get_to(limit.quota);
}

void from_json(const nlohmann::json &j, LimitConfig &config) {
    j.at("uuid").get_to(config.uuid);
    j.at("limits").get_to(config.limits);
}
