#include "smith_message.h"
#include <unistd.h>
#include <ctime>
#include <zero/strings/strings.h>
#include <Python.h>

constexpr auto RUNTIME = "CPython";
constexpr auto PROBE_VERSION = "1.0.0";

std::string getVersion() {
    const char *version = Py_GetVersion();

    if (!version)
        return "";

    return zero::strings::split(version, " ").front();
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

void to_json(nlohmann::json &j, const Trace &trace) {
    j = {
            {"class_id",  trace.classID},
            {"method_id", trace.methodID},
            {"blocked",   trace.blocked}
    };

    if (*trace.policyID)
        j["policy_id"] = trace.policyID;

    for (int i = 0; i < trace.count; i++)
        j["args"].push_back(trace.args[i]);

    for (const auto &kw: trace.kwargs) {
        if (!*kw[0])
            break;

        j["kwargs"][kw[0]] = kw[1];
    }

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
