#include "smith_message.h"
#include <unistd.h>
#include <ctime>
#include <go/symbol/build_info.h>

constexpr auto RUNTIME = "golang";
constexpr auto PROBE_VERSION = "1.0.0";

void to_json(nlohmann::json &j, const SmithMessage &message) {
    static pid_t pid = getpid();

    j = {
            {"pid",             pid},
            {"runtime",         RUNTIME},
            {"runtime_version", gBuildInfo->mVersion},
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

    for (int i = 0; i < trace.count; i++)
        j["args"].push_back(std::string(trace.args[i], ARG_LENGTH).c_str());

    for (const auto &stackTrace: trace.stackTrace) {
        if (stackTrace.pc == 0)
            break;

        char stack[4096] = {};

        snprintf(stack, sizeof(stack),
                 "%s %s:%d +0x%lx",
                 stackTrace.func.getName(),
                 stackTrace.func.getSourceFile(stackTrace.pc),
                 stackTrace.func.getSourceLine(stackTrace.pc),
                 stackTrace.pc - stackTrace.func.getEntry()
        );

        j["stack_trace"].push_back(stack);
    }
}

void to_json(nlohmann::json &j, const Module &module) {
    j = {
            {"path",    module.path},
            {"version", module.version},
            {"sum",     module.sum}
    };

    if (module.replace)
        j["replace"] = *module.replace;
}

void to_json(nlohmann::json &j, const ModuleInfo &moduleInfo) {
    j = {
            {"path", moduleInfo.path},
            {"main", moduleInfo.main},
            {"deps", moduleInfo.deps}
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

void from_json(const nlohmann::json &j, Block &block) {
    j.at("class_id").get_to(block.classID);
    j.at("method_id").get_to(block.methodID);
    j.at("rules").get_to(block.rules);
}

void from_json(const nlohmann::json &j, Limit &limit) {
    j.at("class_id").get_to(limit.classID);
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
