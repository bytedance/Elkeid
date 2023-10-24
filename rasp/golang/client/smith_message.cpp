#include "smith_message.h"
#include "smith_probe.h"
#include <unistd.h>
#include <zero/cache/lru.h>
#include <zero/strings/strings.h>

constexpr auto RUNTIME = "golang";
constexpr auto PROBE_VERSION = "1.0.0";
constexpr auto FRAME_CACHE_SIZE = 128;

void to_json(nlohmann::json &j, const SmithMessage &message) {
    static pid_t pid = getpid();
    static std::string version = zero::strings::format("%d.%d", gTarget->version.major, gTarget->version.minor);

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

void to_json(nlohmann::json &j, const Request &request) {
    j = {
            {"method",  request.method},
            {"uri",     request.uri},
            {"host",    request.host},
            {"headers", request.headers},
            {"remote",  request.remote}
    };
}

void to_json(nlohmann::json &j, const Trace &trace) {
    j = {
            {"class_id",  trace.classID},
            {"method_id", trace.methodID},
            {"blocked",   trace.blocked},
    };

    for (int i = 0; i < trace.count; i++)
        j["args"].push_back(trace.args[i]);

    if (*trace.policyID)
        j["policy_id"] = trace.policyID;

    for (const auto &[pc, symbol]: trace.stackTrace) {
        if (!pc)
            break;

        static zero::cache::LRUCache<uintptr_t, std::string> frameCache(FRAME_CACHE_SIZE);

        std::optional<std::string> cache = frameCache.get(pc);

        if (cache) {
            j["stack_trace"].push_back(std::move(*cache));
            continue;
        }

        char frame[4096] = {};

        snprintf(
                frame,
                sizeof(frame),
                "%s %s:%d +0x%lx",
                symbol->name(),
                symbol->sourceFile(pc),
                symbol->sourceLine(pc),
                pc - symbol->entry()
        );

        frameCache.set(pc, frame);
        j["stack_trace"].push_back(frame);
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
