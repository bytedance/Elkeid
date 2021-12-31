#include "smith_message.h"
#include <unistd.h>
#include <ctime>

constexpr auto RUNTIME = "golang";
constexpr auto PROBE_VERSION = "1.0.0";

void to_json(nlohmann::json &j, const CSmithMessage &m) {
    static pid_t pid = getpid();

    j = nlohmann::json {
        {"pid", pid},
        {"runtime", RUNTIME},
        {"runtime_version", gBuildInfo->mVersion},
        {"time", std::time(nullptr)},
        {"message_type", m.operate},
        {"probe_version", PROBE_VERSION},
        {"data", m.data}
    };
}

void from_json(const nlohmann::json &j, CSmithMessage &m) {
    j.at("message_type").get_to(m.operate);
    j.at("data").get_to(m.data);
}

void to_json(nlohmann::json &j, const CSmithTrace &t) {
    j = nlohmann::json {
        {"class_id", t.classID},
        {"method_id", t.methodID}
    };

    for (int i = 0; i < t.count; i++)
        j["args"].push_back(std::string(t.args[i], ARG_LENGTH).c_str());

    for (const auto& stackTrace: t.stackTrace) {
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

void to_json(nlohmann::json &j, const CModule &m) {
    j = nlohmann::json {
        {"path", m.path},
        {"version", m.version},
        {"sum", m.sum}
    };

    if (m.replace)
        j["replace"] = *m.replace;
}

void to_json(nlohmann::json &j, const CModuleInfo &i) {
    j = nlohmann::json {
        {"path", i.path},
        {"main", i.main},
        {"deps", i.deps}
    };
}

void from_json(const nlohmann::json &j, CMatchRule &r) {
    j.at("index").get_to(r.index);
    j.at("regex").get_to(r.regex);
}

void from_json(const nlohmann::json &j, CFilter &f) {
    j.at("class_id").get_to(f.classId);
    j.at("method_id").get_to(f.methodID);
    j.at("include").get_to(f.include);
    j.at("exclude").get_to(f.exclude);
}

void from_json(const nlohmann::json &j, CBlock &b) {
    j.at("class_id").get_to(b.classId);
    j.at("method_id").get_to(b.methodID);
    j.at("rules").get_to(b.rules);
}

void from_json(const nlohmann::json &j, CLimit &l) {
    j.at("class_id").get_to(l.classId);
    j.at("method_id").get_to(l.methodID);
    j.at("quota").get_to(l.quota);
}
