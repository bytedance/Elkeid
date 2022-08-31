#ifndef GO_PROBE_SMITH_MESSAGE_H
#define GO_PROBE_SMITH_MESSAGE_H

#include <list>
#include <vector>
#include <nlohmann/json.hpp>
#include <go/symbol/func.h>

constexpr auto ARG_COUNT = 20;
constexpr auto ARG_LENGTH = 256;
constexpr auto TRACE_COUNT = 20;

enum Operate {
    EXIT,
    HEARTBEAT,
    TRACE,
    CONFIG,
    CONTROL,
    DETECT,
    FILTER,
    BLOCK,
    LIMIT
};

struct SmithMessage {
    Operate operate;
    nlohmann::json data;
};

struct Heartbeat {
    std::string filter;
    std::string block;
    std::string limit;
};

struct StackTrace {
    uintptr_t pc;
    Func func;
};

struct Trace {
    int classID;
    int methodID;
    bool blocked;
    int count;
    char args[ARG_COUNT][ARG_LENGTH];
    StackTrace stackTrace[TRACE_COUNT];
};

struct Module {
    std::string path;
    std::string version;
    std::string sum;
    Module *replace{};

    ~Module() {
        if (replace) {
            delete replace;
            replace = nullptr;
        }
    }
};

struct ModuleInfo {
    std::string path;
    Module main;
    std::list<Module> deps;
};

struct MatchRule {
    int index;
    std::string regex;
};

struct Filter {
    int classID;
    int methodID;
    std::list<MatchRule> include;
    std::list<MatchRule> exclude;
};

struct FilterConfig {
    std::string uuid;
    std::list<Filter> filters;
};

struct Block {
    int classID;
    int methodID;
    std::list<MatchRule> rules;
};

struct BlockConfig {
    std::string uuid;
    std::list<Block> blocks;
};

struct Limit {
    int classID;
    int methodID;
    int quota;
};

struct LimitConfig {
    std::string uuid;
    std::list<Limit> limits;
};

void to_json(nlohmann::json &j, const SmithMessage &message);
void from_json(const nlohmann::json &j, SmithMessage &message);

void to_json(nlohmann::json &j, const Heartbeat &heartbeat);
void to_json(nlohmann::json &j, const Trace &trace);
void to_json(nlohmann::json &j, const Module &module);
void to_json(nlohmann::json &j, const ModuleInfo &moduleInfo);

void from_json(const nlohmann::json &j, MatchRule &matchRule);
void from_json(const nlohmann::json &j, Filter &filter);
void from_json(const nlohmann::json &j, Block &block);
void from_json(const nlohmann::json &j, Limit &limit);
void from_json(const nlohmann::json &j, FilterConfig &config);
void from_json(const nlohmann::json &j, BlockConfig &config);
void from_json(const nlohmann::json &j, LimitConfig &config);

#endif //GO_PROBE_SMITH_MESSAGE_H
