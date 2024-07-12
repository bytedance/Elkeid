#ifndef GO_PROBE_SMITH_MESSAGE_H
#define GO_PROBE_SMITH_MESSAGE_H

#include <list>
#include <vector>
#include <nlohmann/json.hpp>
#include <go/symbol/symbol.h>

constexpr auto ARG_COUNT = 8;
constexpr auto ARG_LENGTH = 256;
constexpr auto FRAME_COUNT = 20;
constexpr auto HEADER_COUNT = 20;
constexpr auto POLICY_ID_LENGTH = 256;

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
    int64_t discard_surplus;
    int64_t discard_post;
    int64_t discard_send;
};

struct Request {
    char method[ARG_LENGTH];
    char uri[ARG_LENGTH];
    char host[ARG_LENGTH];
    char remote[ARG_LENGTH];
    char headers[HEADER_COUNT][2][ARG_LENGTH];
};

struct Trace {
    int classID;
    int methodID;
    int count;
    bool blocked;
    char policyID[POLICY_ID_LENGTH];
    char args[ARG_COUNT][ARG_LENGTH];
    std::pair<uintptr_t, std::optional<go::symbol::Symbol>> stackTrace[FRAME_COUNT];
    Request request;
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

enum LogicalOperator {
    OR,
    AND
};

struct StackFrame {
    std::vector<std::string> keywords;
    LogicalOperator logicalOperator;
};

struct Block {
    int classID;
    int methodID;
    std::string policyID;
    std::vector<MatchRule> rules;
    std::optional<StackFrame> stackFrame;
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
void to_json(nlohmann::json &j, const Request &request);
void to_json(nlohmann::json &j, const Trace &trace);

void from_json(const nlohmann::json &j, MatchRule &rule);
void from_json(const nlohmann::json &j, Filter &filter);
void from_json(const nlohmann::json &j, FilterConfig &config);
void from_json(const nlohmann::json &j, StackFrame &stackFrame);
void from_json(const nlohmann::json &j, Block &block);
void from_json(const nlohmann::json &j, BlockConfig &config);
void from_json(const nlohmann::json &j, Limit &limit);
void from_json(const nlohmann::json &j, LimitConfig &config);

#endif //GO_PROBE_SMITH_MESSAGE_H
