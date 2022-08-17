#ifndef PHP_PROBE_SMITH_MESSAGE_H
#define PHP_PROBE_SMITH_MESSAGE_H

#include <list>
#include <vector>
#include <nlohmann/json.hpp>

constexpr auto SMITH_ARG_COUNT = 20;
constexpr auto SMITH_ARG_LENGTH = 256;
constexpr auto SMITH_TRACE_COUNT = 20;
constexpr auto SMITH_TRACE_LENGTH = 1024;

constexpr auto SMITH_FILE_COUNT = 5;
constexpr auto SMITH_HEADER_COUNT = 20;
constexpr auto SMITH_FIELD_LENGTH = 256;

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

struct UploadFile {
    char name[SMITH_FIELD_LENGTH];
    char type[SMITH_FIELD_LENGTH];
    char tmp_name[SMITH_FIELD_LENGTH];
};

struct Request {
    short port;
    char scheme[SMITH_FIELD_LENGTH];
    char host[SMITH_FIELD_LENGTH];
    char serverName[SMITH_FIELD_LENGTH];
    char serverAddress[SMITH_FIELD_LENGTH];
    char uri[SMITH_FIELD_LENGTH];
    char query[SMITH_FIELD_LENGTH];
    char body[SMITH_FIELD_LENGTH];
    char method[SMITH_FIELD_LENGTH];
    char remoteAddress[SMITH_FIELD_LENGTH];
    char documentRoot[SMITH_FIELD_LENGTH];
    int file_count;
    char headers[SMITH_HEADER_COUNT][2][SMITH_FIELD_LENGTH];
    int header_count;
    UploadFile files[SMITH_FILE_COUNT];
};

struct Trace {
    int classID;
    int methodID;
    bool blocked;
    int count;
    char ret[SMITH_ARG_LENGTH];
    char args[SMITH_ARG_COUNT][SMITH_ARG_LENGTH];
    char stackTrace[SMITH_TRACE_COUNT][SMITH_TRACE_LENGTH];
    Request request;
};

struct MatchRule {
    int index;
    std::string regex;
};

struct Filter {
    int classId;
    int methodID;
    std::list<MatchRule> include;
    std::list<MatchRule> exclude;
};

struct FilterConfig {
    std::string uuid;
    std::list<Filter> filters;
};

struct Block {
    int classId;
    int methodID;
    std::list<MatchRule> rules;
};

struct BlockConfig {
    std::string uuid;
    std::list<Block> blocks;
};

struct Limit {
    int classId;
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
void to_json(nlohmann::json &j, const UploadFile &uploadFile);
void to_json(nlohmann::json &j, const Request &request);
void to_json(nlohmann::json &j, const Trace &trace);

void from_json(const nlohmann::json &j, MatchRule &matchRule);
void from_json(const nlohmann::json &j, Filter &filter);
void from_json(const nlohmann::json &j, Block &block);
void from_json(const nlohmann::json &j, Limit &limit);
void from_json(const nlohmann::json &j, FilterConfig &config);
void from_json(const nlohmann::json &j, BlockConfig &config);
void from_json(const nlohmann::json &j, LimitConfig &config);

#endif //PHP_PROBE_SMITH_MESSAGE_H
