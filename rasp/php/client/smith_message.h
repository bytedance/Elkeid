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

struct UploadFile {
    char name[SMITH_FIELD_LENGTH];
    char type[SMITH_FIELD_LENGTH];
    char tmp_name[SMITH_FIELD_LENGTH];
};

struct SmithRequest {
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

struct SmithTrace {
    int classID;
    int methodID;
    bool blocked;
    int count;
    char ret[SMITH_ARG_LENGTH];
    char args[SMITH_ARG_COUNT][SMITH_ARG_LENGTH];
    char stackTrace[SMITH_TRACE_COUNT][SMITH_TRACE_LENGTH];
    SmithRequest request;
};

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

struct Block {
    int classId;
    int methodID;
    std::list<MatchRule> rules;
};

struct Limit {
    int classId;
    int methodID;
    int quota;
};

void to_json(nlohmann::json &j, const SmithRequest &r);

void to_json(nlohmann::json &j, const SmithMessage &m);
void from_json(const nlohmann::json &j, SmithMessage &m);

void to_json(nlohmann::json &j, const SmithTrace &t);

void from_json(const nlohmann::json &j, MatchRule &r);
void from_json(const nlohmann::json &j, Filter &f);
void from_json(const nlohmann::json &j, Block &b);
void from_json(const nlohmann::json &j, Limit &l);

#endif //PHP_PROBE_SMITH_MESSAGE_H
