#ifndef GO_PROBE_EBPF_SMITH_MESSAGE_H
#define GO_PROBE_EBPF_SMITH_MESSAGE_H

#include <list>
#include <vector>
#include <regex>
#include <nlohmann/json.hpp>
#include <sys/types.h>

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

struct ProcessInfo {
    int sid;
    pid_t ppid;
    pid_t tgid;
    pid_t nspid;
    std::string exe;
    std::string argv;
    uid_t ruid;
    uid_t euid;
    uid_t suid;
    uid_t fuid;
    pid_t rgid;
    pid_t egid;
    pid_t sgid;
    pid_t fgid;
};

struct SmithMessage {
    pid_t pid;
    std::string version;
    std::shared_ptr<ProcessInfo> processInfo;
    Operate operate;
    nlohmann::json data;
};

struct Heartbeat {
    std::string filter;
};

struct Request {
    std::string method;
    std::string uri;
    std::string host;
    std::string remote;
#ifndef DISABLE_HTTP_HEADER
    std::map<std::string, std::string> headers;
#endif
};

struct Trace {
    int classID;
    int methodID;
    std::vector<std::string> args;
    std::vector<std::string> stackTrace;
#ifdef ENABLE_HTTP
    Request request;
#endif
};

struct MatchRule {
    int index;
    std::regex regex;
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

struct Limit {
    int classID;
    int methodID;
    int quota;
};

struct LimitConfig {
    std::string uuid;
    std::list<Limit> limits;
};

void to_json(nlohmann::json &j, const ProcessInfo &processInfo);

void to_json(nlohmann::json &j, const SmithMessage &message);
void from_json(const nlohmann::json &j, SmithMessage &message);

void to_json(nlohmann::json &j, const Heartbeat &heartbeat);
void to_json(nlohmann::json &j, const Request &request);
void to_json(nlohmann::json &j, const Trace &trace);

void from_json(const nlohmann::json &j, MatchRule &matchRule);
void from_json(const nlohmann::json &j, Filter &filter);
void from_json(const nlohmann::json &j, FilterConfig &config);
void from_json(const nlohmann::json &j, Limit &limit);
void from_json(const nlohmann::json &j, LimitConfig &config);

#endif //GO_PROBE_EBPF_SMITH_MESSAGE_H
