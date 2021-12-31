#ifndef GO_PROBE_SMITH_MESSAGE_H
#define GO_PROBE_SMITH_MESSAGE_H

#include <nlohmann/json.hpp>
#include <go/stack/smith_trace.h>
#include <go/symbol/build_info.h>

enum emOperate {
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

struct CSmithMessage {
    emOperate operate;
    nlohmann::json data;
};

struct CMatchRule {
    int index;
    std::string regex;
};

struct CFilter {
    int classId;
    int methodID;
    std::list<CMatchRule> include;
    std::list<CMatchRule> exclude;
};

struct CBlock {
    int classId;
    int methodID;
    std::list<CMatchRule> rules;
};

struct CLimit {
    int classId;
    int methodID;
    int quota;
};

void to_json(nlohmann::json &j, const CSmithMessage &m);
void from_json(const nlohmann::json &j, CSmithMessage &m);

void to_json(nlohmann::json &j, const CSmithTrace &t);
void to_json(nlohmann::json &j, const CModule &m);
void to_json(nlohmann::json &j, const CModuleInfo &i);

void from_json(const nlohmann::json &j, CMatchRule &r);
void from_json(const nlohmann::json &j, CFilter &f);
void from_json(const nlohmann::json &j, CBlock &b);
void from_json(const nlohmann::json &j, CLimit &l);

#endif //GO_PROBE_SMITH_MESSAGE_H
