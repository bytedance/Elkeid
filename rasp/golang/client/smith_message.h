#ifndef GO_PROBE_SMITH_MESSAGE_H
#define GO_PROBE_SMITH_MESSAGE_H

#include <nlohmann/json.hpp>
#include <go/stack/smith_trace.h>
#include <go/symbol/build_info.h>

enum emOperate {
    emExit,
    emHeartBeat,
    emTrace,
    emConfig,
    emControl,
    emDetect
};

struct CSmithMessage {
    emOperate operate;
    nlohmann::json data;
};

void to_json(nlohmann::json &j, const CSmithMessage &m);
void from_json(const nlohmann::json &j, CSmithMessage &m);

void to_json(nlohmann::json &j, const CSmithTrace &t);
void to_json(nlohmann::json &j, const CModule &m);
void to_json(nlohmann::json &j, const CModuleInfo &i);

#endif //GO_PROBE_SMITH_MESSAGE_H
