#ifndef GO_PROBE_SMITH_PROBE_H
#define GO_PROBE_SMITH_PROBE_H

#include "smith_message.h"
#include <z_sync.h>
#include <zero/singleton.h>
#include <zero/atomic/event.h>
#include <zero/atomic/circular_buffer.h>
#include <go/version.h>
#include <go/symbol/symbol.h>

constexpr auto CLASS_MAX = 15;
constexpr auto METHOD_MAX = 20;

constexpr auto BLOCK_RULE_LENGTH = 256;
constexpr auto BLOCK_RULE_MAX_COUNT = 8;

constexpr auto TRACE_BUFFER_SIZE = 100;

struct Target {
#define gTarget zero::Singleton<Target>::getInstance()
    go::Version version;
    std::unique_ptr<go::symbol::SymbolTable> symbolTable;
};

struct Policy {
    size_t ruleCount;
    size_t KeywordCount;
    char policyID[POLICY_ID_LENGTH];
    std::pair<int, char[BLOCK_RULE_LENGTH]> rules[BLOCK_RULE_MAX_COUNT];
    std::pair<LogicalOperator, char[BLOCK_RULE_MAX_COUNT][BLOCK_RULE_LENGTH]> stackFrame;
    Policy *next;
};

struct Probe {
#define gProbe zero::Singleton<Probe>::getInstance()
    int efd{-1};
    std::atomic<bool> waiting;
    std::atomic<int> quotas[CLASS_MAX][METHOD_MAX];
    z_rwlock_t locks[CLASS_MAX][METHOD_MAX];
    std::pair<size_t, Policy *> policies[CLASS_MAX][METHOD_MAX];
    zero::atomic::CircularBuffer<Trace, TRACE_BUFFER_SIZE> buffer;
    std::atomic<int64_t> discard_surplus;
    std::atomic<int64_t> discard_post;
    std::atomic<int64_t> discard_send;
};

void startProbe();

#endif //GO_PROBE_SMITH_PROBE_H
