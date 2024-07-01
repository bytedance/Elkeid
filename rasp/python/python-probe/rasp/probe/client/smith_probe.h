#ifndef PYTHON_CLIENT_SMITH_PROBE_H
#define PYTHON_CLIENT_SMITH_PROBE_H

#include "smith_message.h"
#include <z_sync.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <zero/singleton.h>
#include <zero/atomic/event.h>
#include <zero/atomic/circular_buffer.h>

constexpr auto CLASS_MAX = 20;
constexpr auto METHOD_MAX = 20;

constexpr auto BLOCK_RULE_LENGTH = 256;
constexpr auto BLOCK_RULE_MAX_COUNT = 8;

constexpr auto TRACE_BUFFER_SIZE = 100;
constexpr auto EXCEPTIONINFO_BUFFER_SIZE = 100;

constexpr auto MAX_POLICY_COUNT = 10;
constexpr auto PREPARED_POLICY_COUNT = 100;

struct Policy {
    size_t ruleCount;
    size_t KeywordCount;
    char policyID[POLICY_ID_LENGTH];
    std::pair<int, char[BLOCK_RULE_LENGTH]> rules[BLOCK_RULE_MAX_COUNT];
    std::pair<LogicalOperator, char[BLOCK_RULE_MAX_COUNT][BLOCK_RULE_LENGTH]> stackFrame;
};

struct Probe {
#define gProbe Probe::getInstance()
    int efd{-1};
    int infoefd;
    std::atomic<bool> waiting;
    std::atomic<bool> infowaiting;
    std::atomic<int> quotas[CLASS_MAX][METHOD_MAX];
    z_rwlock_t locks[CLASS_MAX][METHOD_MAX];
    std::pair<size_t, Policy *[MAX_POLICY_COUNT]> policies[CLASS_MAX][METHOD_MAX];
    zero::atomic::CircularBuffer<Trace, TRACE_BUFFER_SIZE> buffer;
    zero::atomic::CircularBuffer<ExceptionInfo, EXCEPTIONINFO_BUFFER_SIZE> info;
    zero::atomic::CircularBuffer<Policy *, PREPARED_POLICY_COUNT> nodes;

    Policy *popNode();
    bool pushNode(Policy *node);

    static Probe *getInstance();
};

void *allocShared(size_t size);
void freeShared(void *ptr);

template<typename T>
T *newShared() {
    void *ptr = allocShared(sizeof(T));

    if (!ptr)
        return nullptr;

    return new(ptr) T();
}

void startProbe();

#endif //PYTHON_CLIENT_SMITH_PROBE_H
