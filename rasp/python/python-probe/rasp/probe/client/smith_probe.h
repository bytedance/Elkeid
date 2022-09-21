#ifndef PYTHON_CLIENT_SMITH_PROBE_H
#define PYTHON_CLIENT_SMITH_PROBE_H

#include "smith_client.h"
#include <zero/singleton.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <z_sync.h>
#include <tiny-regex-c/re.h>
#include <zero/atomic/event.h>
#include <zero/atomic/circular_buffer.h>

constexpr auto CLASS_MAX = 20;
constexpr auto METHOD_MAX = 20;
constexpr auto BLOCK_RULE_COUNT = 20;
constexpr auto BLOCK_RULE_LENGTH = 256;

constexpr auto DEFAULT_QUOTAS = 12000;
constexpr auto TRACE_BUFFER_SIZE = 100;

template<typename T>
T *allocShared() {
    void *ptr = mmap(
            nullptr,
            (sizeof(T) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1),
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_SHARED,
            -1,
            0
    );

    if (ptr == MAP_FAILED)
        return nullptr;

    return new(ptr) T();
}

class APITrace {
#define gAPITrace APITrace::getInstance()
public:
    static APITrace *getInstance() {
        static auto instance = allocShared<APITrace>();
        return instance;
    }

public:
    void enqueue(const Trace &trace) {
        std::optional<size_t> index = mBuffer.reserve();

        if (!index)
            return;

        mBuffer[*index] = trace;
        mBuffer.commit(*index);

        if (mBuffer.size() >= TRACE_BUFFER_SIZE / 2)
            mEvent.notify();
    }

public:
    zero::atomic::Event mEvent;
    zero::atomic::CircularBuffer<Trace, TRACE_BUFFER_SIZE> mBuffer;
};

struct BlockPolicy {
    int count;
    z_rwlock_t lock;
    std::pair<int, char[BLOCK_RULE_LENGTH]> rules[BLOCK_RULE_COUNT];
};

class APIConfig {
#define gAPIConfig APIConfig::getInstance()
public:
    APIConfig() {
        for (auto &c: mQuotas) {
            for (auto &m: c) {
                m = DEFAULT_QUOTAS;
            }
        }
    }

public:
    static APIConfig *getInstance() {
        static auto instance = allocShared<APIConfig>();
        return instance;
    }

public:
    bool surplus(int classID, int methodID) {
        int n = __atomic_load_n(&mQuotas[classID][methodID], __ATOMIC_SEQ_CST);

        do {
            if (n <= 0)
                return false;
        } while (!__atomic_compare_exchange_n(&mQuotas[classID][methodID], &n, n - 1, true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));

        return true;
    }

    bool block(const Trace &trace) {
        BlockPolicy &policy = mBlockPolicies[trace.classID][trace.methodID];

        z_rwlock_read_lock(&policy.lock);

        bool match = std::any_of(policy.rules, policy.rules + policy.count, [&](const auto &rule) {
            if (rule.first >= trace.count)
                return false;

            int length = 0;
            return re_match(rule.second, trace.args[rule.first], &length) != -1;
        });

        z_rwlock_read_unlock(&policy.lock);

        return match;
    }

public:
    int mQuotas[CLASS_MAX][METHOD_MAX]{};
    BlockPolicy mBlockPolicies[CLASS_MAX][METHOD_MAX]{};
};

class SmithProbe: public IMessageHandler {
#define gSmithProbe zero::Singleton<SmithProbe>::getInstance()
public:
    SmithProbe();
    ~SmithProbe() override;

public:
    void start();
    void stop();

public:
    void consume();

public:
    void onTimer();
    void onMessage(const SmithMessage &message) override;

private:
    bool filter(const Trace& trace);

private:
    bool mExit{false};

private:
    std::mutex mLimitMutex;
    std::mutex mFilterMutex;
    std::map<std::tuple<int, int>, int> mLimits;
    std::map<std::tuple<int, int>, Filter> mFilters;

private:
    event *mTimer;
    event_base *mEventBase;
    Heartbeat mHeartbeat;
    SmithClient mClient{mEventBase, this};
    zero::Thread<SmithProbe> mConsumer{this};
};


#endif //PYTHON_CLIENT_SMITH_PROBE_H
