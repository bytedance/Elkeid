#include "smith_probe.h"
#include <zero/log.h>
#include <event2/thread.h>
#include <php/api.h>

constexpr auto WAIT_TIMEOUT = std::chrono::seconds{30};
constexpr auto RESET_QUOTAS_INTERVAL = timeval{60, 0};

SmithProbe::SmithProbe() : mEventBase((evthread_use_pthreads(), event_base_new())) {
    struct stub {
        static void onEvent(evutil_socket_t fd, short what, void *arg) {
            static_cast<SmithProbe *>(arg)->onTimer();
        }
    };

    mTimer = event_new(mEventBase, -1, EV_PERSIST, stub::onEvent, this);
}

SmithProbe::~SmithProbe() {
    if (mTimer) {
        event_free(mTimer);
        mTimer = nullptr;
    }

    if (mEventBase) {
        event_base_free(mEventBase);
        mEventBase = nullptr;
    }
}

void SmithProbe::start() {
    mClient.connect();
    mConsumer.start(&SmithProbe::consume);

    evtimer_add(mTimer, &RESET_QUOTAS_INTERVAL);
    event_base_dispatch(mEventBase);
}

void SmithProbe::stop() {
    mExit = true;

    evtimer_del(mTimer);
    event_base_loopbreak(mEventBase);

    gAPITrace->mEvent.notify();

    mConsumer.stop();
    mClient.disconnect();
}

void SmithProbe::consume() {
    while (!mExit) {
        std::optional<size_t> index = gAPITrace->mBuffer.acquire();

        if (!index) {
            gAPITrace->mEvent.wait(WAIT_TIMEOUT);
            continue;
        }

        const Trace &trace = gAPITrace->mBuffer[*index];

        if (filter(trace))
            mClient.write({TRACE, trace});

        gAPITrace->mBuffer.release(*index);
    }
}

void SmithProbe::onTimer() {
    mClient.write({HEARTBEAT, mHeartbeat});

    std::lock_guard<std::mutex> _0_(mLimitMutex);

    for (int i = 0; i < CLASS_MAX; i++) {
        for (int j = 0; j < METHOD_MAX; j++) {
            auto it = mLimits.find({i, j});

            if (it == mLimits.end()) {
                __atomic_store_n(&gAPIConfig->mQuotas[i][j], DEFAULT_QUOTAS, __ATOMIC_SEQ_CST);
                continue;
            }

            __atomic_store_n(&gAPIConfig->mQuotas[i][j], it->second, __ATOMIC_SEQ_CST);
        }
    }
}

void SmithProbe::onMessage(const SmithMessage &message) {
    switch (message.operate) {
        case HEARTBEAT:
            LOG_INFO("heartbeat message");
            break;

        case DETECT:
            LOG_INFO("detect message");
            break;

        case FILTER: {
            LOG_INFO("filter message");

            auto config = message.data.get<FilterConfig>();

            std::lock_guard<std::mutex> _0_(mFilterMutex);

            mFilters.clear();
            mHeartbeat.filter = config.uuid;

            for (const auto &filter: config.filters)
                mFilters.insert({{filter.classID, filter.methodID}, filter});

            break;
        }

        case BLOCK: {
            LOG_INFO("block message");

            auto config = message.data.get<BlockConfig>();

            mHeartbeat.block = config.uuid;

            for (int i = 0; i < CLASS_MAX; i++) {
                for (int j = 0; j < METHOD_MAX; j++) {
                    z_rwlock_write_lock(&gAPIConfig->mBlockPolicies[i][j].lock);

                    auto it = std::find_if(config.blocks.begin(), config.blocks.end(), [=](const auto &block) {
                        return block.classID == i && block.methodID == j;
                    });

                    if (it == config.blocks.end()) {
                        gAPIConfig->mBlockPolicies[i][j].count = 0;
                        z_rwlock_write_unlock(&gAPIConfig->mBlockPolicies[i][j].lock);
                        continue;
                    }

                    if (it->rules.size() > BLOCK_RULE_COUNT) {
                        LOG_WARNING("block rule size limit");

                        gAPIConfig->mBlockPolicies[i][j].count = 0;
                        z_rwlock_write_unlock(&gAPIConfig->mBlockPolicies[i][j].lock);

                        continue;
                    }

                    int count = 0;

                    for (const auto &r : it->rules) {
                        if (r.regex.length() >= BLOCK_RULE_LENGTH) {
                            LOG_WARNING("block rule regex length limit");
                            continue;
                        }

                        auto rule = gAPIConfig->mBlockPolicies[i][j].rules + count++;

                        rule->first = r.index;
                        strcpy(rule->second, r.regex.c_str());
                    }

                    gAPIConfig->mBlockPolicies[i][j].count = count;
                    z_rwlock_write_unlock(&gAPIConfig->mBlockPolicies[i][j].lock);
                }
            }

            break;
        }

        case LIMIT: {
            LOG_INFO("limit message");

            auto config = message.data.get<LimitConfig>();

            std::lock_guard<std::mutex> _0_(mLimitMutex);

            mLimits.clear();
            mHeartbeat.limit = config.uuid;

            for (const auto &limit: config.limits)
                mLimits.insert({{limit.classID, limit.methodID}, limit.quota});

            break;
        }

        default:
            break;
    }
}

bool SmithProbe::filter(const Trace &trace) {
    std::lock_guard<std::mutex> _0_(mFilterMutex);

    auto it = mFilters.find({trace.classID, trace.methodID});

    if (it == mFilters.end()) {
        return true;
    }

    const auto &include = it->second.include;
    const auto &exclude = it->second.exclude;

    auto pred = [&](const MatchRule &rule) {
        if (rule.index >= trace.count)
            return false;

        int length = 0;

        return re_match(rule.regex.c_str(), trace.args[rule.index], &length) != -1;
    };

    if (!include.empty() && std::none_of(include.begin(), include.end(), pred))
        return false;

    if (!exclude.empty() && std::any_of(exclude.begin(), exclude.end(), pred))
        return false;

    return true;
}
