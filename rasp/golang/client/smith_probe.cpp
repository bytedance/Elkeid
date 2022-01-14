#include "smith_probe.h"
#include <zero/log.h>
#include <go/api/api.h>
#include <unistd.h>

constexpr auto DEFAULT_QUOTAS = 12000;
constexpr auto RESET_QUOTAS_INTERVAL = 60;

constexpr auto WAIT_TIMEOUT = timespec {30, 0};

void CSmithProbe::start() {
    mClient.start();

    mThread.start(&CSmithProbe::traceThread);
    mTimer.start(&CSmithProbe::resetQuotas);
}

void CSmithProbe::stop() {
    mExit = true;

    z_cond_signal(&mCond);

    mThread.stop();
    mTimer.stop();

    mClient.stop();
}

void CSmithProbe::trace(const CSmithTrace &smithTrace) {
    if (mTraces.full())
        return;

    if (!mTraces.enqueue(smithTrace))
        return;

    if (mTraces.size() >= TRACE_BUFFER_SIZE / 2)
        z_cond_signal(&mCond);
}

void CSmithProbe::traceThread() {
    LOG_INFO("trace thread start");

    pthread_setname_np(pthread_self(), "go-probe");

    while (!mExit) {
        if (mTraces.empty())
            z_cond_wait(&mCond, nullptr, &WAIT_TIMEOUT);

        CSmithTrace smithTrace = {};

        if (!mTraces.dequeue(smithTrace))
            continue;

        if (!filter(smithTrace))
            continue;

        mClient.write({TRACE, smithTrace});
    }
}

void CSmithProbe::resetQuotas() {
    while (!mExit) {
        {
            std::lock_guard<std::mutex> _0_(mLimitMutex);

            for (const auto &api : GOLANG_API) {
                auto it = mLimits.find({api.metadata.classID, api.metadata.methodID});

                if (it == mLimits.end()) {
                    __atomic_store_n(api.metadata.quota, DEFAULT_QUOTAS, __ATOMIC_SEQ_CST);
                    continue;
                }

                __atomic_store_n(api.metadata.quota, it->second, __ATOMIC_SEQ_CST);
            }
        }

        sleep(RESET_QUOTAS_INTERVAL);
    }
}

void CSmithProbe::onMessage(const CSmithMessage &message) {
    switch (message.operate) {
        case HEARTBEAT:
            LOG_INFO("heartbeat message");
            break;

        case DETECT:
            LOG_INFO("detect message");
            mClient.write({DETECT, {{"golang", gBuildInfo->mModuleInfo}}});
            break;

        case FILTER: {
            LOG_INFO("filter message");

            if (!message.data.contains("filters"))
                break;

            std::list<CFilter> filters = message.data.at("filters").get<std::list<CFilter>>();
            std::lock_guard<std::mutex> _0_(mFilterMutex);

            mFilters.clear();

            for (const auto &f : filters) {
                mFilters.insert({{f.classId, f.methodID}, f});
            }

            break;
        }

        case BLOCK: {
            LOG_INFO("block message");

            if (!message.data.contains("blocks"))
                break;

            std::list<CBlock> blocks = message.data.at("blocks").get<std::list<CBlock>>();

            for (const auto &block : blocks) {
                auto it = std::find_if(GOLANG_API.begin(), GOLANG_API.end(), [&](const auto &r) {
                    return r.metadata.classID == block.classId && r.metadata.methodID == block.methodID;
                });

                if (it == GOLANG_API.end())
                    continue;

                if (block.rules.size() > BLOCK_RULE_COUNT) {
                    LOG_WARNING("block rule size limit");
                    continue;
                }

                z_rwlock_write_lock(it->metadata.lock);

                int count = 0;

                for (const auto &r : block.rules) {
                    if (r.regex.length() >= BLOCK_RULE_LENGTH) {
                        LOG_WARNING("block rule regex length limit");
                        continue;
                    }

                    CAPIBlockRule *item = it->metadata.rules->items + count++;

                    item->index = r.index;
                    strcpy(item->regex, r.regex.c_str());
                }

                it->metadata.rules->count = count;

                z_rwlock_write_unlock(it->metadata.lock);
            }

            break;
        }

        case LIMIT: {
            LOG_INFO("limit message");

            if (!message.data.contains("limits"))
                break;

            std::list<CLimit> limits = message.data.at("limits").get<std::list<CLimit>>();
            std::lock_guard<std::mutex> _0_(mLimitMutex);

            mLimits.clear();

            for (const auto &l : limits) {
                mLimits.insert({{l.classId, l.methodID}, l.quota});
            }

            break;
        }

        default:
            break;
    }
}

bool CSmithProbe::filter(const CSmithTrace &smithTrace) {
    std::lock_guard<std::mutex> _0_(mFilterMutex);

    auto it = mFilters.find({smithTrace.classID, smithTrace.methodID});

    if (it == mFilters.end()) {
        return true;
    }

    const auto &include = it->second.include;
    const auto &exclude = it->second.exclude;

    auto pred = [&](const CMatchRule &rule) {
        if (rule.index >= smithTrace.count)
            return false;

        int length = 0;

        return re_match(rule.regex.c_str(), smithTrace.args[rule.index], &length) != -1;
    };

    if (!include.empty() && std::none_of(include.begin(), include.end(), pred))
        return false;

    if (!exclude.empty() && std::any_of(exclude.begin(), exclude.end(), pred))
        return false;

    return true;
}
