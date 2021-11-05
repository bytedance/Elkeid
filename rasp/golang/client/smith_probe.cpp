#include "smith_probe.h"
#include <zero/log.h>
#include <go/api/api.h>

constexpr auto WAIT_TIMEOUT = timespec {30, 0};

void CSmithProbe::start() {
    mClient.start();
    mThread.start(&CSmithProbe::traceThread);
}

void CSmithProbe::stop() {
    mExit = true;

    z_cond_signal(&mCond);

    mThread.stop();
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
            std::lock_guard<std::mutex> _0_(mMutex);

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
        }

        default:
            break;
    }
}

bool CSmithProbe::filter(const CSmithTrace &smithTrace) {
    std::lock_guard<std::mutex> _0_(mMutex);

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
