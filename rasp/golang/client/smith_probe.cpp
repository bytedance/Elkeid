#include "smith_probe.h"
#include <common/log.h>

constexpr auto WAIT_TIMEOUT = timespec {30, 0};

void CSmithProbe::start() {
    gSmithClient->setNotify(this);
    mThread.start(this, &CSmithProbe::traceThread);
}

void CSmithProbe::stop() {
    mExit = true;
    mCondition.notify();
    mThread.stop();
}

void CSmithProbe::trace(const CSmithTrace &smithTrace) {
    if (mTraces.full())
        return;

    if (!mTraces.enqueue(smithTrace))
        return;

    if (mTraces.size() >= TRACE_MAX_SIZE / 2)
        mCondition.notify();
}

void CSmithProbe::traceThread() {
    LOG_INFO("trace thread start");

    pthread_setname_np(pthread_self(), "go-probe");

    while (!mExit) {
        if (mTraces.empty())
            mCondition.wait(&WAIT_TIMEOUT);

        CSmithTrace smithTrace = {};

        if (!mTraces.dequeue(smithTrace))
            continue;

        gSmithClient->write({emTrace, smithTrace});
    }
}

void CSmithProbe::onMessage(const CSmithMessage &message) {
    switch (message.operate) {
        case emHeartBeat:
            LOG_INFO("heartbeat");
            break;

        case emDetect:
            LOG_INFO("detect");
            gSmithClient->write({emDetect, {{"golang", gBuildInfo->mModuleInfo}}});
            break;

        default:
            break;
    }
}
