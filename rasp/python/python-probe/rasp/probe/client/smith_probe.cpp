#include "smith_probe.h"
#include "smith_client.h"
#include <zero/log.h>
#include <aio/ev/timer.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <csignal>
#include <re.h>

#ifndef PR_SET_MM
#define PR_SET_MM 35
#define PR_SET_MM_ARG_START 8
#define PR_SET_MM_ARG_END 9
#endif

using namespace std::chrono_literals;

constexpr auto DEFAULT_QUOTAS = 12000;

Policy *Probe::popNode() {
    std::optional<size_t> index = nodes.acquire();

    if (!index)
        return nullptr;

    Policy *node = nodes[*index];
    nodes.release(*index);

    return node;
}

bool Probe::pushNode(Policy *node) {
    std::optional<size_t> index = nodes.reserve();

    if (!index)
        return false;

    nodes[*index] = node;
    nodes.commit(*index);

    return true;
}

Probe *Probe::getInstance() {
    static auto instance = newShared<Probe>();
    return instance;
}

void *allocShared(size_t size) {
    void *ptr = mmap(
            nullptr,
            (size + sizeof(size_t) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1),
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_SHARED,
            -1,
            0
    );

    if (ptr == MAP_FAILED)
        return nullptr;

    *(size_t *) ptr = size;

    return (std::byte *) ptr + sizeof(size_t);
}

void freeShared(void *ptr) {
    munmap(
            (std::byte *) ptr - sizeof(size_t),
            *(size_t *) ((std::byte *) ptr - sizeof(size_t))
    );
}

bool pass(const Trace &trace, const std::map<std::tuple<int, int>, Filter> &filters) {
    auto it = filters.find({trace.classID, trace.methodID});

    if (it == filters.end())
        return true;

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

void startProbe() {
    if (fork() != 0)
        return;

    INIT_FILE_LOG(zero::INFO_LEVEL, "python-probe-addon");

    if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
        LOG_ERROR("set death signal failed");
        exit(-1);
    }

    char buffer[64] = {};
    int n = snprintf(buffer, sizeof(buffer), "Python RASP(%d)", getppid());

    if (n < 0)
        exit(-1);

    prctl(PR_SET_MM, PR_SET_MM_ARG_START, (unsigned long) buffer, 0, 0);
    prctl(PR_SET_MM, PR_SET_MM_ARG_END, (unsigned long) buffer + n + 1, 0, 0);

    pthread_setname_np(pthread_self(), "python-probe");

    std::shared_ptr<aio::Context> context = aio::newContext();

    if (!context) {
        LOG_ERROR("create aio context failed");
        return;
    }

    int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

    if (efd < 0) {
        LOG_ERROR("create event fd failed");
        return;
    }

    gProbe->efd = efd;
    std::fill_n(gProbe->quotas[0], sizeof(gProbe->quotas) / sizeof(**gProbe->quotas), DEFAULT_QUOTAS);

    std::shared_ptr<Heartbeat> heartbeat = std::make_shared<Heartbeat>();
    std::shared_ptr<std::map<std::tuple<int, int>, Filter>> filters = std::make_shared<std::map<std::tuple<int, int>, Filter>>();
    std::shared_ptr<std::map<std::tuple<int, int>, int>> limits = std::make_shared<std::map<std::tuple<int, int>, int>>();

    const auto [receiver, sender] = startClient(context);

    std::make_shared<aio::ev::Timer>(context)->setInterval(1min, [=, sender = sender]() {
        for (int cid = 0; cid < CLASS_MAX; cid++) {
            for (int mid = 0; mid < METHOD_MAX; mid++) {
                auto it = limits->find({cid, mid});

                if (it == limits->end()) {
                    gProbe->quotas[cid][mid] = DEFAULT_QUOTAS;
                    continue;
                }

                gProbe->quotas[cid][mid] = it->second;
            }
        }

        sender->sendNoWait({HEARTBEAT, *heartbeat});
        return true;
    });

    zero::async::promise::loop<void>([=, receiver = receiver](const auto &loop) {
        receiver->receive()->then([=](const SmithMessage &message) {
            switch (message.operate) {
                case FILTER: {
                    try {
                        auto config = message.data.get<FilterConfig>();

                        filters->clear();
                        heartbeat->filter = config.uuid;

                        std::transform(
                                config.filters.begin(),
                                config.filters.end(),
                                std::inserter(*filters, filters->end()),
                                [](const auto &filter) {
                                    return std::pair{std::tuple{filter.classID, filter.methodID}, filter};
                                }
                        );
                    } catch (const nlohmann::json::exception &e) {
                        LOG_ERROR("exception: %s", e.what());
                    }

                    break;
                }

                case BLOCK: {
                    try {
                        auto config = message.data.get<BlockConfig>();

                        heartbeat->block = config.uuid;

                        for (int cid = 0; cid < CLASS_MAX; cid++) {
                            for (int mid = 0; mid < METHOD_MAX; mid++) {
                                z_rwlock_t *lock = gProbe->locks[cid] + mid;
                                z_rwlock_write_lock(lock);

                                auto &[size, policies] = gProbe->policies[cid][mid];

                                if (size > 0) {
                                    for (int i = 0; i < size; i++)
                                        gProbe->pushNode(policies[i]);

                                    size = 0;
                                }

                                std::vector<Block> blocks;

                                std::copy_if(
                                        config.blocks.begin(),
                                        config.blocks.end(),
                                        std::back_inserter(blocks),
                                        [=](const auto &block) {
                                            return block.classID == cid && block.methodID == mid;
                                        }
                                );

                                if (blocks.empty()) {
                                    z_rwlock_write_unlock(lock);
                                    continue;
                                }

                                while (size < blocks.size()) {
                                    Policy *node = gProbe->popNode();

                                    if (!node) {
                                        LOG_ERROR("pop node failed");

                                        for (int i = 0; i < size; i++)
                                            gProbe->pushNode(policies[i]);

                                        size = 0;
                                        break;
                                    }

                                    policies[size++] = node;
                                }

                                for (size_t index = 0; index < size; index++) {
                                    Policy *policy = policies[index];
                                    Block &block = blocks[index];

                                    if (block.rules.size() > BLOCK_RULE_MAX_COUNT) {
                                        LOG_WARNING("the number of rules exceeds limit");
                                        continue;
                                    }

                                    if (std::any_of(
                                            block.rules.begin(),
                                            block.rules.end(),
                                            [](const auto &rule) {
                                                return rule.regex.length() >= BLOCK_RULE_LENGTH;
                                            })) {
                                        LOG_WARNING("the length of the rule exceeds limit");
                                        continue;
                                    }

                                    if (block.stackFrame) {
                                        if (block.stackFrame->keywords.size() > BLOCK_RULE_MAX_COUNT) {
                                            LOG_WARNING("the number of rules exceeds limit");
                                            continue;
                                        }

                                        if (std::any_of(
                                                block.stackFrame->keywords.begin(),
                                                block.stackFrame->keywords.end(),
                                                [](const auto &keyword) {
                                                    return keyword.length() >= BLOCK_RULE_LENGTH;
                                                })) {
                                            LOG_WARNING("the length of the keyword exceeds limit");
                                            continue;
                                        }
                                    }

                                    strncpy(policy->policyID, block.policyID.c_str(), sizeof(Policy::policyID) - 1);
                                    policy->ruleCount = block.rules.size();

                                    for (size_t i = 0; i < policy->ruleCount; i++) {
                                        policy->rules[i].first = block.rules[i].index;
                                        strcpy(policy->rules[i].second, block.rules[i].regex.c_str());
                                    }

                                    if (block.stackFrame) {
                                        policy->KeywordCount = block.stackFrame->keywords.size();
                                        policy->stackFrame.first = block.stackFrame->logicalOperator;

                                        for (size_t i = 0; i < policy->KeywordCount; i++) {
                                            strcpy(policy->stackFrame.second[i], block.stackFrame->keywords[i].c_str());
                                        }
                                    }
                                }

                                z_rwlock_write_unlock(lock);
                            }
                        }
                    } catch (const nlohmann::json::exception &e) {
                        LOG_ERROR("exception: %s", e.what());
                    }

                    break;
                }

                case LIMIT: {
                    try {
                        auto config = message.data.get<LimitConfig>();

                        limits->clear();
                        heartbeat->limit = config.uuid;

                        std::transform(
                                config.limits.begin(),
                                config.limits.end(),
                                std::inserter(*limits, limits->end()),
                                [](const auto &limit) {
                                    return std::pair{std::tuple{limit.classID, limit.methodID}, limit.quota};
                                }
                        );
                    } catch (const nlohmann::json::exception &e) {
                        LOG_ERROR("exception: %s", e.what());
                    }

                    break;
                }

                default:
                    break;
            }

            P_CONTINUE(loop);
        })->fail([=](const zero::async::promise::Reason &reason) {
            LOG_ERROR("receive failed: %s", reason.message.c_str());
            P_BREAK(loop);
        });
    });

    zero::async::promise::loop<void>(
            [=, sender = sender, event = std::make_shared<aio::ev::Event>(context, efd)](const auto &loop) {
                std::optional<size_t> index = gProbe->buffer.acquire();

                if (!index) {
                    gProbe->waiting = true;

                    event->on(EV_READ, 30s)->then([=](short what) {
                        if (what & EV_TIMEOUT) {
                            P_CONTINUE(loop);
                            return;
                        }

                        eventfd_t value;
                        eventfd_read(efd, &value);

                        P_CONTINUE(loop);
                    });

                    return;
                }

                Trace trace = gProbe->buffer[*index];
                gProbe->buffer.release(*index);

                if (pass(trace, *filters))
                    sender->sendNoWait({TRACE, gProbe->buffer[*index]});

                P_CONTINUE(loop);
            }
    );

    context->dispatch();
}