#include "smith_probe.h"
#include "smith_client.h"
#include <zero/log.h>
#include <aio/ev/timer.h>
#include <sys/eventfd.h>
#include <go/api/api.h>
#include <re.h>

using namespace std::chrono_literals;

constexpr auto DEFAULT_QUOTAS = 12000;

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
    pthread_setname_np(pthread_self(), "go-probe");

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

    zero::ptr::makeRef<aio::ev::Timer>(context)->setInterval(1min, [=, sender = sender]() {
        for (const auto &api: GOLANG_API) {
            int classID = api.metadata.classID;
            int methodID = api.metadata.methodID;

            auto it = limits->find({classID, methodID});

            if (it == limits->end()) {
                gProbe->quotas[classID][methodID] = DEFAULT_QUOTAS;
                continue;
            }

            gProbe->quotas[classID][methodID] = it->second;
        }

        sender->trySend({HEARTBEAT, *heartbeat});
        return true;
    });

    zero::async::promise::doWhile([=, receiver = receiver]() {
        return receiver->receive()->then([=](const SmithMessage &message) {
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

                        for (const auto &api: GOLANG_API) {
                            int classID = api.metadata.classID;
                            int methodID = api.metadata.methodID;

                            z_rwlock_t *lock = gProbe->locks[api.metadata.classID] + api.metadata.methodID;
                            z_rwlock_write_lock(lock);

                            auto &[size, policies] = gProbe->policies[classID][methodID];

                            if (size > 0) {
                                size = 0;
                                free(policies);
                                policies = nullptr;
                            }

                            std::vector<Block> blocks;

                            std::copy_if(
                                    config.blocks.begin(),
                                    config.blocks.end(),
                                    std::back_inserter(blocks),
                                    [=](const auto &block) {
                                        return block.classID == classID && block.methodID == methodID;
                                    }
                            );

                            if (blocks.empty()) {
                                z_rwlock_write_unlock(lock);
                                continue;
                            }

                            size = blocks.size();
                            policies = (Policy *) malloc(sizeof(Policy) * size);

                            for (size_t index = 0; index < size; index++) {
                                Policy *policy = policies + index;
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
        });
    })->fail([=](const zero::async::promise::Reason &reason) {
        LOG_ERROR("receive failed: %s", reason.message.c_str());
    });

    zero::async::promise::loop<void>(
            [=, sender = sender, event = zero::ptr::makeRef<aio::ev::Event>(context, efd)](const auto &loop) {
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
                    sender->trySend({TRACE, gProbe->buffer[*index]});

                P_CONTINUE(loop);
            }
    );

    context->dispatch();
}
