#include "api/api.h"
#include "client/smith_client.h"
#include "ebpf/src/event.h"
#include "ebpf/src/config.h"
#include "ebpf/probe.skel.h"
#include <Zydis/Zydis.h>
#include <zero/log.h>
#include <zero/os/procfs.h>
#include <zero/cache/lru.h>
#include <aio/ev/timer.h>
#include <aio/ev/buffer.h>
#include <go/symbol/reader.h>
#include <iostream>
#include <sys/prctl.h>
#include <unistd.h>
#include <csignal>

using namespace std::chrono_literals;

constexpr auto MAX_OFFSET = 100;
constexpr auto INSTRUCTION_BUFFER_SIZE = 128;
constexpr auto FRAME_CACHE_SIZE = 128;
constexpr auto DEFAULT_QUOTAS = 12000;

constexpr auto TRACK_HTTP_VERSION = go::Version{1, 12};
constexpr auto REGISTER_BASED_VERSION = go::Version{1, 17};
constexpr auto FRAME_POINTER_VERSION = go::Version{1, 7};

struct Instance {
    std::string version;
    go::symbol::seek::SymbolTable symbolTable;
    std::list<std::unique_ptr<bpf_link, decltype(bpf_link__destroy) *>> links;
    zero::cache::LRUCache<uintptr_t, std::string> cache;
    unsigned long long startTime;
    std::shared_ptr<ProcessInfo> processInfo;
    probe_config config;
    std::map<std::tuple<int, int>, Filter> filters;
    std::map<std::tuple<int, int>, int> limits;
    int quotas[CLASS_MAX][METHOD_MAX];
};

int onLog(libbpf_print_level level, const char *format, va_list args) {
    va_list copy;
    va_copy(copy, args);

    int length = vsnprintf(nullptr, 0, format, args);

    if (length <= 0)
        return 0;

    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(length + 1);
    vsnprintf(buffer.get(), length + 1, format, copy);

    switch (level) {
        case LIBBPF_WARN:
            LOG_WARNING("%s", zero::strings::trim(buffer.get()).c_str());
            break;

        case LIBBPF_INFO:
            LOG_INFO("%s", zero::strings::trim(buffer.get()).c_str());
            break;

        case LIBBPF_DEBUG:
            LOG_DEBUG("%s", zero::strings::trim(buffer.get()).c_str());
            break;
    }

    return length;
}

bool filter(const Trace &trace, const std::map<std::tuple<int, int>, Filter> &filters) {
    auto it = filters.find({trace.classID, trace.methodID});

    if (it == filters.end())
        return true;

    const auto &include = it->second.include;
    const auto &exclude = it->second.exclude;

    auto pred = [&](const MatchRule &rule) {
        if (rule.index >= trace.args.size())
            return false;

        return std::regex_match(trace.args[rule.index], rule.regex);
    };

    if (!include.empty() && std::none_of(include.begin(), include.end(), pred))
        return false;

    if (!exclude.empty() && std::any_of(exclude.begin(), exclude.end(), pred))
        return false;

    return true;
}

void onEvent(probe_event *event, void *ctx) {
    auto &[skeleton, instances, channel] = *(std::tuple<probe_bpf *, std::map<pid_t, Instance> &, std::shared_ptr<aio::IChannel<SmithMessage>>> *) ctx;

    auto it = instances.find(event->pid);

    if (it == instances.end())
        return;

    auto &quota = it->second.quotas[event->class_id][event->method_id];

    if (quota <= 0)
        return;

    if (!--quota) {
        LOG_INFO("disable probe: %d %d %d", it->first, event->class_id, event->method_id);

        it->second.config.stop[event->class_id][event->method_id] = true;

        if (bpf_map__update_elem(skeleton->maps.config_map, &it->first, sizeof(pid_t), &it->second.config, sizeof(probe_config), BPF_ANY) < 0) {
            LOG_ERROR("update process %d config failed", it->first);
            return;
        }
    }

    Trace trace = {
            event->class_id,
            event->method_id
    };

    for (int i = 0; i < event->count; i++)
        trace.args.emplace_back(event->args[i]);

    for (const auto &pc : event->stack_trace) {
        if (!pc)
            break;

        std::optional<std::string> cache = it->second.cache.get(pc);

        if (cache) {
            trace.stackTrace.emplace_back(*cache);
            continue;
        }

        auto symbolIterator = it->second.symbolTable.find(pc);

        if (symbolIterator == it->second.symbolTable.end())
            break;

        char frame[4096] = {};
        go::symbol::seek::Symbol symbol = symbolIterator.operator*().symbol();

        snprintf(
                frame,
                sizeof(frame),
                "%s %s:%d +0x%lx",
                symbol.name().c_str(),
                symbol.sourceFile(pc).c_str(),
                symbol.sourceLine(pc),
                pc - symbol.entry()
        );

        it->second.cache.set(pc, frame);
        trace.stackTrace.emplace_back(frame);
    }

    if (!filter(trace, it->second.filters))
        return;

#ifdef ENABLE_HTTP
    trace.request.method = event->request.method;
    trace.request.uri = event->request.uri;
    trace.request.host = event->request.host;
    trace.request.remote = event->request.remote;

#ifndef DISABLE_HTTP_HEADER
    for (const auto &header : event->request.headers) {
        if (!header[0][0])
            break;

        trace.request.headers.insert({header[0], header[1]});
    }
#endif
#endif

    channel->sendNoWait({it->first, it->second.version, it->second.processInfo, TRACE, trace});
}

std::optional<int> getAPIOffset(const elf::Reader &reader, uint64_t address) {
    std::optional<std::vector<std::byte>> buffer = reader.readVirtualMemory(address, INSTRUCTION_BUFFER_SIZE);

    if (!buffer)
        return std::nullopt;

    ZydisDecoder decoder;

    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        LOG_ERROR("disassembler init failed");
        return std::nullopt;
    }

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    int offset = 0;

    while (true) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer->data() + offset, INSTRUCTION_BUFFER_SIZE - offset, &instruction, operands))) {
            LOG_ERROR("disassemble failed");
            return std::nullopt;
        }

        if ((instruction.mnemonic == ZYDIS_MNEMONIC_SUB || instruction.mnemonic == ZYDIS_MNEMONIC_ADD) && operands[0].reg.value == ZYDIS_REGISTER_RSP)
            break;

        offset += instruction.length;

        if (offset > MAX_OFFSET) {
            LOG_ERROR("offset out of bounds");
            return std::nullopt;
        }
    }

    return offset;
}

std::shared_ptr<aio::IChannel<pid_t>> inputChannel(const std::shared_ptr<aio::Context> &context) {
    std::shared_ptr channel = std::make_shared<aio::Channel<pid_t, 10>>(context);
    std::shared_ptr buffer = std::make_shared<aio::ev::Buffer>(bufferevent_socket_new(context->base(), STDIN_FILENO, 0));

    zero::async::promise::loop<void>([=](const auto &loop) {
        buffer->readLine(EVBUFFER_EOL_ANY)->then([=](const std::string &line) {
            std::optional<pid_t> pid = zero::strings::toNumber<pid_t>(line);

            if (!pid) {
                LOG_WARNING("invalid pid: %s", line.c_str());
                return zero::async::promise::resolve<void>();
            }

            return channel->send(*pid);
        })->then([=]() {
            P_CONTINUE(loop);
        }, [=](const zero::async::promise::Reason &reason) {
            LOG_ERROR("read stdin failed: %s", reason.message.c_str());
            channel->close();
            P_BREAK(loop);
        });
    });

    return channel;
}

std::optional<Instance> attach(probe_bpf *skeleton, pid_t pid) {
    std::optional<zero::os::procfs::Process> process = zero::os::procfs::openProcess(pid);

    if (!process) {
        LOG_ERROR("open process %d failed", pid);
        return std::nullopt;
    }

    std::optional<zero::os::procfs::Stat> stat = process->stat();
    std::optional<zero::os::procfs::Status> status = process->status();
    std::optional<std::filesystem::path> exe = process->exe();
    std::optional<std::vector<std::string>> cmdline = process->cmdline();

    if (!stat || !status || !exe || !cmdline) {
        LOG_ERROR("get process %d info failed", pid);
        return std::nullopt;
    }

    std::filesystem::path path = std::filesystem::path("/proc") / std::to_string(pid) / "root" / exe->relative_path();

    std::optional<elf::Reader> reader = elf::openFile(path);

    if (!reader) {
        LOG_ERROR("load golang binary failed: %s", path.string().c_str());
        return std::nullopt;
    }

    bool abi = false;
    bool fp = false;
    bool http = false;

    go::symbol::Reader symbolReader(*reader, path);
    std::optional<go::Version> version = symbolReader.version();

    if (version) {
        LOG_INFO("golang version: %d.%d", version->major, version->minor);

        abi = *version >= REGISTER_BASED_VERSION;
        fp = *version >= FRAME_POINTER_VERSION;
        http = *version >= TRACK_HTTP_VERSION;
    }

    LOG_INFO("process %d: abi(%d) fp(%d) http(%d)", pid, abi, fp, http);

    std::optional<zero::os::procfs::MemoryMapping> memoryMapping = process->getImageBase(exe->string());

    if (!memoryMapping) {
        LOG_INFO("get image base failed");
        return std::nullopt;
    }

    LOG_INFO("image base: %p", memoryMapping->start);

    std::optional<go::symbol::seek::SymbolTable> seekSymbolTable = symbolReader.symbols(memoryMapping->start);
    std::optional<go::symbol::SymbolTable> symbolTable = symbolReader.symbols(
            go::symbol::FileMapping,
            memoryMapping->start
    );

    if (!symbolTable || !seekSymbolTable) {
        LOG_INFO("get symbol table failed");
        return std::nullopt;
    }

    probe_config config = {
            abi,
            fp
    };

    if (bpf_map__update_elem(skeleton->maps.config_map, &pid, sizeof(pid_t), &config, sizeof(probe_config), BPF_ANY) < 0) {
        LOG_ERROR("update process %d config failed", pid);
        return std::nullopt;
    }

    std::list<std::unique_ptr<bpf_link, decltype(bpf_link__destroy) *>> links;

    auto attachAPI = [&](const auto &api) {
        auto it = std::find_if(symbolTable->begin(), symbolTable->end(), [&](const auto &entry) {
            std::string name = entry.symbol().name();

            if (api.ignoreCase)
                return strcasecmp(name.c_str(), api.name) == 0;

            return name == api.name;
        });

        if (it == symbolTable->end()) {
            LOG_WARNING("function %s not found", api.name);
            return;
        }

        auto program = std::find_if(
                skeleton->skeleton->progs,
                skeleton->skeleton->progs + skeleton->skeleton->prog_cnt,
                [&](const auto &program) {
                    return strcmp(api.probe, program.name) == 0;
                }
        );

        if (program == skeleton->skeleton->progs + skeleton->skeleton->prog_cnt) {
            LOG_WARNING("probe %s not found", api.probe);
            return;
        }

        uint64_t entry = it.operator*().symbol().entry();

        std::optional<int> offset = getAPIOffset(*reader, entry);

        if (!offset) {
            LOG_ERROR("get api offset failed");
            return;
        }

        LOG_INFO("attach function %s: %p+%d", api.name, entry, offset);

        bpf_link *link = bpf_program__attach_uprobe(
                *program->prog,
                false,
                pid,
                zero::strings::format("/proc/%d/exe", pid).c_str(),
                entry + *offset - memoryMapping->start
        );

        if (!link) {
            LOG_ERROR("failed to attach: %s", strerror(errno));
            return;
        }

        links.push_back(std::unique_ptr<bpf_link, decltype(bpf_link__destroy) *>(link, bpf_link__destroy));
    };

    std::for_each(GOLANG_API.begin(), GOLANG_API.end(), attachAPI);

    if (http)
        std::for_each(GOLANG_HTTP_API.begin(), GOLANG_HTTP_API.end(), attachAPI);

    return Instance{
            version ? zero::strings::format("%d.%d", version->major, version->minor) : "",
            std::move(*seekSymbolTable),
            std::move(links),
            zero::cache::LRUCache<uintptr_t, std::string>(FRAME_CACHE_SIZE),
            stat->startTime,
            std::make_shared<ProcessInfo>(ProcessInfo{
                    stat->session,
                    stat->ppid,
                    stat->tpgid,
                    status->nspid.value_or(0),
                    exe->string(),
                    zero::strings::join(*cmdline, " "),
                    status->uid[0],
                    status->uid[1],
                    status->uid[2],
                    status->uid[3],
                    status->gid[0],
                    status->gid[1],
                    status->gid[2],
                    status->gid[3]
            }),
            config
    };
}

int main() {
    INIT_FILE_LOG(zero::INFO_LEVEL, "go-probe-ebpf");

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(onLog);

    probe_bpf *skeleton = probe_bpf::open_and_load();

    if (!skeleton) {
        LOG_ERROR("failed to open BPF skeleton");
        return -1;
    }

    signal(SIGPIPE, SIG_IGN);
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    std::shared_ptr<aio::Context> context = aio::newContext();
    std::map<pid_t, Instance> instances;

    zero::async::promise::loop<void>([skeleton, &instances, channel = inputChannel(context)](const auto &loop) {
        channel->receive()->then([skeleton, loop, &instances](pid_t pid) {
            if (instances.find(pid) != instances.end()) {
                LOG_WARNING("ignore process %d", pid);
                P_CONTINUE(loop);
                return;
            }

            std::optional<Instance> instance = attach(skeleton, pid);

            if (!instance) {
                P_CONTINUE(loop);
                std::cout << pid << ":failed" << std::endl;
                return;
            }

            std::cout << pid << ":succeeded" << std::endl;

            std::fill_n(instance->quotas[0], sizeof(instance->quotas) / sizeof(**instance->quotas), DEFAULT_QUOTAS);
            instances.insert({pid, std::move(*instance)});

            P_CONTINUE(loop);
        }, [=](const zero::async::promise::Reason &reason) {
            LOG_ERROR("receive failed: %s", reason.message.c_str());
            P_BREAK(loop);
        });
    });

    std::make_shared<aio::ev::Timer>(context)->setInterval(1min, [&]() {
        auto it = instances.begin();

        while (it != instances.end()) {
            std::optional<zero::os::procfs::Process> process = zero::os::procfs::openProcess(it->first);

            if (!process) {
                LOG_INFO("clean dead process %d", it->first);
                bpf_map__delete_elem(skeleton->maps.config_map, &it->first, sizeof(pid_t), BPF_ANY);
                it = instances.erase(it);
                continue;
            }

            std::optional<zero::os::procfs::Stat> stat = process->stat();

            if (!stat || stat->startTime != it->second.startTime) {
                LOG_INFO("clean reused process %d", it->first);
                bpf_map__delete_elem(skeleton->maps.config_map, &it->first, sizeof(pid_t), BPF_ANY);
                it = instances.erase(it);
                continue;
            }

            for (int i = 0; i < CLASS_MAX; i++) {
                for (int j = 0; j < METHOD_MAX; j++) {
                    auto limitIterator = it->second.limits.find({i, j});

                    if (limitIterator == it->second.limits.end()) {
                        it->second.quotas[i][j] = DEFAULT_QUOTAS;
                        continue;
                    }

                    it->second.quotas[i][j] = limitIterator->second;
                }
            }

            std::fill_n(it->second.config.stop[0], sizeof(it->second.config.stop) / sizeof(**it->second.config.stop), false);
            bpf_map__update_elem(skeleton->maps.config_map, &it->first, sizeof(pid_t), &it->second.config, sizeof(probe_config), BPF_ANY);

            it++;
        }

        return true;
    });

    std::array<std::shared_ptr<aio::IChannel<SmithMessage>>, 2> channels = startClient(context);

    zero::async::promise::loop<void>([channels, &instances](const auto &loop) {
        channels[0]->receive()->then([loop, &instances](const SmithMessage &message) {
            auto it = instances.find(message.pid);

            if (it == instances.end()) {
                LOG_INFO("process not found: %d", message.pid);
                return;
            }

            switch (message.operate) {
                case FILTER: {
                    try {
                        auto config = message.data.get<FilterConfig>();

                        it->second.filters.clear();

                        std::transform(
                                config.filters.begin(),
                                config.filters.end(),
                                std::inserter(it->second.filters, it->second.filters.end()),
                                [](const auto &filter) {
                                    return std::pair{std::tuple{filter.classID, filter.methodID}, filter};
                                }
                        );
                    } catch (const nlohmann::json::exception &e) {
                        LOG_ERROR("exception: %s", e.what());
                    }

                    break;
                }

                case LIMIT: {
                    try {
                        auto config = message.data.get<LimitConfig>();

                        it->second.limits.clear();

                        std::transform(
                                config.limits.begin(),
                                config.limits.end(),
                                std::inserter(it->second.limits, it->second.limits.end()),
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

    std::tuple<probe_bpf *, std::map<pid_t, Instance> &, std::shared_ptr<aio::IChannel<SmithMessage>>> ctx = {
            skeleton,
            instances,
            channels[1]
    };

#ifdef USE_RING_BUFFER
    ring_buffer *rb = ring_buffer__new(
            bpf_map__fd(skeleton->maps.events),
            [](void *ctx, void *data, size_t size) {
                onEvent((probe_event *) data, ctx);
                return 0;
            },
            &ctx,
            nullptr
    );

    if (!rb) {
        LOG_ERROR("failed to create ring buffer: %s", strerror(errno));
        probe_bpf::destroy(skeleton);
        return -1;
    }

    std::make_shared<aio::ev::Event>(context, bpf_map__fd(skeleton->maps.events))->onPersist(
            EV_READ,
            [=](short what) {
                ring_buffer__consume(rb);
                return true;
            },
            10min
    );
#else
    perf_buffer *pb = perf_buffer__new(
            bpf_map__fd(skeleton->maps.events),
            64,
            [](void *ctx, int cpu, void *data, __u32 size) {
                onEvent((probe_event *) data, ctx);
            },
            nullptr,
            &ctx,
            nullptr
    );

    if (!pb) {
        LOG_ERROR("failed to create perf buffer: %s", strerror(errno));
        probe_bpf::destroy(skeleton);
        return -1;
    }

    for (size_t i = 0; i < perf_buffer__buffer_cnt(pb); i++) {
        std::make_shared<aio::ev::Event>(context, perf_buffer__buffer_fd(pb, i))->onPersist(
                EV_READ,
                [=](short what) {
                    perf_buffer__consume_buffer(pb, i);
                    return true;
                },
                10min
        );
    }
#endif

    context->dispatch();

#ifdef USE_RING_BUFFER
    ring_buffer__free(rb);
#else
    perf_buffer__free(pb);
#endif

    probe_bpf::destroy(skeleton);

    return 0;
}
