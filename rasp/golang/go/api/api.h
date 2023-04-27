#ifndef GO_PROBE_API_H
#define GO_PROBE_API_H

#include <re.h>
#include <sys/user.h>
#include <z_syscall.h>
#include <go/type/errors.h>
#include <go/type/stringify.h>
#include <client/smith_probe.h>

constexpr auto STACK_SIZE = PAGE_SIZE * 10;

constexpr auto FLOAT_REGISTER = 15;
constexpr auto INTEGER_REGISTER = 9;

constexpr auto REGISTER_BASED_VERSION = go::Version{1, 17};
constexpr auto RASP_ERROR = "API blocked by RASP";

constexpr auto RASP_ERROR_STRING = go::errors::ErrorString{
        RASP_ERROR,
        19
};

struct APIMetadata {
    int classID;
    int methodID;
    void (*entry)();
    void **origin;
};

struct API {
    const char *name;
    APIMetadata metadata;
    bool ignoreCase;
};

struct Layout {
    int ni;
    int nfp;
    uintptr_t stack;
};

template<size_t Index, typename... Ts>
Layout getTypeLayout(Layout layout) {
    size_t index = 0;

    ([&]() {
        if (index++ >= Index)
            return;

        int ni = go::Metadata<Ts>::NI;
        int nfp = go::Metadata<Ts>::NFP;

        size_t align = go::Metadata<Ts>::align;
        size_t size = go::Metadata<Ts>::size;

        bool hasNonTrivialArray = go::Metadata<Ts>::hasNonTrivialArray;

        if (gTarget->version < REGISTER_BASED_VERSION || hasNonTrivialArray || ni + layout.ni > INTEGER_REGISTER ||
            nfp + layout.nfp > FLOAT_REGISTER) {
            layout.stack = (layout.stack + align - 1) / align * align + size;
        } else {
            layout.ni += ni;
            layout.nfp += nfp;
        }
    }(), ...);

    return layout;
}

template<typename... Ts>
class APITracer {
public:
    APITracer(uintptr_t stack, unsigned long *I, double _Complex *FP) : mStack(stack), mI(I), mFP(FP) {

    }

public:
    void read(Trace &trace) {
        Layout layout = {
                0,
                0,
                mStack + sizeof(uintptr_t)
        };

        ([&]() {
            if (trace.count >= ARG_COUNT)
                return;

            Ts t = {};

            void *p = &t;

            int ni = go::Metadata<Ts>::NI;
            int nfp = go::Metadata<Ts>::NFP;

            size_t align = go::Metadata<Ts>::align;
            size_t size = go::Metadata<Ts>::size;

            bool hasNonTrivialArray = go::Metadata<Ts>::hasNonTrivialArray;

            if (gTarget->version < REGISTER_BASED_VERSION || hasNonTrivialArray || ni + layout.ni > INTEGER_REGISTER ||
                nfp + layout.nfp > FLOAT_REGISTER) {
                layout.stack = (layout.stack + align - 1) / align * align;
                memcpy(p, (void *) layout.stack, size);
                layout.stack += size;
            } else {
                for (const auto &f: go::Metadata<Ts>::getFields()) {
                    if (f.floating) {
                        double _Complex *reg = mFP + layout.nfp++;
                        memcpy((std::byte *) p + f.offset, reg, f.size);
                    } else {
                        unsigned long *reg = mI + layout.ni++;
                        memcpy((std::byte *) p + f.offset, reg, f.size);
                    }
                }
            }

            go::stringify(t, trace.args[trace.count++], ARG_LENGTH);
        }(), ...);
    }

    uintptr_t resultAddress() {
        Layout layout = getTypeLayout<sizeof...(Ts), Ts...>(
                {
                        0,
                        0,
                        mStack + sizeof(uintptr_t)
                }
        );

        return (layout.stack + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
    }

    void traceback(Trace &trace) {
        auto sp = (std::byte *) mStack;

        for (auto &frame: trace.stackTrace) {
            uintptr_t pc = *(uintptr_t *) sp;

            auto it = gTarget->symbolTable->find(pc);

            if (it == gTarget->symbolTable->end())
                break;

            frame.first = pc;
            frame.second = it.operator*().symbol();

            if (frame.second->isStackTop())
                break;

            int frameSize = frame.second->frameSize(pc);

            if (frameSize == 0)
                break;

            sp = sp + frameSize + sizeof(uintptr_t);
        }
    }

private:
    uintptr_t mStack;
    unsigned long *mI;
    double _Complex *mFP;
};

template<typename... Ts>
class APITamper {
public:
    explicit APITamper(uintptr_t stack, unsigned long *I, double _Complex *FP) : mStack(stack), mI(I), mFP(FP) {

    }

public:
    template<size_t ...Index>
    void reset(std::index_sequence<Index...>) {
        ([&]() {
            std::tuple_element_t<Index, std::tuple<Ts...>> v = {};
            write<Index>(&v);
        }(), ...);
    }

    template<size_t Index, typename T = std::tuple_element_t<Index, std::tuple<Ts...>>>
    void write(const T *ptr) {
        size_t index = 0;

        Layout layout = getTypeLayout<Index, Ts...>(
                {
                        0,
                        0,
                        mStack
                }
        );

        ([&]() {
            if (index++ != Index)
                return;

            int integerRegister = go::Metadata<Ts>::NI;
            int floatRegister = go::Metadata<Ts>::NFP;

            size_t align = go::Metadata<Ts>::align;
            size_t size = go::Metadata<Ts>::size;

            bool hasNonTrivialArray = go::Metadata<Ts>::hasNonTrivialArray;

            if (gTarget->version < REGISTER_BASED_VERSION || hasNonTrivialArray ||
                integerRegister + layout.ni > INTEGER_REGISTER || floatRegister + layout.nfp > FLOAT_REGISTER) {
                memcpy((void *) ((layout.stack + align - 1) / align * align), ptr, size);
                return;
            }

            for (const auto &f: go::Metadata<Ts>::getFields()) {
                if (f.floating) {
                    double _Complex *reg = mFP + layout.nfp++;
                    memcpy(reg, (const std::byte *) ptr + f.offset, f.size);
                } else {
                    unsigned long *reg = mI + layout.ni++;
                    memcpy(reg, (const std::byte *) ptr + f.offset, f.size);
                }
            }
        }(), ...);
    }

private:
    uintptr_t mStack;
    unsigned long *mI;
    double _Complex *mFP;
};

template<int ClassID, int MethodID, int ErrorIndex, typename Tamper, typename Tracer, typename ResetIndex = std::index_sequence<>>
struct APIEntry {
    static void __attribute__ ((naked)) entry() {
        asm volatile(
                "mov $1, %%r12;"
                "mov %%rsp, %%r13;"
                "add $8, %%r13;"
                "and $15, %%r13;"
                "sub $16, %%rsp;"
                "movdqu %%xmm14, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm13, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm12, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm11, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm10, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm9, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm8, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm7, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm6, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm5, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm4, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm3, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm2, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm1, (%%rsp);"
                "sub $16, %%rsp;"
                "movdqu %%xmm0, (%%rsp);"
                "push %%r11;"
                "push %%r10;"
                "push %%r9;"
                "push %%r8;"
                "push %%rsi;"
                "push %%rdi;"
                "push %%rcx;"
                "push %%rbx;"
                "push %%rax;"
                "sub $16, %%rsp;"
                "movdqu %%xmm15, (%%rsp);"
                "sub %%r13, %%rsp;"
                "mov %0, %%rdi;"
                "call z_malloc;"
                "cmp $0, %%rax;"
                "je end_%=;"
                "mov %%rsp, %%rdi;"
                "mov %%rax, %%rsp;"
                "add %0, %%rsp;"
                "push %%rax;"
                "push %%rdi;"
                "add $328, %%rdi;"
                "add %%r13, %%rdi;"
                "mov %%r14, %%rsi;"
                "call %P1;"
                "mov %%rax, %%r12;"
                "pop %%rsi;"
                "pop %%rdi;"
                "mov %%rsi, %%rsp;"
                "call z_free;"
                "end_%=:"
                "add %%r13, %%rsp;"
                "movdqu (%%rsp), %%xmm15;"
                "add $16, %%rsp;"
                "pop %%rax;"
                "pop %%rbx;"
                "pop %%rcx;"
                "pop %%rdi;"
                "pop %%rsi;"
                "pop %%r8;"
                "pop %%r9;"
                "pop %%r10;"
                "pop %%r11;"
                "movdqu (%%rsp), %%xmm0;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm1;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm2;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm3;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm4;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm5;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm6;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm7;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm8;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm9;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm10;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm11;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm12;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm13;"
                "add $16, %%rsp;"
                "movdqu (%%rsp), %%xmm14;"
                "add $16, %%rsp;"
                "cmp $0, %%r12;"
                "je block_%=;"
                "jmp *%2;"
                "block_%=:"
                "ret;"
                ::
                "i"(STACK_SIZE),
                "i"(handler),
                "m"(origin)
                );
    }

    static bool handler(uintptr_t sp, uintptr_t g) {
        if constexpr (ErrorIndex < 0) {
            if (!surplus())
                return true;
        }

        size_t FPSize = FLOAT_REGISTER * sizeof(double _Complex);
        size_t ISize = INTEGER_REGISTER * sizeof(unsigned long);

        auto I = (unsigned long *) (sp - FPSize - ISize);
        auto FP = (double _Complex *) (sp - FPSize);

        if (gTarget->version < REGISTER_BASED_VERSION)
            g = I[2];

        Tracer tracer(sp, I, FP);

        Trace trace = {
                ClassID,
                MethodID
        };

        tracer.read(trace);
        tracer.traceback(trace);

        if constexpr (ErrorIndex >= 0) {
            if (*go::errors::ErrorString::errorTab() && !pass(trace)) {
                go::Interface interface = {
                        *go::errors::ErrorString::errorTab(),
                        (void *) &RASP_ERROR_STRING
                };

                Tamper tamper(tracer.resultAddress(), I, FP);

                tamper.template reset(ResetIndex{});
                tamper.template write<ErrorIndex>(&interface);

                post(trace);

                return false;
            }

            if (!surplus())
                return true;
        }

        post(trace);

        return true;
    }

    static bool surplus() {
        std::atomic<int> &quota = gProbe->quotas[ClassID][MethodID];
        int n = quota;

        do {
            if (n <= 0)
                return false;
        } while (!quota.compare_exchange_weak(n, n - 1));

        return true;
    }

    static bool pass(Trace &trace) {
        z_rwlock_t *lock = gProbe->locks[ClassID] + MethodID;
        z_rwlock_read_lock(lock);

        auto [size, policies] = gProbe->policies[ClassID][MethodID];

        if (std::any_of(policies, policies + size, [&](const Policy &policy) {
            if (policy.ruleCount > 0 && std::none_of(
                    policy.rules,
                    policy.rules + policy.ruleCount,
                    [&](const auto &rule) {
                        if (rule.first >= trace.count)
                            return false;

                        int length = 0;

                        return re_match(rule.second, trace.args[rule.first], &length) != -1;
                    }))
                return false;

            if (policy.KeywordCount == 0) {
                trace.blocked = true;
                strncpy(trace.policyID, policy.policyID, sizeof(Trace::policyID) - 1);
                return true;
            }

            auto pred = [&](const auto &keyword) {
                return std::any_of(trace.stackTrace, trace.stackTrace + FRAME_COUNT, [=](const auto &frame) {
                    if (!frame.first)
                        return false;

                    int length = 0;

                    if (re_match(keyword, frame.second->name(), &length) != -1)
                        return true;

                    return re_match(keyword, frame.second->sourceFile(frame.first), &length) != -1;
                });
            };

            const auto &[logicalOperator, keywords] = policy.stackFrame;

            if (logicalOperator == OR && std::any_of(keywords, keywords + policy.KeywordCount, pred)) {
                trace.blocked = true;
                strncpy(trace.policyID, policy.policyID, sizeof(Trace::policyID) - 1);
                return true;
            }

            if (logicalOperator == AND && std::all_of(keywords, keywords + policy.KeywordCount, pred)) {
                trace.blocked = true;
                strncpy(trace.policyID, policy.policyID, sizeof(Trace::policyID) - 1);
                return true;
            }

            return false;
        })) {
            z_rwlock_read_unlock(lock);
            return false;
        }

        z_rwlock_read_unlock(lock);
        return true;
    }

    static void post(const Trace &trace) {
        std::optional<size_t> index = gProbe->buffer.reserve();

        if (!index)
            return;

        gProbe->buffer[*index] = trace;
        gProbe->buffer.commit(*index);

        if (gProbe->buffer.size() < TRACE_BUFFER_SIZE / 2)
            return;

        bool expected = true;

        if (!gProbe->waiting.compare_exchange_strong(expected, false))
            return;

        uint64_t value = 1;
        z_write(gProbe->efd, &value, sizeof(uint64_t));
    }

    static void *origin;
    static constexpr APIMetadata metadata = {ClassID, MethodID, entry, &origin};
};

template<int ClassID, int MethodID, int ErrorIndex, typename Tamper, typename Tracer, typename ResetIndex>
void *APIEntry<ClassID, MethodID, ErrorIndex, Tamper, Tracer, ResetIndex>::origin = nullptr;

constexpr auto GOLANG_API = {
        API{
                "os/exec.Command",
                APIEntry<0, 0, -1, APITamper<go::Uintptr>, APITracer<go::String, go::Slice<go::String>>>::metadata,
                false
        },
        {
                "os/exec.(*Cmd).Start",
                APIEntry<0, 1, 0, APITamper<go::Interface>, APITracer<go::os::exec::Cmd *>>::metadata,
                false
        },
        {
                "os.OpenFile",
                APIEntry<1, 0, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::Int, go::Uint32>>::metadata,
                false
        },
        {
                "os.Remove",
                APIEntry<1, 1, -1, APITamper<go::Interface>, APITracer<go::String>>::metadata,
                false
        },
        {
                "os.RemoveAll",
                APIEntry<1, 2, -1, APITamper<go::Interface>, APITracer<go::String>>::metadata,
                false
        },
        {
                "os.Rename",
                APIEntry<1, 3, -1, APITamper<go::Interface>, APITracer<go::String, go::String>>::metadata,
                true
        },
        {
                "io/ioutil.ReadDir",
                APIEntry<1, 4, -1, APITamper<go::Slice<go::Interface>, go::Interface>, APITracer<go::String>>::metadata,
                false
        },
        {
                "net.Dial",
                APIEntry<2, 0, -1, APITamper<go::Interface, go::Interface>, APITracer<go::String, go::String>>::metadata,
                false
        },
        {
                "net.DialTCP",
                APIEntry<2, 1, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::net::TCPAddress *, go::net::TCPAddress *>>::metadata,
                false
        },
        {
                "net.DialIP",
                APIEntry<2, 2, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::net::IPAddress *, go::net::IPAddress *>>::metadata,
                false
        },
        {
                "net.DialUDP",
                APIEntry<2, 3, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::net::UDPAddress *, go::net::UDPAddress *>>::metadata,
                false
        },
        {
                "net.DialUnix",
                APIEntry<2, 4, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::net::UnixAddress *, go::net::UnixAddress *>>::metadata,
                false
        },
        {
                "net.(*Dialer).DialContext",
                APIEntry<2, 5, -1, APITamper<go::Interface, go::Interface>, APITracer<go::Uintptr, go::Interface, go::String, go::String>>::metadata,
                false
        },
        {
                "net.ResolveTCPAddr",
                APIEntry<3, 0, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::String>>::metadata,
                false
        },
        {
                "net.ResolveIPAddr",
                APIEntry<3, 1, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::String>>::metadata,
                false
        },
        {
                "net.ResolveUDPAddr",
                APIEntry<3, 2, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::String>>::metadata,
                false
        },
        {
                "net.ResolveUnixAddr",
                APIEntry<3, 3, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::String>>::metadata,
                false
        },
        {
                "net.LookupAddr",
                APIEntry<4, 0, -1, APITamper<go::Slice<go::String>, go::Interface>, APITracer<go::String>>::metadata,
                false
        },
        {
                "net.LookupCNAME",
                APIEntry<4, 1, -1, APITamper<go::String, go::Interface>, APITracer<go::String>>::metadata,
                false
        },
        {
                "net.LookupHost",
                APIEntry<4, 2, -1, APITamper<go::Slice<go::String>, go::Interface>, APITracer<go::String>>::metadata,
                false
        },
        {
                "net.LookupPort",
                APIEntry<4, 3, -1, APITamper<go::Int, go::Interface>, APITracer<go::String, go::String>>::metadata,
                false
        },
        {
                "net.LookupTXT",
                APIEntry<4, 4, -1, APITamper<go::Slice<go::String>, go::Interface>, APITracer<go::String>>::metadata,
                false
        },
        {
                "net.LookupIP",
                APIEntry<4, 5, -1, APITamper<go::Slice<go::Slice<go::Uint8>>, go::Interface>, APITracer<go::String>>::metadata,
                false
        },
        {
                "net.LookupMX",
                APIEntry<4, 6, -1, APITamper<go::Slice<go::Uintptr>, go::Interface>, APITracer<go::String>>::metadata,
                false
        },
        {
                "net.LookupNS",
                APIEntry<4, 7, -1, APITamper<go::Slice<go::Uintptr>, go::Interface>, APITracer<go::String>>::metadata,
                false
        },
        {
                "net.(*Resolver).LookupAddr",
                APIEntry<4, 8, -1, APITamper<go::Slice<go::String>, go::Interface>, APITracer<go::Uintptr, go::Interface, go::String>>::metadata,
                true
        },
        {
                "net.(*Resolver).LookupCNAME",
                APIEntry<4, 9, -1, APITamper<go::String, go::Interface>, APITracer<go::Uintptr, go::Interface, go::String>>::metadata,
                true
        },
        {
                "net.(*Resolver).LookupHost",
                APIEntry<4, 10, -1, APITamper<go::Slice<go::String>, go::Interface>, APITracer<go::Uintptr, go::Interface, go::String>>::metadata,
                false
        },
        {
                "net.(*Resolver).LookupPort",
                APIEntry<4, 11, -1, APITamper<go::Int, go::Interface>, APITracer<go::Uintptr, go::Interface, go::String, go::String>>::metadata,
                false
        },
        {
                "net.(*Resolver).LookupTXT",
                APIEntry<4, 12, -1, APITamper<go::Slice<go::String>, go::Interface>, APITracer<go::Uintptr, go::Interface, go::String>>::metadata,
                true
        },
        {
                "net.(*Resolver).LookupIPAddr",
                APIEntry<4, 13, -1, APITamper<go::Slice<go::net::IPAddress>, go::Interface>, APITracer<go::Uintptr, go::Interface, go::String>>::metadata,
                false
        },
        {
                "net.(*Resolver).LookupMX",
                APIEntry<4, 14, -1, APITamper<go::Slice<go::Uintptr>, go::Interface>, APITracer<go::Uintptr, go::Interface, go::String>>::metadata,
                true
        },
        {
                "net.(*Resolver).LookupNS",
                APIEntry<4, 15, -1, APITamper<go::Slice<go::Uintptr>, go::Interface>, APITracer<go::Uintptr, go::Interface, go::String>>::metadata,
                true
        },
        {
                "net.Listen",
                APIEntry<5, 0, -1, APITamper<go::Interface, go::Interface>, APITracer<go::String, go::String>>::metadata,
                false
        },
        {
                "net.ListenTCP",
                APIEntry<5, 1, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::net::TCPAddress *>>::metadata,
                false
        },
        {
                "net.ListenIP",
                APIEntry<5, 2, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::net::IPAddress *>>::metadata,
                false
        },
        {
                "net.ListenUDP",
                APIEntry<5, 3, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::net::UDPAddress *>>::metadata,
                false
        },
        {
                "net.ListenUnix",
                APIEntry<5, 4, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::net::UnixAddress *>>::metadata,
                false
        },
        {
                "net/http.NewRequest",
                APIEntry<6, 0, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String, go::String>>::metadata,
                false
        },
        {
                "net/http.NewRequestWithContext",
                APIEntry<6, 1, 1, APITamper<go::Uintptr, go::Interface>, APITracer<go::Interface, go::String, go::String, go::Interface>, std::index_sequence<0>>::metadata,
                false
        },
        {
                "plugin.Open",
                APIEntry<7, 0, -1, APITamper<go::Uintptr, go::Interface>, APITracer<go::String>>::metadata,
                false
        }
};

#endif //GO_PROBE_API_H
