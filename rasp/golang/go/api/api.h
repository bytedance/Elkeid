#ifndef GO_PROBE_API_H
#define GO_PROBE_API_H

#include <sys/user.h>
#include <client/smith_probe.h>
#include <tiny-regex-c/re.h>
#include <z_sync.h>
#include <go/symbol/line_table.h>
#include <go/symbol/build_info.h>
#include <go/type/net.h>
#include <go/type/os.h>

constexpr auto STACK_SIZE = PAGE_SIZE * 10;

constexpr auto BLOCK_RULE_COUNT = 20;
constexpr auto BLOCK_RULE_LENGTH = 256;

constexpr auto FLOAT_REGISTER = 15;
constexpr auto INTEGER_REGISTER = 9;

constexpr auto DEFAULT_QUOTAS = 12000;

struct BlockPolicy {
    int count;
    std::pair<int, char[BLOCK_RULE_LENGTH]> rules[BLOCK_RULE_COUNT];
};

struct APIConfig {
    int quota{};
    z_rwlock_t lock{};
    BlockPolicy policies;
};

struct APIMetadata {
    int classID;
    int methodID;
    void (*entry)();
    void **origin;
    APIConfig *config;
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

int toString(const go::Int &value, char *buffer, size_t size);
int toString(const go::Uint32 &value, char *buffer, size_t size);
int toString(const go::Uintptr &value, char *buffer, size_t size);
int toString(const go::interface &value, char *buffer, size_t size);
int toString(const go::string &value, char *buffer, size_t size);

int toString(const go::tcp_address &value, char *buffer, size_t size);
int toString(const go::ip_address &value, char *buffer, size_t size);
int toString(const go::unix_address &value, char *buffer, size_t size);
int toString(const go::exec_cmd &value, char *buffer, size_t size);

template<typename T>
int toString(const go::slice<T> &value, char *buffer, size_t size) {
    int length = 0;

    for (int i = 0; i < value.count * 2 - 1 && length + 1 < size; i++) {
        if (i % 2) {
            strcpy(buffer + length++, " ");
            continue;
        }

        int n = toString(value[i/2], buffer + length, size - length);

        if (n < 0)
            break;

        length += n;
    }

    return length;
}

template<typename K, typename V>
int toString(const go::map<K, V> &value, char *buffer, size_t size);

template<typename T, std::enable_if_t<std::is_pointer_v<T>> * = nullptr>
int toString(const T &value, char *buffer, size_t size) {
    if (!value)
        return 0;

    return toString(*value, buffer, size);
}

template<int Index, typename... Ts>
Layout getTypeLayout(Layout layout) {
    int index = 0;

    ([&]() {
        if (index++ >= Index)
            return;

        int ni = go::Metadata<Ts>::NI;
        int nfp = go::Metadata<Ts>::NFP;

        size_t align = go::Metadata<Ts>::align;
        size_t size = go::Metadata<Ts>::size;

        bool hasNonTrivialArray = go::Metadata<Ts>::hasNonTrivialArray;

        if (!gBuildInfo->mRegisterBased || hasNonTrivialArray || ni + layout.ni > INTEGER_REGISTER || nfp + layout.nfp > FLOAT_REGISTER) {
            uintptr_t piece = layout.stack % align;
            layout.stack += (piece ? align - piece : 0) + size;
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
    explicit APITracer(void *I, void *FP, void *stack) {
        mI = I;
        mFP = FP;
        mStack = stack;
    }

public:
    void read(Trace &trace) {
        Layout layout = {
                0,
                0,
                (uintptr_t)mStack + sizeof(uintptr_t)
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

            if (!gBuildInfo->mRegisterBased || hasNonTrivialArray || ni + layout.ni > INTEGER_REGISTER || nfp + layout.nfp > FLOAT_REGISTER) {
                uintptr_t piece = layout.stack % align;
                layout.stack += (piece ? align - piece : 0);

                memcpy(p, (void *)layout.stack, size);
                layout.stack += size;
            } else {
                for (const auto &f : go::Metadata<Ts>::getFields()) {
                    if (f.floating) {
                        double _Complex *reg = (double _Complex *)mFP + layout.nfp++;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                        memcpy((char *)p + f.offset, reg, f.size);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                        memcpy((char *)p + f.offset, (const char *)reg + sizeof(double _Complex) - f.size, f.size);
#endif
                    } else {
                        unsigned long *reg = (unsigned long *)mI + layout.ni++;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                        memcpy((char *)p + f.offset, reg, f.size);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                        memcpy((char *)p + f.offset, (const char *)reg + sizeof(unsigned long) - f.size, f.size);
#endif
                    }
                }
            }

            toString(t, trace.args[trace.count++], ARG_LENGTH);
        }(), ...);
    }

    void *getResultStack() {
        Layout layout = getTypeLayout<sizeof...(Ts), Ts...>(
                {
                        0,
                        0,
                        (uintptr_t) mStack + sizeof(uintptr_t)
                }
        );

        return (void *) ((layout.stack + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
    }

    void traceback(Trace &trace) {
        void *sp = mStack;

        for (auto &st : trace.stackTrace) {
            uintptr_t pc = *(uintptr_t *)sp;

            Func func = {};

            if (!gLineTable->findFunc(pc, func))
                break;

            st = {pc, func};

            if (func.isStackTop())
                break;

            int frameSize = func.getFrameSize(pc);

            if (frameSize == 0)
                break;

            sp = (char *)sp + frameSize + sizeof(uintptr_t);
        }
    }

private:
    void *mI;
    void *mFP;
    void *mStack;
};

template<typename... Ts>
class APITamper {
public:
    explicit APITamper(void *I, void *FP, void *stack) {
        mI = I;
        mFP = FP;
        mStack = stack;
    }

public:
    template<int Index>
    void write(void *ptr) {
        int index = 0;

        Layout layout = getTypeLayout<Index, Ts...>(
                {
                        0,
                        0,
                        (uintptr_t) mStack
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

            if (!gBuildInfo->mRegisterBased || hasNonTrivialArray || integerRegister + layout.ni > INTEGER_REGISTER || floatRegister + layout.nfp > FLOAT_REGISTER) {
                uintptr_t piece = layout.stack % align;
                uintptr_t stack = layout.stack + (piece ? align - piece : 0);

                memcpy((void *)stack, ptr, size);

                return;
            }

            for (const auto &f : go::Metadata<Ts>::getFields()) {
                if (f.floating) {
                    double _Complex *reg = (double _Complex *)mFP + layout.nfp++;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                    memcpy(reg, (char *)ptr + f.offset, f.size);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                    memcpy((const char *)reg + sizeof(double _Complex) - f.size, (char *)ptr + f.offset, f.size);
#endif
                } else {
                    unsigned long *reg = (unsigned long *)mI + layout.ni++;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                    memcpy(reg, (char *)ptr + f.offset, f.size);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                    memcpy((const char *)reg + sizeof(unsigned long) - f.size, (char *)ptr + f.offset, f.size);
#endif
                }
            }
        }(), ...);
    }

private:
    void *mI;
    void *mFP;
    void *mStack;
};

class APIBase {
public:
    static constexpr void **errorInterface() {
        return &error.t;
    }

protected:
    static go::interface error;
};

template<int ClassID, int MethodID, int ErrorIndex, typename Tamper, typename Tracer>
class APIEntry : public APIBase {
public:
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

private:
    static bool handler(void *sp) {
        unsigned long SFP = FLOAT_REGISTER * sizeof(double _Complex);
        unsigned long SI = INTEGER_REGISTER * sizeof(unsigned long);

        void *I = (char *)sp - SFP - SI;
        void *FP = (char *)sp - SFP;

        Tracer tracer(I, FP, sp);

        Trace trace = {
                ClassID,
                MethodID
        };

        tracer.read(trace);
        tracer.traceback(trace);

        if constexpr (ErrorIndex >= 0) {
            if (error.t && block(trace)) {
                trace.blocked = true;

                gSmithProbe->enqueue(trace);
                Tamper(I, FP, tracer.getResultStack()).template write<ErrorIndex>(&error);

                return false;
            }
        }

        if (!surplus())
            return true;

        gSmithProbe->enqueue(trace);

        return true;
    }

    static bool surplus() {
        int n = __atomic_load_n(&config.quota, __ATOMIC_SEQ_CST);

        do {
            if (n <= 0)
                return false;
        } while (!__atomic_compare_exchange_n(&config.quota, &n, n - 1, true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));

        return true;
    }

    static bool block(const Trace &trace)  {
        z_rwlock_read_lock(&config.lock);

        bool match = std::any_of(config.policies.rules, config.policies.rules + config.policies.count, [&](const auto &rule) {
            if (rule.first >= trace.count)
                return false;

            int length = 0;

            return re_match(rule.second, trace.args[rule.first], &length) != -1;
        });

        z_rwlock_read_unlock(&config.lock);

        return match;
    }

public:
    static constexpr APIMetadata metadata() {
        return {ClassID, MethodID, entry, &origin, &config};
    }

private:
    static void *origin;
    static APIConfig config;
};

template<int ClassID, int MethodID, int ErrorIndex, typename Tamper, typename Tracer>
void *APIEntry<ClassID, MethodID, ErrorIndex, Tamper, Tracer>::origin = nullptr;

template<int ClassID, int MethodID, int ErrorIndex, typename Tamper, typename Tracer>
APIConfig APIEntry<ClassID, MethodID, ErrorIndex, Tamper, Tracer>::config = {DEFAULT_QUOTAS};

constexpr auto GOLANG_API = {
        API {
                "os/exec.Command",
                APIEntry<0, 0, -1, APITamper<go::Uintptr>, APITracer<go::string, go::slice<go::string>>>::metadata(),
                false
        },
        {
                "os/exec.(*Cmd).Start",
                APIEntry<0, 1, 0, APITamper<go::interface>, APITracer<go::exec_cmd *>>::metadata(),
                false
        },
        {
                "os.OpenFile",
                APIEntry<1, 0, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::Int, go::Uint32>>::metadata(),
                false
        },
        {
                "os.Remove",
                APIEntry<1, 1, -1, APITamper<go::interface>, APITracer<go::string>>::metadata(),
                false
        },
        {
                "os.RemoveAll",
                APIEntry<1, 2, -1, APITamper<go::interface>, APITracer<go::string>>::metadata(),
                false
        },
        {
                "os.Rename",
                APIEntry<1, 3, -1, APITamper<go::interface>, APITracer<go::string, go::string>>::metadata(),
                true
        },
        {
                "io/ioutil.ReadDir",
                APIEntry<1, 4, -1, APITamper<go::slice<go::interface>, go::interface>, APITracer<go::string>>::metadata(),
                false
        },
        {
                "net.Dial",
                APIEntry<2, 0, -1, APITamper<go::interface, go::interface>, APITracer<go::string, go::string>>::metadata(),
                false
        },
        {
                "net.DialTCP",
                APIEntry<2, 1, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::tcp_address *, go::tcp_address *>>::metadata(),
                false
        },
        {
                "net.DialIP",
                APIEntry<2, 2, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::ip_address *, go::ip_address *>>::metadata(),
                false
        },
        {
                "net.DialUDP",
                APIEntry<2, 3, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::udp_address *, go::udp_address *>>::metadata(),
                false
        },
        {
                "net.DialUnix",
                APIEntry<2, 4, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::unix_address *, go::unix_address *>>::metadata(),
                false
        },
        {
                "net.(*Dialer).DialContext",
                APIEntry<2, 5, -1, APITamper<go::interface, go::interface>, APITracer<go::Uintptr, go::interface, go::string, go::string>>::metadata(),
                false
        },
        {
                "net.ResolveTCPAddr",
                APIEntry<3, 0, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::string>>::metadata(),
                false
        },
        {
                "net.ResolveIPAddr",
                APIEntry<3, 1, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::string>>::metadata(),
                false
        },
        {
                "net.ResolveUDPAddr",
                APIEntry<3, 2, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::string>>::metadata(),
                false
        },
        {
                "net.ResolveUnixAddr",
                APIEntry<3, 3, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::string>>::metadata(),
                false
        },
        {
                "net.LookupAddr",
                APIEntry<4, 0, -1, APITamper<go::slice<go::string>, go::interface>, APITracer<go::string>>::metadata(),
                false
        },
        {
                "net.LookupCNAME",
                APIEntry<4, 1, -1, APITamper<go::string, go::interface>, APITracer<go::string>>::metadata(),
                false
        },
        {
                "net.LookupHost",
                APIEntry<4, 2, -1, APITamper<go::slice<go::string>, go::interface>, APITracer<go::string>>::metadata(),
                false
        },
        {
                "net.LookupPort",
                APIEntry<4, 3, -1, APITamper<go::Int, go::interface>, APITracer<go::string, go::string>>::metadata(),
                false
        },
        {
                "net.LookupTXT",
                APIEntry<4, 4, -1, APITamper<go::slice<go::string>, go::interface>, APITracer<go::string>>::metadata(),
                false
        },
        {
                "net.LookupIP",
                APIEntry<4, 5, -1, APITamper<go::slice<go::slice<go::Uint8>>, go::interface>, APITracer<go::string>>::metadata(),
                false
        },
        {
                "net.LookupMX",
                APIEntry<4, 6, -1, APITamper<go::slice<go::Uintptr>, go::interface>, APITracer<go::string>>::metadata(),
                false
        },
        {
                "net.LookupNS",
                APIEntry<4, 7, -1, APITamper<go::slice<go::Uintptr>, go::interface>, APITracer<go::string>>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupAddr",
                APIEntry<4, 8, -1, APITamper<go::slice<go::string>, go::interface>, APITracer<go::Uintptr, go::interface, go::string>>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupCNAME",
                APIEntry<4, 9, -1, APITamper<go::string, go::interface>, APITracer<go::Uintptr, go::interface, go::string>>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupHost",
                APIEntry<4, 10, -1, APITamper<go::slice<go::string>, go::interface>, APITracer<go::Uintptr, go::interface, go::string>>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupPort",
                APIEntry<4, 11, -1, APITamper<go::Int, go::interface>, APITracer<go::Uintptr, go::interface, go::string, go::string>>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupTXT",
                APIEntry<4, 12, -1, APITamper<go::slice<go::string>, go::interface>, APITracer<go::Uintptr, go::interface, go::string>>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupIPAddr",
                APIEntry<4, 13, -1, APITamper<go::slice<go::ip_address>, go::interface>, APITracer<go::Uintptr, go::interface, go::string>>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupMX",
                APIEntry<4, 14, -1, APITamper<go::slice<go::Uintptr>, go::interface>, APITracer<go::Uintptr, go::interface, go::string>>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupNS",
                APIEntry<4, 15, -1, APITamper<go::slice<go::Uintptr>, go::interface>, APITracer<go::Uintptr, go::interface, go::string>>::metadata(),
                true
        },
        {
                "net.Listen",
                APIEntry<5, 0, -1, APITamper<go::interface, go::interface>, APITracer<go::string, go::string>>::metadata(),
                false
        },
        {
                "net.ListenTCP",
                APIEntry<5, 1, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::tcp_address *>>::metadata(),
                false
        },
        {
                "net.ListenIP",
                APIEntry<5, 2, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::ip_address *>>::metadata(),
                false
        },
        {
                "net.ListenUDP",
                APIEntry<5, 3, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::udp_address *>>::metadata(),
                false
        },
        {
                "net.ListenUnix",
                APIEntry<5, 4, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::unix_address *>>::metadata(),
                false
        },
        {
                "net/http.NewRequest",
                APIEntry<6, 0, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string, go::string>>::metadata(),
                false
        },
        {
                "net/http.NewRequestWithContext",
                APIEntry<6, 1, 1, APITamper<go::Uintptr, go::interface>, APITracer<go::interface, go::string, go::string, go::interface>>::metadata(),
                false
        },
        {
                "plugin.Open",
                APIEntry<7, 0, -1, APITamper<go::Uintptr, go::interface>, APITracer<go::string>>::metadata(),
                false
        }
};

#endif //GO_PROBE_API_H
