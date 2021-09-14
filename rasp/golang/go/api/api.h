#ifndef GO_PROBE_API_H
#define GO_PROBE_API_H

#include "workspace.h"
#include <client/smith_probe.h>
#include <tiny-regex-c/re.h>

constexpr auto BLOCK_RULE_COUNT = 20;
constexpr auto BLOCK_RULE_LENGTH = 256;

struct CAPIBlockRule {
    int index;
    char regex[BLOCK_RULE_LENGTH];
};

struct CAPIBlockRuleList {
    unsigned long count;
    CAPIBlockRule items[BLOCK_RULE_COUNT];
};

struct CAPIMetadata {
    int classID;
    int methodID;
    void (*entry)();
    void **origin;
    z_rwlock_t *lock;
    CAPIBlockRuleList *rules;
};

class CAPIBase {
protected:
    template<typename Current, typename Next, typename... Rest>
    static constexpr void *getResultStack(void *stack) {
        unsigned long align = go::Metadata<Current>::getAlign();
        unsigned long size = go::Metadata<Current>::getSize();
        unsigned long piece = (unsigned long)stack % align;

        return getResultStack<Next, Rest...>((char *)stack + (piece ? align - piece : 0) + size);
    }

    template<typename Current>
    static constexpr void *getResultStack(void *stack) {
        unsigned long align = go::Metadata<Current>::getAlign();
        unsigned long size = go::Metadata<Current>::getSize();
        unsigned long piece = (unsigned long)stack % align;

        return (char *)stack + (piece ? align - piece : 0) + size;
    }

public:
    static constexpr void **errorInterface() {
        return &error.t;
    }

protected:
    static go::interface error;
};

template<int ClassID, int MethodID, bool CanBlock, typename... Args>
class CAPIEntry : public CAPIBase {
public:
    static void __attribute__ ((naked)) entry() {
        asm volatile(
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
        "call new_workspace;"
        "cmp $0, %%rax;"
        "je end_%=;"
        "mov %%rsp, %%rdi;"
        "mov %%rax, %%rsp;"
        "add %0, %%rsp;"
        "push %%rax;"
        "push %%rdi;"
        "add $312, %%rdi;"
        "call %P1;"
        "mov %%rax, %%r12;"
        "pop %%rsi;"
        "pop %%rdi;"
        "mov %%rsi, %%rsp;"
        "call free_workspace;"
        "end_%=:"
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
        "i"(WORKSPACE_SIZE),
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

        CSmithTracer smithTracer(ClassID, MethodID, sp, I, FP);

        smithTracer.read<Args...>();
        smithTracer.traceback();

        gSmithProbe->trace(smithTracer.mTrace);

        if (!CanBlock || !error.t)
            return true;

        if (block(smithTracer.mTrace)) {
            if (!gBuildInfo->mRegisterBased) {
                void *stack = getResultStack<Args...>((char *)sp + sizeof(unsigned long));

                unsigned long align = go::Metadata<go::interface>::getAlign();
                unsigned long piece = (unsigned long)stack % align;

                stack = (char *)stack + (piece ? align - piece : 0);

                *(void **)stack = error.t;
                *((void **)stack + 1) = error.v;
            } else {
                *(void **)I = error.t;
                *((void **)I + 1) = error.v;
            }

            return false;
        }

        return true;
    }

    static bool block(const CSmithTrace &smithTrace)  {
        z_rwlock_read_lock(&lock);

        bool match = std::any_of(rules.items, rules.items + rules.count, [&](const auto &rule) {
            if (rule.index >= smithTrace.count)
                return false;

            int length = 0;

            return re_match(rule.regex, smithTrace.args[rule.index], &length) != -1;
        });

        z_rwlock_read_unlock(&lock);

        return match;
    }

public:
    static constexpr CAPIMetadata metadata() {
        return {ClassID, MethodID, entry, &origin, &lock, &rules};
    }

private:
    static void *origin;
    static z_rwlock_t lock;
    static CAPIBlockRuleList rules;
};

template<int ClassID, int MethodID, bool CanBlock, typename... Args>
void *CAPIEntry<ClassID, MethodID, CanBlock, Args...>::origin = nullptr;

template<int ClassID, int MethodID, bool CanBlock, typename... Args>
z_rwlock_t CAPIEntry<ClassID, MethodID, CanBlock, Args...>::lock = {};

template<int ClassID, int MethodID, bool CanBlock, typename... Args>
CAPIBlockRuleList CAPIEntry<ClassID, MethodID, CanBlock, Args...>::rules = {};

struct CGolangAPI {
    const char *name;
    CAPIMetadata metadata;
    bool ignoreCase;
};

constexpr auto GOLANG_API = {
        CGolangAPI {
                "os/exec.Command",
                CAPIEntry<0, 0, false, go::string, go::slice<go::string>>::metadata(),
                false
        },
        {
                "os/exec.(*Cmd).Start",
                CAPIEntry<0, 1, true, go::exec_cmd *>::metadata(),
                false
        },
        {
                "os.OpenFile",
                CAPIEntry<1, 0, false, go::string, go::Int, go::Uint32>::metadata(),
                false
        },
        {
                "os.Remove",
                CAPIEntry<1, 1, false, go::string>::metadata(),
                false
        },
        {
                "os.RemoveAll",
                CAPIEntry<1, 2, false, go::string>::metadata(),
                false
        },
        {
                "os.Rename",
                CAPIEntry<1, 3, false, go::string, go::string>::metadata(),
                true
        },
        {
                "io/ioutil.ReadDir",
                CAPIEntry<1, 4, false, go::string>::metadata(),
                false
        },
        {
                "net.Dial",
                CAPIEntry<2, 0, false, go::string, go::string>::metadata(),
                false
        },
        {
                "net.DialTCP",
                CAPIEntry<2, 1, false, go::string, go::tcp_address *, go::tcp_address *>::metadata(),
                false
        },
        {
                "net.DialIP",
                CAPIEntry<2, 2, false, go::string, go::ip_address *, go::ip_address *>::metadata(),
                false
        },
        {
                "net.DialUDP",
                CAPIEntry<2, 3, false, go::string, go::udp_address *, go::udp_address *>::metadata(),
                false
        },
        {
                "net.DialUnix",
                CAPIEntry<2, 4, false, go::string, go::unix_address *, go::unix_address *>::metadata(),
                false
        },
        {
                "net.(*Dialer).DialContext",
                CAPIEntry<2, 5, false, go::Uintptr, go::interface, go::string, go::string>::metadata(),
                false
        },
        {
                "net.ResolveTCPAddr",
                CAPIEntry<3, 0, false, go::string, go::string>::metadata(),
                false
        },
        {
                "net.ResolveIPAddr",
                CAPIEntry<3, 1, false, go::string, go::string>::metadata(),
                false
        },
        {
                "net.ResolveUDPAddr",
                CAPIEntry<3, 2, false, go::string, go::string>::metadata(),
                false
        },
        {
                "net.ResolveUnixAddr",
                CAPIEntry<3, 3, false, go::string, go::string>::metadata(),
                false
        },
        {
                "net.LookupAddr",
                CAPIEntry<4, 0, false, go::string>::metadata(),
                false
        },
        {
                "net.LookupCNAME",
                CAPIEntry<4, 1, false, go::string>::metadata(),
                false
        },
        {
                "net.LookupHost",
                CAPIEntry<4, 2, false, go::string>::metadata(),
                false
        },
        {
                "net.LookupPort",
                CAPIEntry<4, 3, false, go::string, go::string>::metadata(),
                false
        },
        {
                "net.LookupTXT",
                CAPIEntry<4, 4, false, go::string>::metadata(),
                false
        },
        {
                "net.LookupIP",
                CAPIEntry<4, 5, false, go::string>::metadata(),
                false
        },
        {
                "net.LookupMX",
                CAPIEntry<4, 6, false, go::string>::metadata(),
                false
        },
        {
                "net.LookupNS",
                CAPIEntry<4, 7, false, go::string>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupAddr",
                CAPIEntry<4, 8, false, go::Uintptr, go::interface, go::string>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupCNAME",
                CAPIEntry<4, 9, false, go::Uintptr, go::interface, go::string>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupHost",
                CAPIEntry<4, 10, false, go::Uintptr, go::interface, go::string>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupPort",
                CAPIEntry<4, 11, false, go::Uintptr, go::interface, go::string, go::string>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupTXT",
                CAPIEntry<4, 12, false, go::Uintptr, go::interface, go::string>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupIPAddr",
                CAPIEntry<4, 13, false, go::Uintptr, go::interface, go::string>::metadata(),
                false
        },
        {
                "net.(*Resolver).LookupMX",
                CAPIEntry<4, 14, false, go::Uintptr, go::interface, go::string>::metadata(),
                true
        },
        {
                "net.(*Resolver).LookupNS",
                CAPIEntry<4, 15, false, go::Uintptr, go::interface, go::string>::metadata(),
                true
        },
        {
                "net.Listen",
                CAPIEntry<5, 0, false, go::string, go::string>::metadata(),
                false
        },
        {
                "net.ListenTCP",
                CAPIEntry<5, 1, false, go::string, go::tcp_address *>::metadata(),
                false
        },
        {
                "net.ListenIP",
                CAPIEntry<5, 2, false, go::string, go::ip_address *>::metadata(),
                false
        },
        {
                "net.ListenUDP",
                CAPIEntry<5, 3, false, go::string, go::udp_address *>::metadata(),
                false
        },
        {
                "net.ListenUnix",
                CAPIEntry<5, 4, false, go::string, go::unix_address *>::metadata(),
                false
        },
        {
                "net/http.NewRequest",
                CAPIEntry<6, 0, false, go::string, go::string>::metadata(),
                false
        },
        {
                "net/http.NewRequestWithContext",
                CAPIEntry<6, 1, false, go::interface, go::string, go::string>::metadata(),
                false
        },
        {
                "plugin.Open",
                CAPIEntry<7, 0, false, go::string>::metadata(),
                false
        }
};

#endif //GO_PROBE_API_H
