#ifndef GO_PROBE_HOOK_H
#define GO_PROBE_HOOK_H

#include "workspace.h"
#include <client/smith_probe.h>

using EntryPtr = void (*)();

struct CAPIMetadata {
    EntryPtr entry;
    void **origin;
};

template<int classID, int methodID, typename... Args>
struct CAPIEntry {
    static void *origin;

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
                "jmp *%2;"
                ::
                "i"(WORKSPACE_SIZE),
                "i"(handler),
                "m"(origin)
                );
    }

    static void handler(void *sp) {
        unsigned long SFP = FLOAT_REGISTER * sizeof(double _Complex);
        unsigned long SI = INTEGER_REGISTER * sizeof(unsigned long);

        int NI = INTEGER_REGISTER;
        int NFP = FLOAT_REGISTER;

        void *I = (char *)sp - SFP - SI;
        void *FP = (char *)sp - SFP;
        void *stack = (char *)sp + sizeof(unsigned long);

        CSmithTrace smithTrace = {};

        smithTrace.classID = classID;
        smithTrace.methodID = methodID;

        smithTrace.read<Args...>(stack, I, NI, FP, NFP);
        smithTrace.traceback(sp);

        gSmithProbe->trace(smithTrace);
    }

    static constexpr CAPIMetadata metadata() {
        return {entry, &origin};
    }
};

template<int classID, int methodID, typename... Args>
void * CAPIEntry<classID, methodID, Args...>::origin = nullptr;

#endif //GO_PROBE_HOOK_H
