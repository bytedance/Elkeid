#ifndef GO_PROBE_HOOK_H
#define GO_PROBE_HOOK_H

#include "workspace.h"
#include <client/smith_probe.h>

#define ENTRY_NAME(name) GO_HOOK_##name
#define HANDLER_NAME(name) GO_HANDLER_##name
#define ORIGIN_NAME(name) GO_ORIGIN_##name
#define ORIGIN_PTR_FUNCTION(name) GO_ORIGIN_PTR_##name
#define ORIGIN_PTR(name) ORIGIN_PTR_FUNCTION(name)()
#define CLASS_ID(name) CLASS_ID_##name
#define METHOD_ID(name) METHOD_ID_##name

#define GO_HOOK_ENTRY_DEFINE(name, cid, mid)                        \
constexpr auto CLASS_ID(name) = cid;                                \
constexpr auto METHOD_ID(name) = mid;                               \
                                                                    \
void ENTRY_NAME(name)();                                            \
void HANDLER_NAME(name)(void *sp);                                  \
void **ORIGIN_PTR_FUNCTION(name)();                                 \

#define GO_HOOK_ENTRY(name, ...)                                    \
void *ORIGIN_NAME(name) = nullptr;                                  \
                                                                    \
void **ORIGIN_PTR_FUNCTION(name)() {                                \
    return &ORIGIN_NAME(name);                                      \
}                                                                   \
                                                                    \
void __attribute__ ((naked)) ENTRY_NAME(name)() {                   \
    asm volatile(                                                   \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm14, (%%rsp);"                                  \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm13, (%%rsp);"                                  \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm12, (%%rsp);"                                  \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm11, (%%rsp);"                                  \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm10, (%%rsp);"                                  \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm9, (%%rsp);"                                   \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm8, (%%rsp);"                                   \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm7, (%%rsp);"                                   \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm6, (%%rsp);"                                   \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm5, (%%rsp);"                                   \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm4, (%%rsp);"                                   \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm3, (%%rsp);"                                   \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm2, (%%rsp);"                                   \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm1, (%%rsp);"                                   \
        "sub $16, %%rsp;"                                           \
        "movdqu %%xmm0, (%%rsp);"                                   \
        "push %%r11;"                                               \
        "push %%r10;"                                               \
        "push %%r9;"                                                \
        "push %%r8;"                                                \
        "push %%rsi;"                                               \
        "push %%rdi;"                                               \
        "push %%rcx;"                                               \
        "push %%rbx;"                                               \
        "push %%rax;"                                               \
        "call new_workspace;"                                       \
        "cmp $0, %%rax;"                                            \
        "je end_%=;"                                                \
        "mov %%rsp, %%rdi;"                                         \
        "mov %%rax, %%rsp;"                                         \
        "add %0, %%rsp;"                                            \
        "push %%rax;"                                               \
        "push %%rdi;"                                               \
        "add $312, %%rdi;"                                          \
        "call %P1;"                                                 \
        "pop %%rsi;"                                                \
        "pop %%rdi;"                                                \
        "mov %%rsi, %%rsp;"                                         \
        "call free_workspace;"                                      \
        "end_%=:"                                                   \
        "pop %%rax;"                                                \
        "pop %%rbx;"                                                \
        "pop %%rcx;"                                                \
        "pop %%rdi;"                                                \
        "pop %%rsi;"                                                \
        "pop %%r8;"                                                 \
        "pop %%r9;"                                                 \
        "pop %%r10;"                                                \
        "pop %%r11;"                                                \
        "movdqu (%%rsp), %%xmm0;"                                   \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm1;"                                   \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm2;"                                   \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm3;"                                   \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm4;"                                   \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm5;"                                   \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm6;"                                   \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm7;"                                   \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm8;"                                   \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm9;"                                   \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm10;"                                  \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm11;"                                  \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm12;"                                  \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm13;"                                  \
        "add $16, %%rsp;"                                           \
        "movdqu (%%rsp), %%xmm14;"                                  \
        "add $16, %%rsp;"                                           \
        "jmp *%2;"                                                  \
        ::                                                          \
        "i"(WORKSPACE_SIZE),                                        \
        "i"(HANDLER_NAME(name)),                                    \
        "m"(ORIGIN_NAME(name))                                      \
        );                                                          \
}                                                                   \
                                                                    \
void HANDLER_NAME(name)(void *sp) {                                 \
    unsigned long SFP = FLOAT_REGISTER * sizeof(double _Complex);   \
    unsigned long SI = INTEGER_REGISTER * sizeof(unsigned long);    \
                                                                    \
    int NI = INTEGER_REGISTER;                                      \
    int NFP = FLOAT_REGISTER;                                       \
                                                                    \
    void *I = (char *)sp - SFP - SI;                                \
    void *FP = (char *)sp - SFP;                                    \
    void *stack = (char *)sp + sizeof(unsigned long);               \
                                                                    \
    CSmithTrace smithTrace = {};                                    \
                                                                    \
    smithTrace.classID = CLASS_ID(name);                            \
    smithTrace.methodID = METHOD_ID(name);                          \
                                                                    \
    smithTrace.read<__VA_ARGS__>(stack, I, NI, FP, NFP);            \
    smithTrace.traceback(sp);                                       \
                                                                    \
    gSmithProbe->trace(smithTrace);                                 \
}                                                                   \

#endif //GO_PROBE_HOOK_H
