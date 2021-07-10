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

#define GO_HOOK_ENTRY(name, offset, ...)                            \
void *ORIGIN_NAME(name) = nullptr;                                  \
                                                                    \
void **ORIGIN_PTR_FUNCTION(name)() {                                \
    return &ORIGIN_NAME(name);                                      \
}                                                                   \
                                                                    \
void __attribute__ ((naked)) ENTRY_NAME(name)() {                   \
    asm volatile(                                                   \
        "sub $8, %%rsp;"                                            \
        "call new_workspace;"                                       \
        "cmp $0, %%rax;"                                            \
        "je end_%=;"                                                \
        "mov %%rsp, %%rdi;"                                         \
        "mov %%rax, %%rsp;"                                         \
        "add %0, %%rsp;"                                            \
        "push %%rax;"                                               \
        "push %%rdi;"                                               \
        "add $8, %%rdi;"                                            \
        "call %P1;"                                                 \
        "pop %%rsi;"                                                \
        "pop %%rdi;"                                                \
        "mov %%rsi, %%rsp;"                                         \
        "call free_workspace;"                                      \
        "end_%=:"                                                   \
        "add $8, %%rsp;"                                            \
        "jmp *%2;"                                                  \
        ::                                                          \
        "i"(WORKSPACE_SIZE),                                        \
        "i"(HANDLER_NAME(name)),                                    \
        "m"(ORIGIN_NAME(name))                                      \
        );                                                          \
}                                                                   \
                                                                    \
void HANDLER_NAME(name)(void *sp) {                                 \
    void *arg = (char *)sp + sizeof(unsigned long) + offset;        \
                                                                    \
    CSmithTrace smithTrace = {};                                    \
                                                                    \
    smithTrace.classID = CLASS_ID(name);                            \
    smithTrace.methodID = METHOD_ID(name);                          \
                                                                    \
    smithTrace.read<__VA_ARGS__>(arg);                              \
    smithTrace.traceback(sp);                                       \
                                                                    \
    gSmithProbe->trace(smithTrace);                                 \
}                                                                   \

#endif //GO_PROBE_HOOK_H
