#ifndef GO_PROBE_EBPF_MACRO_H
#define GO_PROBE_EBPF_MACRO_H

#include <bpf/bpf_tracing.h>

#define BOUND(length, limit) (length & (limit - 1))
#define UNROLL_LOOP _Pragma("clang loop unroll(full)")

#define GO_PARM1_REGS rax
#define GO_PARM2_REGS rbx
#define GO_PARM3_REGS rcx
#define GO_PARM4_REGS rdi
#define GO_PARM5_REGS rsi
#define GO_PARM6_REGS r8
#define GO_PARM7_REGS r9
#define GO_PARM8_REGS r10
#define GO_PARM9_REGS r11

#define GO_REGS_PARM1(x) (__PT_REGS_CAST(x)->GO_PARM1_REGS)
#define GO_REGS_PARM2(x) (__PT_REGS_CAST(x)->GO_PARM2_REGS)
#define GO_REGS_PARM3(x) (__PT_REGS_CAST(x)->GO_PARM3_REGS)
#define GO_REGS_PARM4(x) (__PT_REGS_CAST(x)->GO_PARM4_REGS)
#define GO_REGS_PARM5(x) (__PT_REGS_CAST(x)->GO_PARM5_REGS)
#define GO_REGS_PARM6(x) (__PT_REGS_CAST(x)->GO_PARM6_REGS)
#define GO_REGS_PARM7(x) (__PT_REGS_CAST(x)->GO_PARM7_REGS)
#define GO_REGS_PARM8(x) (__PT_REGS_CAST(x)->GO_PARM8_REGS)
#define GO_REGS_PARM9(x) (__PT_REGS_CAST(x)->GO_PARM9_REGS)

#define GO_ABI_0_G_REGS rcx
#define GO_G_REGS r14

#define GO_REGS_ABI_0_G(x) (__PT_REGS_CAST(x)->GO_ABI_0_G_REGS)
#define GO_REGS_G(x) (__PT_REGS_CAST(x)->GO_G_REGS)

#endif //GO_PROBE_EBPF_MACRO_H
