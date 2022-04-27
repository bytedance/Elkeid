#ifndef GO_PROBE_SMITH_TRACE_H
#define GO_PROBE_SMITH_TRACE_H

#include <go/symbol/func.h>
#include <go/type/net.h>
#include <go/type/os.h>

constexpr auto ARG_COUNT = 20;
constexpr auto ARG_LENGTH = 256;
constexpr auto TRACE_COUNT = 20;

struct CStackTrace {
    uintptr_t pc;
    CFunc func;
};

class CSmithTrace {
public:
    void push(const go::Int &arg);
    void push(const go::Uint32 &arg);
    void push(const go::Uintptr &arg);
    void push(const go::interface &arg);
    void push(const go::string &arg);
    void push(const go::slice<go::string>& arg);

public:
    void push(const go::tcp_address* arg);
    void push(const go::ip_address* arg);
    void push(const go::unix_address* arg);
    void push(const go::exec_cmd *arg);

public:
    void traceback(void *sp);

public:
    int classID;
    int methodID;
    bool blocked;
    int count;
    char args[ARG_COUNT][ARG_LENGTH];
    CStackTrace stackTrace[TRACE_COUNT];
};

#endif //GO_PROBE_SMITH_TRACE_H
