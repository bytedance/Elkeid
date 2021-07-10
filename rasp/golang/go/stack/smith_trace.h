#ifndef GO_PROBE_SMITH_TRACE_H
#define GO_PROBE_SMITH_TRACE_H

#include <go/type/net.h>
#include <go/type/os.h>
#include <go/symbol/func.h>

constexpr auto ARG_COUNT = 20;
constexpr auto ARG_LENGTH = 256;
constexpr auto TRACE_COUNT = 5;

struct CStackTrace {
    void *pc;
    CFunction func;
};

class CSmithTrace {
private:
    void push(const go::Int &arg);
    void push(const go::Uint32 &arg);
    void push(const go::string &arg);
    void push(const go::slice<go::string>& arg);

private:
    void push(const tcp_addr* arg);
    void push(const ip_addr* arg);
    void push(const unix_addr* arg);

private:
    void push(const exec_cmd *arg);

public:
    template<typename Current, typename Next, typename... Rest>
    void read(void *ptr) {
        push(*(Current *)ptr);
        read<Next, Rest...>((char *)ptr + sizeof(Current));
    }

    template<typename T>
    void read(void *ptr) {
        push(*(T *)ptr);
    }

public:
    void traceback(void *sp);

public:
    int classID;
    int methodID;

public:
    int count;
    char args[ARG_COUNT][ARG_LENGTH];

public:
    CStackTrace stackTrace[TRACE_COUNT];
};

#endif //GO_PROBE_SMITH_TRACE_H
