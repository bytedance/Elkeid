#ifndef GO_PROBE_SMITH_TRACE_H
#define GO_PROBE_SMITH_TRACE_H

#include <go/type/net.h>
#include <go/type/os.h>
#include <go/symbol/func.h>
#include <go/symbol/build_info.h>
#include <cstring>

constexpr auto ARG_COUNT = 20;
constexpr auto ARG_LENGTH = 256;
constexpr auto TRACE_COUNT = 20;

constexpr auto FLOAT_REGISTER = 15;
constexpr auto INTEGER_REGISTER = 9;

struct CStackTrace {
    void *pc;
    CFunction func;
};

class CSmithTrace {
private:
    void push(const go::Int &arg);
    void push(const go::Uint32 &arg);
    void push(const go::Uintptr &arg);
    void push(const go::interface &arg);
    void push(const go::string &arg);
    void push(const go::slice<go::string>& arg);

private:
    void push(const go::tcp_address* arg);
    void push(const go::ip_address* arg);
    void push(const go::unix_address* arg);

private:
    void push(const go::exec_cmd *arg);

public:
    template<typename Current, typename Next, typename... Rest>
    void read(void *&sp, void *&I, int &NI, void *&FP, int &NFP) {
        read<Current>(sp, I, NI, FP, NFP);
        read<Next, Rest...>(sp, I, NI, FP, NFP);
    }

    template<typename T>
    void read(void *&stack, void *&I, int &NI, void *&FP, int &NFP) {
        T t = {};
        void *p = &t;

        auto fields = go::Metadata<T>::getFields();
        auto align = go::Metadata<T>::getAlign();
        auto size = go::Metadata<T>::getSize();

        auto integerRegister = go::Metadata<T>::getIntegerRegister();
        auto floatRegister = go::Metadata<T>::getFloatRegister();
        auto hasNonTrivialArray = go::Metadata<T>::hasNonTrivialArray();

        if (!gBuildInfo->mRegisterBased || hasNonTrivialArray || integerRegister > NI || floatRegister > NFP) {
            auto piece = (unsigned long)stack % align;
            stack = (char *)stack + (piece ? align - piece : 0);

            for (const auto &f : fields) {
                memcpy(p, (char *)stack + f.offset, f.size);
                p = (char *)p + f.size;
            }

            stack = (char *)stack + size;
        } else {
            for (const auto &f : fields) {
                if (f.floating) {
                    memcpy(p, (double _Complex *)FP + (FLOAT_REGISTER - NFP--), f.size);
                } else {
                    memcpy(p, (unsigned long *)I + (INTEGER_REGISTER - NI--), f.size);
                }

                p = (char *)p + f.size;
            }
        }

        push(t);
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
