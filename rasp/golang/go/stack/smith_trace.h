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

struct CSmithTrace {
    int classID;
    int methodID;
    int count;
    char args[ARG_COUNT][ARG_LENGTH];
    CStackTrace stackTrace[TRACE_COUNT];
};

class CSmithTracer {
public:
    explicit CSmithTracer(int classID, int methodID, void *sp, void *I, void *FP);

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
    void read() {
        read<Current>();
        read<Next, Rest...>();
    }

    template<typename T>
    void read() {
        T t = {};
        void *p = &t;

        auto fields = go::Metadata<T>::getFields();
        auto align = go::Metadata<T>::getAlign();
        auto size = go::Metadata<T>::getSize();

        auto integerRegister = go::Metadata<T>::getIntegerRegister();
        auto floatRegister = go::Metadata<T>::getFloatRegister();
        auto hasNonTrivialArray = go::Metadata<T>::hasNonTrivialArray();

        if (!gBuildInfo->mRegisterBased || hasNonTrivialArray || integerRegister > mNI || floatRegister > mNFP) {
            auto piece = (unsigned long)mStack % align;
            mStack = (char *)mStack + (piece ? align - piece : 0);

            for (const auto &f : fields) {
                memcpy(p, (char *)mStack + f.offset, f.size);
                p = (char *)p + f.size;
            }

            mStack = (char *)mStack + size;
        } else {
            for (const auto &f : fields) {
                if (f.floating) {
                    auto reg = (double _Complex *)mFP + (FLOAT_REGISTER - mNFP--);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                    memcpy(p, reg, f.size);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                    memcpy(p, (const char *)reg + sizeof(double _Complex) - f.size, f.size);
#endif
                } else {
                    auto reg = (unsigned long *)mI + (INTEGER_REGISTER - mNI--);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                    memcpy(p, reg, f.size);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                    memcpy(p, (const char *)reg + sizeof(unsigned long) - f.size, f.size);
#endif
                }

                p = (char *)p + f.size;
            }
        }

        push(t);
    }

public:
    void traceback();

public:
    CSmithTrace mTrace{};

private:
    void *mI;
    void *mFP;
    void *mPC;
    void *mStack;

private:
    int mNI{INTEGER_REGISTER};
    int mNFP{FLOAT_REGISTER};
};

#endif //GO_PROBE_SMITH_TRACE_H
