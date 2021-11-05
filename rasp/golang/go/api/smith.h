#ifndef GO_PROBE_SMITH_H
#define GO_PROBE_SMITH_H

#include <go/symbol/build_info.h>
#include <go/stack/smith_trace.h>

constexpr auto FLOAT_REGISTER = 15;
constexpr auto INTEGER_REGISTER = 9;

struct CLayout {
    int ni;
    int nfp;
    uintptr_t stack;
};

template<typename Current, typename Next, typename... Rest>
void getTypeLayout(int index, CLayout &layout) {
    if (index == 0)
        return;

    getTypeLayout<Current>(index, layout);
    getTypeLayout<Next, Rest...>(index - 1, layout);
}

template<typename T>
void getTypeLayout(int index, CLayout &layout) {
    if (index == 0)
        return;

    unsigned long align = go::Metadata<T>::getAlign();
    unsigned long size = go::Metadata<T>::getSize();

    int integerRegister = go::Metadata<T>::getIntegerRegister();
    int floatRegister = go::Metadata<T>::getFloatRegister();
    bool hasNonTrivialArray = go::Metadata<T>::hasNonTrivialArray();

    if (!gBuildInfo->mRegisterBased || hasNonTrivialArray || integerRegister + layout.ni > INTEGER_REGISTER || floatRegister + layout.nfp > FLOAT_REGISTER) {
        uintptr_t piece = layout.stack % align;
        layout.stack += (piece ? align - piece : 0) + size;
        return;
    }

    layout.ni += integerRegister;
    layout.nfp += floatRegister;
}

template<typename... Args>
class CSmithTracer {
public:
    explicit CSmithTracer(void *I, void *FP, void *stack) {
        mI = I;
        mFP = FP;
        mStack = stack;
    }

public:
    void read(CSmithTrace &trace) {
        CLayout layout = {
                0,
                0,
                (uintptr_t)mStack
        };

        read<Args...>(trace, layout);
    }

    void *getResultStack() {
        CLayout layout = {
                0,
                0,
                (uintptr_t)mStack
        };

        getTypeLayout<Args...>(sizeof...(Args), layout);

        return (void *)((layout.stack + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
    }

private:
    template<typename Current, typename Next, typename... Rest>
    void read(CSmithTrace &trace, CLayout &layout) {
        read<Current>(trace, layout);
        read<Next, Rest...>(trace, layout);
    }

    template<typename T>
    void read(CSmithTrace &trace, CLayout &layout) {
        T t = {};
        void *p = &t;

        auto fields = go::Metadata<T>::getFields();
        auto align = go::Metadata<T>::getAlign();
        auto size = go::Metadata<T>::getSize();

        int integerRegister = go::Metadata<T>::getIntegerRegister();
        int floatRegister = go::Metadata<T>::getFloatRegister();
        bool hasNonTrivialArray = go::Metadata<T>::hasNonTrivialArray();

        if (!gBuildInfo->mRegisterBased || hasNonTrivialArray || integerRegister + layout.ni > INTEGER_REGISTER || floatRegister + layout.nfp > FLOAT_REGISTER) {
            uintptr_t piece = layout.stack % align;
            layout.stack += (piece ? align - piece : 0);

            for (const auto &f : fields) {
                memcpy(p, (char *)layout.stack + f.offset, f.size);
                p = (char *)p + f.size;
            }

            layout.stack += size;
            trace.push(t);

            return;
        }

        for (const auto &f : fields) {
            if (f.floating) {
                double _Complex *reg = (double _Complex *)mFP + layout.nfp++;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                memcpy(p, reg, f.size);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                memcpy(p, (const char *)reg + sizeof(double _Complex) - f.size, f.size);
#endif
            } else {
                unsigned long *reg = (unsigned long *)mI + layout.ni++;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                memcpy(p, reg, f.size);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                memcpy(p, (const char *)reg + sizeof(unsigned long) - f.size, f.size);
#endif
            }

            p = (char *)p + f.size;
        }

        trace.push(t);
    }

private:
    void *mI;
    void *mFP;
    void *mStack;
};

template<typename... Args>
class CSmithTamper {
public:
    explicit CSmithTamper(void *I, void *FP, void *stack) {
        mI = I;
        mFP = FP;
        mStack = stack;
    }

public:
    void write(int index, void *ptr) {
        CLayout layout = {
                0,
                0,
                (uintptr_t)mStack
        };

        getTypeLayout<Args...>(index, layout);
        write<Args...>(index, ptr, layout);
    }

private:
    template<typename Current, typename Next, typename... Rest>
    void write(int index, void *ptr, CLayout &layout) {
        write<Current>(index, ptr, layout);
        write<Next, Rest...>(index - 1, ptr, layout);
    }

    template<typename T>
    void write(int index, void *ptr, CLayout &layout) {
        if (index != 0)
            return;

        auto fields = go::Metadata<T>::getFields();
        auto align = go::Metadata<T>::getAlign();
        auto size = go::Metadata<T>::getSize();

        int integerRegister = go::Metadata<T>::getIntegerRegister();
        int floatRegister = go::Metadata<T>::getFloatRegister();
        bool hasNonTrivialArray = go::Metadata<T>::hasNonTrivialArray();

        if (!gBuildInfo->mRegisterBased || hasNonTrivialArray || integerRegister + layout.ni > INTEGER_REGISTER || floatRegister + layout.nfp > FLOAT_REGISTER) {
            uintptr_t piece = layout.stack % align;
            uintptr_t stack = layout.stack + (piece ? align - piece : 0);

            for (const auto &f : fields) {
                memcpy((char *)stack + f.offset, ptr, f.size);
                ptr = (char *)ptr + f.size;
            }

            return;
        }

        for (const auto &f : fields) {
            if (f.floating) {
                double _Complex *reg = (double _Complex *)mFP + layout.nfp++;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                    memcpy(reg, ptr, f.size);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                    memcpy((const char *)reg + sizeof(double _Complex) - f.size, ptr, f.size);
#endif
            } else {
                unsigned long *reg = (unsigned long *)mI + layout.ni++;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                    memcpy(reg, ptr, f.size);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                    memcpy((const char *)reg + sizeof(unsigned long) - f.size, ptr, f.size);
#endif
            }

            ptr = (char *)ptr + f.size;
        }
    }

private:
    void *mI;
    void *mFP;
    void *mStack;
};

#endif //GO_PROBE_SMITH_H
