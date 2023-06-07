#ifndef GO_PROBE_BASIC_H
#define GO_PROBE_BASIC_H

#include "preprocess.h"
#include <string>

namespace go {
    typedef signed char Int8;
    typedef unsigned char Uint8;
    typedef short Int16;
    typedef unsigned short Uint16;
    typedef int Int32;
    typedef unsigned int Uint32;
    typedef long long Int64;
    typedef unsigned long long Uint64;
    typedef Int64 Int;
    typedef Uint64 Uint;
    typedef __SIZE_TYPE__ Uintptr;
    typedef float Float32;
    typedef double Float64;
    typedef float _Complex Complex64;
    typedef double _Complex Complex128;

    struct Interface {
        void *tab;
        void *data;
    };

    METADATA(Interface, void *, void *)

    struct EmptyInterface {
        void *type;
        void *data;
    };

    METADATA(EmptyInterface, void *, void *)

    struct String {
        const char *data;
        ptrdiff_t length;

        [[nodiscard]] bool empty() const {
            return data == nullptr || length == 0;
        }

        [[nodiscard]] std::string string() const {
            return {data, (size_t) length};
        }
    };

    METADATA(String, const char *, ptrdiff_t)

    template<typename T>
    struct Slice {
        T *values;
        Int count;
        Int capacity;

        [[nodiscard]] bool empty() const {
            return count == 0;
        }

        [[nodiscard]] T &operator[](int i) const {
            return values[i];
        }
    };

    template<typename T>
    TEMPLATE_METADATA(Slice<T>, T *, Int, Int)

    template<typename K, typename V>
    struct Bucket {
        Uint8 topBits[8];
        K keys[8];
        V elems[8];
        Bucket<K, V> *overflow;
    };

    template<typename K, typename V>
    TEMPLATE_METADATA(TEMPLATE_ARG(Bucket<K, V>), Int, K[8], V[8], Bucket<K, V> *)

    template<typename K, typename V>
    struct Map {
        Int count;
        Uint8 flags;
        Uint8 B;
        Uint16 overflowNum;
        Uint32 hash0;
        Bucket<K, V> *buckets;
        Bucket<K, V> *oldBuckets;
        Uintptr evacuateNum;
        Uintptr extra;
    };

    template<typename K, typename V>
    TEMPLATE_METADATA(
            TEMPLATE_ARG(Map<K, V>),
            Int,
            Uint8,
            Uint8,
            Uint16,
            Uint32,
            Bucket<K, V> *,
            Uintptr,
            Uintptr,
            Uintptr
    )
}

#endif //GO_PROBE_BASIC_H
