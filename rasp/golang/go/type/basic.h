#ifndef GO_PROBE_BASIC_H
#define GO_PROBE_BASIC_H

#include <string>
#include <cstddef>

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

    enum endian {
        emLittleEndian,
        emBigEndian
    };

    struct interface {
        void *t;
        void *v;
    };

    struct string {
        const char *data;
        ptrdiff_t length;

        bool empty() const {
            return data == nullptr || length == 0;
        }

        std::string toSTDString() const {
            return std::string(data, length);
        }
    };

    template<class T>
    struct slice {
        T *values;
        Int count;
        Int capacity;

        bool empty() const {
            return count == 0;
        }

        T& operator[](int i) const {
            return values[i];
        }
    };
}

#endif //GO_PROBE_BASIC_H
