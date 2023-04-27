#ifndef GO_PROBE_STRINGIFY_H
#define GO_PROBE_STRINGIFY_H

#include "os.h"
#include "net.h"
#include <cstring>

constexpr auto MIN_TOP_HASH = 5;
constexpr auto WRITING_FLAG = 0x4;

namespace go {
    int stringify(const go::Int &value, char *buffer, size_t size);
    int stringify(const go::Uint32 &value, char *buffer, size_t size);
    int stringify(const go::Uintptr &value, char *buffer, size_t size);
    int stringify(const go::Interface &value, char *buffer, size_t size);
    int stringify(const go::String &value, char *buffer, size_t size);

    int stringify(const go::net::TCPAddress &value, char *buffer, size_t size);
    int stringify(const go::net::IPAddress &value, char *buffer, size_t size);
    int stringify(const go::net::UnixAddress &value, char *buffer, size_t size);

    int stringify(const go::os::exec::Cmd &value, char *buffer, size_t size);

    template<typename T>
    int stringify(const go::Slice<T> &value, char *buffer, size_t size) {
        int length = 0;

        for (int i = 0; i < value.count * 2 - 1 && length + 1 < size; i++) {
            if (i % 2) {
                strcpy(buffer + length++, " ");
                continue;
            }

            int n = stringify(value[i / 2], buffer + length, size - length);

            if (n < 0)
                break;

            length += n;
        }

        return length;
    }

    template<typename K, typename V>
    int stringify(const go::Map<K, V> &value, char *buffer, size_t size) {
        if (value.flags & WRITING_FLAG || value.oldBuckets)
            return 0;

        int length = 0;

        for (int i = 0, count = 0; i < (2 ^ value.B) && count < value.count && length + 1 < size; i++) {
            for (go::Bucket<K, V> *bucket = value.buckets + i; bucket && length + 1 < size; bucket = bucket->overflow) {
                for (int j = 0; j < 8 && length + 1 < size; j++) {
                    if (bucket->topBits[j] < MIN_TOP_HASH) {
                        if (!bucket->topBits[j])
                            break;

                        continue;
                    }

                    if (count++)
                        strcpy(buffer + length++, " ");

                    char k[1024] = {};

                    if (toString(bucket->keys[j], k, sizeof(k)) < 0)
                        break;

                    char v[1024] = {};

                    if (toString(bucket->elems[j], v, sizeof(v)) < 0)
                        break;

                    int n = snprintf(buffer + length, size - length, "%s:%s", k, v);

                    if (n < 0)
                        break;

                    length += n;
                }
            }
        }

        return length;
    }

    template<typename T, std::enable_if_t<std::is_pointer_v<T>> * = nullptr>
    int stringify(T value, char *buffer, size_t size) {
        if (!value)
            return 0;

        return stringify(*value, buffer, size);
    }
}

#endif //GO_PROBE_STRINGIFY_H
