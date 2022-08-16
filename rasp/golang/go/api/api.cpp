#include "api.h"
#include <printf.h>

constexpr auto MIN_TOP_HASH = 5;
constexpr auto WRITING_FLAG = 0x4;

constexpr auto RASP_ERROR = "API blocked by RASP";

constexpr auto RASP_ERROR_STRING = go::string {
        RASP_ERROR,
        19
};

go::interface APIBase::error = {
        nullptr,
        (void *)&RASP_ERROR_STRING
};

int toString(const go::Int &value, char *buffer, size_t size) {
    return snprintf(buffer, size, "%lld", value);
}

int toString(const go::Uint32 &value, char *buffer, size_t size) {
    return snprintf(buffer, size, "%u", value);
}

int toString(const go::Uintptr &value, char *buffer, size_t size) {
    return snprintf(buffer, size, "0x%lx", value);
}

int toString(const go::interface &value, char *buffer, size_t size) {
    return snprintf(buffer, size, "0x%p:0x%p", value.t, value.v);
}

int toString(const go::string &value, char *buffer, size_t size) {
    if (value.empty())
        return 0;

    return snprintf(buffer, size, "%.*s", (int)value.length, value.data);
}

int toString(const go::tcp_address &value, char *buffer, size_t size) {
    char address[1024] = {};

    switch (value.ip.count) {
        case 4:
            snprintf(address, sizeof(address), "%d.%d.%d.%d", value.ip[0], value.ip[1], value.ip[2], value.ip[3]);
            break;

        case 16:
            snprintf(
                    address,
                    sizeof(address),
                    "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    value.ip[0], value.ip[1], value.ip[2], value.ip[3],
                    value.ip[4], value.ip[5], value.ip[6], value.ip[7],
                    value.ip[8], value.ip[9], value.ip[10], value.ip[11],
                    value.ip[12], value.ip[13], value.ip[14], value.ip[15]
            );
            break;

        default:
            return -1;
    }

    if (value.zone.empty())
        return snprintf(buffer, size, "%s:%lld", address, value.port);

    return snprintf(buffer, size, "%s:%lld:%.*s", address, value.port, (int)value.zone.length, value.zone.data);
}

int toString(const go::ip_address &value, char *buffer, size_t size) {
    char address[1024] = {};

    switch (value.ip.count) {
        case 4:
            snprintf(address, sizeof(address), "%d.%d.%d.%d", value.ip[0], value.ip[1], value.ip[2], value.ip[3]);
            break;

        case 16:
            snprintf(
                    address,
                    sizeof(address),
                    "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    value.ip[0], value.ip[1], value.ip[2], value.ip[3],
                    value.ip[4], value.ip[5], value.ip[6], value.ip[7],
                    value.ip[8], value.ip[9], value.ip[10], value.ip[11],
                    value.ip[12], value.ip[13], value.ip[14], value.ip[15]
            );
            break;

        default:
            return -1;
    }

    if (value.zone.empty())
        return snprintf(buffer, size, "%s", address);

    return snprintf(buffer, size, "%s:%.*s", address, (int)value.zone.length, value.zone.data);
}

int toString(const go::unix_address &value, char *buffer, size_t size) {
    if (value.name.empty())
        return 0;

    if (value.net.empty())
        return snprintf(buffer, size, "%.*s", (int)value.name.length, value.name.data);

    return snprintf(buffer, size, "%.*s:%.*s", (int)value.name.length, value.name.data, (int)value.net.length, value.net.data);
}

int toString(const go::exec_cmd &value, char *buffer, size_t size) {
    char args[1024] = {};

    if (toString(value.args, args, sizeof(args)) < 0)
        return -1;

    return snprintf(buffer, size, "%.*s %s", (int)value.path.length, value.path.data, args);
}

template<typename K, typename V>
int toString(const go::map<K, V> &value, char *buffer, size_t size) {
    if (value.flags & WRITING_FLAG || value.oldBuckets)
        return 0;

    int length = 0;

    for (int i = 0, count = 0; i < (2 ^ value.B) && count < value.count && length + 1 < size; i++) {
        for (go::bucket<K, V> *bucket = value.buckets + i; bucket && length + 1 < size; bucket = bucket->overflow) {
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
