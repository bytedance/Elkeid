#include "stringify.h"
#include <z_printf.h>

int go::stringify(const go::Int &value, char *buffer, size_t size) {
    return snprintf(buffer, size, "%lld", value);
}

int go::stringify(const go::Uint32 &value, char *buffer, size_t size) {
    return snprintf(buffer, size, "%u", value);
}

int go::stringify(const go::Uintptr &value, char *buffer, size_t size) {
    return snprintf(buffer, size, "0x%lx", value);
}

int go::stringify(const go::Interface &value, char *buffer, size_t size) {
    return snprintf(buffer, size, "0x%p:0x%p", value.tab, value.data);
}

int go::stringify(const go::String &value, char *buffer, size_t size) {
    if (value.empty())
        return 0;

    return snprintf(buffer, size, "%.*s", (int) value.length, value.data);
}

int go::stringify(const go::net::TCPAddress &value, char *buffer, size_t size) {
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

    return snprintf(buffer, size, "%s:%lld:%.*s", address, value.port, (int) value.zone.length, value.zone.data);
}

int go::stringify(const go::net::IPAddress &value, char *buffer, size_t size) {
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

    return snprintf(buffer, size, "%s:%.*s", address, (int) value.zone.length, value.zone.data);
}

int go::stringify(const go::net::UnixAddress &value, char *buffer, size_t size) {
    if (value.name.empty())
        return 0;

    if (value.net.empty())
        return snprintf(buffer, size, "%.*s", (int) value.name.length, value.name.data);

    return snprintf(
            buffer,
            size,
            "%.*s:%.*s",
            (int) value.name.length,
            value.name.data,
            (int) value.net.length,
            value.net.data
    );
}

int go::stringify(const go::os::exec::Cmd &value, char *buffer, size_t size) {
    char args[1024] = {};

    if (stringify(value.args, args, sizeof(args)) < 0)
        return -1;

    return snprintf(buffer, size, "%.*s %s", (int) value.path.length, value.path.data, args);
}