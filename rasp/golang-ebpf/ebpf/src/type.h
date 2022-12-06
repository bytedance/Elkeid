#ifndef GO_PROBE_EBPF_TYPE_H
#define GO_PROBE_EBPF_TYPE_H

#include <stddef.h>

typedef signed char go_int8;
typedef unsigned char go_uint8;
typedef short go_int16;
typedef unsigned short go_uint16;
typedef int go_int32;
typedef unsigned int go_uint32;
typedef long long go_int64;
typedef unsigned long long go_uint64;
typedef go_int64 go_int;
typedef go_uint64 go_uint;
typedef __SIZE_TYPE__ go_uintptr;
typedef float go_float32;
typedef double go_float64;
typedef float _Complex go_complex64;
typedef double _Complex go_complex128;

typedef struct {
    void *t;
    void *v;
} interface;

typedef struct {
    void *data;
    go_int count;
    go_int capacity;
} slice;

typedef struct {
    const char *data;
    size_t length;
} string;

typedef struct {
    go_uint8 top_bits[8];
    char keys[0];
    char elems[0];
    void *overflow;
} bucket;

typedef struct {
    go_int count;
    go_uint8 flags;
    go_uint8 B;
    go_uint16 overflow_num;
    go_uint32 hash0;
    void *buckets;
    void *old_buckets;
    go_uintptr evacuate_num;
    go_uintptr extra;
} map;

typedef struct {
    string path;
    slice args;
} os_exec_cmd;

typedef struct {
    slice ip;
    go_int port;
    string zone;
} tcp_address, udp_address;

typedef struct {
    slice ip;
    string zone;
} ip_address;

typedef struct {
    string name;
    string net;
} unix_address;

typedef struct {
    string method;
    void *url;
    string protocol;
    go_int proto_major;
    go_int proto_minor;
    map *header;
    interface body;
    go_uintptr get_body;
    go_uint64 content_length;
    slice transfer_encoding;
    bool close;
    string host;
    map *form;
    map *post_form;
    go_uintptr multipart_form;
    map *trailer;
    string remote_address;
    string request_uri;
} http_request;

#endif //GO_PROBE_EBPF_TYPE_H
