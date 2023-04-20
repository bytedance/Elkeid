#ifndef GO_PROBE_EBPF_CONFIG_H
#define GO_PROBE_EBPF_CONFIG_H

#include <stdbool.h>

#define CLASS_MAX 10
#define METHOD_MAX 20

typedef struct {
    bool register_based;
    bool fp;
    bool stop[CLASS_MAX][METHOD_MAX];
} probe_config;

#endif //GO_PROBE_EBPF_CONFIG_H
