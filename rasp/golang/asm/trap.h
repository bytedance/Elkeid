#ifndef GO_PROBE_TRAP_H
#define GO_PROBE_TRAP_H

int hook(void *address, void *replace, void **backup);
int unhook(void *address, void *backup);

#endif //GO_PROBE_TRAP_H
