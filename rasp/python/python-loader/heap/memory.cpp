#include "memory.h"
#include <z_memory.h>

#ifdef __GLIBC__
static char heap[0x10000] = {};
static char *current = heap;

int brk(void *address) {
    if (address < heap || address > heap + 0x10000)
        return -1;

    current = (char *)address;

    return 0;
}

void *sbrk(intptr_t increment) {
    char *c = current;

    if (brk(c + increment) == -1)
        return (void *)-1;

    return c;
}

#endif

void *malloc(size_t size) {
    return z_malloc(size);
}

void *realloc(void *ptr, size_t size) {
    return z_realloc(ptr, size);
}

void *calloc(size_t num, size_t size) {
    return z_calloc(num, size);
}

void free(void *ptr) {
    z_free(ptr);
}