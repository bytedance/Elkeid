#ifndef GO_PROBE_MEMORY_H
#define GO_PROBE_MEMORY_H

#include <cstddef>

/*
 * Libc already exists in the process.
 * Runtimes will conflict on brk syscall, used by malloc, is not thread safe.
 * So use mmap instead in custom memory allocator.
 * But glibc still call brk, when tls setting up, does not happen in musl.
 */

extern "C" {
void *malloc(size_t size);
void *realloc(void *ptr, size_t size);
void *calloc(size_t num, size_t size);
void free(void *ptr);

#ifdef __GLIBC__
#include <cstdint>

int brk(void *address);
void *sbrk(intptr_t increment);

int __brk(void *address) __attribute__ ((alias ("brk")));
void *__sbrk(intptr_t increment) __attribute__ ((alias ("sbrk")));
#else
// musl 1.2.2
void *__libc_malloc(size_t size) __attribute__ ((alias ("malloc")));
void *__libc_calloc(size_t num, size_t size) __attribute__ ((alias ("calloc")));
#endif
};

#endif //GO_PROBE_MEMORY_H
