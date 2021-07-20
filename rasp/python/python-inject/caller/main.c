#include <z_log.h>
#include <z_syscall.h>
#include <z_std.h>
#include <z_memory.h>
#include <fcntl.h>

typedef int (*PFN_RUN)(const char *command);
typedef int (*PFN_ENSURE)();
typedef void (*PFN_RELEASE)(int);

int main(int argc, char **argv, char **env) {
    if (argc < 6) {
        LOG("usage: ./program source [0|1](source is file) address address address");
        return -1;
    }

    char *source = argv[1];
    int is_file = !z_strcmp(argv[2], "1");

    PFN_ENSURE pfn_ensure = (PFN_ENSURE)z_strtoul(argv[3], NULL, 16);
    PFN_RUN pfn_run = (PFN_RUN)z_strtoul(argv[4], NULL, 16);
    PFN_RELEASE pfn_release = (PFN_RELEASE)z_strtoul(argv[5], NULL, 16);

    if (!pfn_ensure || !pfn_run || !pfn_release) {
        LOG("func address error");
        return -1;
    }

    LOG("inject python source: %s flag: %d", source, is_file);

    char *code = source;

    if (is_file) {
        int fd = z_open(source, O_RDONLY, 0);

        if (fd < 0) {
            LOG("open failed: %s %d", source, z_errno);
            return -1;
        }

        long size = z_lseek(fd, 0, SEEK_END);

        if (size < 0) {
            z_close(fd);
            return -1;
        }

        if (z_lseek(fd, 0, SEEK_SET) < 0) {
            z_close(fd);
            return -1;
        }

        code = z_malloc(size + 1);

        if (!code) {
            z_close(fd);
            return -1;
        }

        z_memset(code, 0, size + 1);

        if (z_read(fd, code, size) != size) {
            z_free(code);
            z_close(fd);

            return -1;
        }

        z_close(fd);
    }

    int state = pfn_ensure();
    int err = pfn_run(code);
    pfn_release(state);

    if (is_file) {
        z_free(code);
    }

    return err;
}

void _main(unsigned long *sp) {
    int argc = *(int *)sp;
    char **argv = (char **)(sp + 1);
    char **env = argv + argc + 1;

    int status = main(argc, argv, env);
    z_exit(status);
}

void _start() {
    asm volatile("mov %%rsp, %%rdi; call *%%rax;" :: "a"(_main));
}
