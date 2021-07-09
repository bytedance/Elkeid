#include <crt_asm.h>
#include <crt_log.h>
#include <crt_utils.h>

typedef int (*PFN_RUN)(const char *command);
typedef int (*PFN_ENSURE)();
typedef void (*PFN_RELEASE)(int);

int main(int argc, char ** argv, char ** env) {
    if (argc < 6) {
        LOG("usage: ./program source [0|1](source is file) address address address");
        return -1;
    }

    char *source = argv[1];
    int is_file = !strcmp(argv[2], "1");

    PFN_ENSURE pfn_ensure = (PFN_ENSURE)strtoul(argv[3], NULL, 16);
    PFN_RUN pfn_run = (PFN_RUN)strtoul(argv[4], NULL, 16);
    PFN_RELEASE pfn_release = (PFN_RELEASE)strtoul(argv[5], NULL, 16);

    if (!pfn_ensure || !pfn_run || !pfn_release) {
        LOG("func address error");
        return -1;
    }

    LOG("inject python source: %s flag: %d", source, is_file);

    char *code = source;

    if (is_file) {
        char *buffer = NULL;
        long length = read_file(source, &buffer);

        if (length <= 0) {
            LOG("read file failed: %s", source);
            return -1;
        }

        code = malloc(length + 1);

        if (!code) {
            LOG("malloc code memory failed");
            free(buffer);
            return -1;
        }

        memset(code, 0, length + 1);
        memcpy(code, buffer, length);

        free(buffer);
    }

    int state = pfn_ensure();
    int err = pfn_run(code);
    pfn_release(state);

    if (is_file) {
        free(code);
    }

    return err;
}

void _main(unsigned long * sp) {
    int argc = *sp;
    char **argv = (char **)(sp + 1);
    char **env = argv + argc + 1;

    __exit(main(argc, argv, env));
}

void _start() {
    CALL_SP(_main);
}
