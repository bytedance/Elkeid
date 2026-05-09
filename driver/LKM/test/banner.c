/*
 * Warning Banner Program
 *
 * Build: gcc -static -o banner banner.c
 *
 */
#include <stdio.h>

void main(int argc, char *argv[])
{
    int i;
    fprintf(stderr, "WARNING: The following command is strictly prohibited:\n");
    for (i = 0; i < argc; i++) {
        fprintf(stderr, " %s", argv[i]);
    }
    fprintf(stderr, "\nAccording to OpenClaw Secure Usage Guidelines at ByteDance, please avoid doing so on business servers, Devbox, or BOE, IT Server, Volcano Engine & BytePlus internal tenant accounts, third-party cloud, or corporate network environments. This helps prevent potential security incidents and resource contention on critical systems.\n");
    fprintf(stderr, "ReferLink: https://bytedance.larkoffice.com/wiki/KqelwiPFlitA4vksQ0XcxiXEnLd?from=from_parent_docx\n");
}
