// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <signal.h>

#include "../include/trace.h"
#include "../include/xfer.h"

static volatile int g_tb_exit = 0;
static volatile int g_tb_quiet = 0;

#define MSG_SLOT_LEN    (65536)
static char g_tb_msg[MSG_SLOT_LEN] = {0};

static void tb_show_message(char *str, int len)
{
    int i, s = 0;

    for (i = 1; i < len; i++) {
        if (str[i] != SD_SEP_ENTRY || i <= s)
            continue;
        if (i + 4 <= len && *((uint32_t *)&str[i]) == SD_REC_ENDIAN) {
            str[i + 1] = str[i + 2] = 0;
            printf("%*s\n", i - s, &str[s]);
            s = i + 4;
        } else if (i + 1 < len) {
            str[i] = 0x20;
        } else if (i > s + 4) {
            printf("%*s\n", i - s, &str[s]);
        }
    }
}

static void tb_sigint_catch(int foo)
{
    printf("got CTRL + C, quiting ...\n");
    g_tb_exit = 1;
}

static int tb_cont(int *ctx)
{
    return *((volatile int *)ctx);
}

int main(int argc, char *argv[])
{
    struct ring_stat start = {0}, now = {0}, last;
    int interval = 5, c;

    signal(SIGINT, tb_sigint_catch);

    while (c = getopt(argc, argv, "QqI:i:")) {
        if (-1 == c)
            break;
        switch (c)
        {
        case 'Q':
        case 'q':
            g_tb_quiet = 1;
            break;
        case 'i':
        case 'I':
            if (optarg)
                interval = atoi(optarg);
            break;
        default:
            printf("Usage: %s [-q] [-i 10]\n", argv[0]);
            abort();
        }
    }

    printf("mode: %s\tinterval: %d seconds\n", g_tb_quiet ? "quiet" : "noisy", interval);
    interval = interval * 1000000; /* second to us */

    if (tb_init_ring()) {
        printf("failed to locate trace ring buffer.\n");
        return -1;
    }

    tb_query_stat_ring(&start);
    last = start;

    /* do consuming */
    while (!g_tb_exit) {
        c = tb_read_ring(g_tb_msg, MSG_SLOT_LEN,
                         tb_cont, (int *)&g_tb_exit);
        if (c > 0 && !g_tb_quiet)
            tb_show_message(g_tb_msg, c);

        if (tb_is_elapsed(&last.tv, interval)) {
            tb_query_stat_ring(&now);
            tb_show_stat_ring(&start, &last, &now);
            tb_show_stat_ring(&start, &start, &now);
            last = now;
        }
    }
    printf("\n\nSummary:\n");
    tb_query_stat_ring(&now);
    tb_show_stat_ring(&start, &start, &now);
    tb_fini_ring();

    return 0;
}
