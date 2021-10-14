// SPDX-License-Identifier: GPL-2.0

#include "ring.h"

static int rs_cont(int *ctx)
{
    return *((volatile int *)ctx);
}

static volatile int g_rs_exit = 0;
static volatile int g_rs_quiet = 0;
static int rs_read_message()
{
    static char msg[SLOT_RECORD_MAX] = {0};
    int len = SLOT_RECORD_MAX;

    len = rs_read_ring(msg, len, rs_cont, (int *)&g_rs_exit);
    if (!g_rs_quiet && len) {
        for (int i = 0; i < len; i++)
            if (msg[i] == 0x1e)
                msg[i] = 0x20;
       printf("%s\n", msg);
    }
/*
 *  do message verifying ... 
 * 
 *   if (len) {
 *       if (memcmp(msg, g_rs_message, len)) {
 *           printf("message corrupted.\n");
 *       }
 *   }
 */

    return len;
}

static void rs_sigint_catch(int foo)
{
    printf("got CTRL + C, quiting ...\n");
    g_rs_exit = 1;
}

int main(int argc, char *argv[])
{
    struct ring_stat start, last, now;
    int interval = 5, c;

    signal(SIGINT, rs_sigint_catch);

    while (c = getopt (argc, argv, "QqI:i:")) {
        if (-1 == c)
            break;
        switch (c)
        {
        case 'Q':
        case 'q':
            g_rs_quiet = 1;
            break;
        case 'i':
        case 'I':
            if (optarg)
                interval = atoi(optarg);
            break;
        default:
            printf("Usage: %s [-q] [-n 10]\n", argv[0]);
            abort();
        }
    }

    /* validate value of interval */
    if (optind < argc && argv[optind])
        interval = atoi(argv[optind]);
    if (interval > 600)
        interval = 600;
    if (interval < 1)
        interval = 1;
    printf("mode: %s\tinterval: %d seconds\n", g_rs_quiet ? "quiet" : "noisy", interval);
    interval = interval * 1000000; /* second to us */

    if (0 == rs_init_ring()) {

        rs_query_stat_ring(&start);
        last = start;
    
        /* do consuming */
        while (!g_rs_exit) {

            rs_read_message();

            if (rs_is_elapsed(&last.tv, interval)) {
                rs_query_stat_ring(&now);
                rs_show_stat_ring(&start, &last, &now);
                rs_show_stat_ring(&start, &start, &now);
                last = now;
            }
        }
        printf("\n\nSummary:\n");
        rs_query_stat_ring(&now);
        rs_show_stat_ring(&start, &start, &now);

        /* cleaning up all resources */
        rs_fini_ring();
    }

    return 0;
}
