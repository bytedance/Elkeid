// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "../include/trace.h"

static volatile int g_rb_exit = 0;
static volatile int g_rb_quiet = 0;

static uint64_t g_num_corrupted = 0;
static uint64_t g_num_processed = 0;


#define MSG_SLOT_LEN    (65536)
static char g_rb_msg[MSG_SLOT_LEN] = {0};
static int rb_read_message(int fd)
{
    int rc, i, s = 0;

    rc = read(fd, g_rb_msg, MSG_SLOT_LEN - 1);
    for (i = 0; i <= rc; i++) {
        if (i == rc || g_rb_msg[i] == 0x17) {
            g_rb_msg[i] = 0;
            if (!g_rb_quiet && i > s)
                printf("%d/%d %s\n", s, rc, &g_rb_msg[s]);
            s = i + 1;
            g_num_processed++;
        } else if (g_rb_msg[i] == 0x1e) {
            g_rb_msg[i] = ' ';
        }
    }
    memset(g_rb_msg, 0, MSG_SLOT_LEN);

    return rc;
}

static void rb_sigint_catch(int foo)
{
    printf("got CTRL + C, quiting ...\n");
    g_rb_exit = 1;
}

/*
 * statatics support routines
 */

struct rb_stat {
    uint32_t        nrings;
    uint32_t        flags;

    struct timeval  tv;
    uint64_t        npros;  /* number of messages producted */
    uint64_t        ncons;  /* number of messages consumed */
    uint64_t        ndrop;  /* dropped by producer when ring is full */
    uint64_t        ndisc;  /* discarded by producer for overwriting */
    uint64_t        nexcd;  /* total dropped messages (too long to save) */
    uint64_t        cpros;  /* bytes of produced messages */
    uint64_t        ccons;  /* bytes of consumed messages */
    uint64_t        cdrop;  /* bytes of dropped messages */
    uint64_t        cdisc;  /* bytes of discarded messages */
    uint32_t        maxsz;
};

int rb_is_elapsed(struct timeval *tv, long cycle)
{
    struct timeval now;

    gettimeofday(&now, NULL);
    return ((int64_t)now.tv_sec * 1000000UL + now.tv_usec >=
            (int64_t)tv->tv_sec * 1000000UL + tv->tv_usec + cycle);
}

int rb_query_stat_ring(int fd, struct rb_stat *stat)
{
    struct tb_stat ts = {0};
    int rc;

    rc = ioctl(fd, TRACE_IOCTL_STAT, &ts);
    if (rc == sizeof(ts)) {
        gettimeofday(&stat->tv, NULL);
        stat->npros = ts.produced_events;
        stat->ncons = ts.consumed_events;
        stat->ndrop = ts.dropped_events + ts.rejected_events;
        stat->ndisc = ts.discarded_events + ts.overwritten_events;
        stat->cpros = ts.produced_size;
        stat->ccons = ts.consumed_size;
        stat->cdrop = ts.dropped_size + ts.rejected_size;
        stat->cdisc = ts.discarded_size + ts.overwritten_size;
        stat->nexcd = ts.rejected_events;
        stat->maxsz = ts.max_event_size;
        stat->nrings = ts.num_cpu_rings;
        stat->flags = ts.overwritable;
        return sizeof(*stat);
    } else {
        printf("faiiled to query ioctl: %d\n", rc);
    }
    return 0;
}

void rb_show_stat_ring(struct rb_stat *s, struct rb_stat *l, struct rb_stat *n)
{
    double interval, elapsed, i1, i2;
    char  *u1, *u2;

    if (n->npros - l->npros > 500UL * 1000 * 1024) {
        u1 = "G";
        i1 = 1024.0 * 1024 * 1024;
    } else if (n->npros - l->npros > 900 * 1024) {
        u1 = "M";
        i1 = 1024.0 * 1024;
    } else if (n->npros - l->npros > 2 * 1024) {
        u1 = "K";
        i1 = 1024.0;
    } else {
        u1 = "n";
        i1 = 1.0;
    }

    if (n->cpros - l->cpros > 500UL * 1000 * 1024) {
        u2 = "GB";
        i2 = 1024.0 * 1024 * 1024;
    } else if (n->cpros - l->cpros > 900 * 1024) {
        u2 = "MB";
        i2 = 1024.0 * 1024;
    } else if (n->cpros - l->cpros > 2 * 1024) {
        u2 = "KB";
        i2 = 1024.0;
    } else {
        u2 = "bytes";
        i2 = 1.0;
    }

    interval = (double)((int64_t)(n->tv.tv_sec - l->tv.tv_sec) * 1000000UL +
                        n->tv.tv_usec - l->tv.tv_usec) / 1000000.0;

    elapsed = (double)((int64_t)(n->tv.tv_sec - s->tv.tv_sec) * 1000000UL +
                        n->tv.tv_usec - l->tv.tv_usec) / 1000000.0;

    if (s != l) {
        printf("\nCPU cores: %d  \tInterval: %.1fs  \t\tElapsed: %.1fs\t\tExtra-large payload: %lu/%u\n",
                n->nrings, interval, elapsed, n->nexcd, n->maxsz);
    } else {
        printf("\nCPU cores: %d  \tElapsed: %.1f (seconds)\t\tExtra-large payload: %lu/%u\n",
                n->nrings, elapsed, n->nexcd, n->maxsz);
    }
    printf("items (%s)\t\t\t\t\t\t\tbytes (%s)\n", u1, u2);
    printf("produced\tconsumed\t dropped\tdiscarded    "
           "\tproduced\tconsumed\t dropped\tdiscarded\n");
    printf("%8lu\t%8lu\t%8lu\t%8lu    "
           "\t%8lu\t%8lu\t%8lu\t%8lu\n",
            n->npros - l->npros,
            n->ncons - l->ncons,
            n->ndrop - l->ndrop,
            n->ndisc - l->ndisc,

            n->cpros - l->cpros,
            n->ccons - l->ccons,
            n->cdrop - l->cdrop,
            n->cdisc - l->cdisc
           );
    printf("%8.3f\t%8.3f\t%8.3f\t%8.3f    "
           "\t%8.3f\t%8.3f\t%8.3f\t%8.3f\n",
            (double)(n->npros - l->npros) / i1,
            (double)(n->ncons - l->ncons) / i1,
            (double)(n->ndrop - l->ndrop) / i1,
            (double)(n->ndisc - l->ndisc) / i1,

            (double)(n->cpros - l->cpros) / i2,
            (double)(n->ccons - l->ccons) / i2,
            (double)(n->cdrop - l->cdrop) / i2,
            (double)(n->cdisc - l->cdisc) / i2
           );

    if ((double)(n->npros - l->npros) > interval * 500UL * 1000 * 1024) {
        u1 = "G";
        i1 = 1024.0 * 1024 * 1024;
    } else if ((double)(n->npros - l->npros) > interval * 900 * 1024) {
        u1 = "M";
        i1 = 1024.0 * 1024;
    } else if ((double)(n->npros - l->npros) > interval * 2 * 1024) {
        u1 = "K";
        i1 = 1024.0;
    } else {
        u1 = "n";
        i1 = 1.0;
    }

    if ((double)(n->cpros - l->cpros) > interval * 500UL * 1000 * 1024) {
        u2 = "GB";
        i2 = 1024.0 * 1024 * 1024;
    } else if ((double)(n->cpros - l->cpros) > interval * 900 * 1024) {
        u2 = "MB";
        i2 = 1024.0 * 1024;
    } else if ((double)(n->cpros - l->cpros) > interval * 2 * 1024) {
        u2 = "KB";
        i2 = 1024.0;
    } else {
        u2 = "bytes";
        i2 = 1.0;
    }

    printf("items (%s/s)\t\t\t\t\t\t\tbytes (%s/s)\n", u1, u2);
    printf("produced\tconsumed\t dropped\tdiscarded    "
           "\tproduced\tconsumed\t dropped\tdiscarded\n");
    printf("%8.3f\t%8.3f\t%8.3f\t%8.3f    "
           "\t%8.3f\t%8.3f\t%8.3f\t%8.3f\n",
            (double)(n->npros - l->npros) / i1 / interval,
            (double)(n->ncons - l->ncons) / i1 / interval,
            (double)(n->ndrop - l->ndrop) / i1 / interval,
            (double)(n->ndisc - l->ndisc) / i1 / interval,

            (double)(n->cpros - l->cpros) / i2 / interval,
            (double)(n->ccons - l->ccons) / i2 / interval,
            (double)(n->cdrop - l->cdrop) / i2 / interval,
            (double)(n->cdisc - l->cdisc) / i2 / interval 
           );
}

int main(int argc, char *argv[])
{
    struct rb_stat start = {0}, now = {0}, last;
    int fd = -1, interval = 5, c;

    signal(SIGINT, rb_sigint_catch);

    while (c = getopt (argc, argv, "QqI:i:")) {
        if (-1 == c)
            break;
        switch (c)
        {
        case 'Q':
        case 'q':
            g_rb_quiet = 1;
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

    fd = open("/proc/elkeid-endpoint", O_RDONLY);
    if (fd < 0) {
        printf("Error: failed to open hids endpoint\n");
        return -1;
    }

    printf("mode: %s\tinterval: %d seconds\n", g_rb_quiet ? "quiet" : "noisy", interval);
    interval = interval * 1000000; /* second to us */

    rb_query_stat_ring(fd, &start);
    last = start;

    /* do consuming */
    while (!g_rb_exit) {
        rb_read_message(fd);

        if (rb_is_elapsed(&last.tv, interval)) {
            rb_query_stat_ring(fd, &now);
            rb_show_stat_ring(&start, &last, &now);
            printf("processed: %lu\t\tcorrupted: %lu\n", g_num_processed, g_num_corrupted);
            g_num_processed = g_num_corrupted = 0;
            rb_show_stat_ring(&start, &start, &now);
            last = now;
        }
    }
    printf("\n\nSummary:\n");
    rb_query_stat_ring(fd, &now);
    rb_show_stat_ring(&start, &start, &now);

    if (fd >= 0)
        close(fd);

    return 0;
}
