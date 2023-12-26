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

static void process_trusted_exes(void)
{
    char *exes[] = {"/usr/bin/pwd",
                    "/usr/bin/top",
                    "/usr/bin/ls",
                    "/usr/bin/git",
                    "/usr/lib/git-core/git",
                    "/usr/bin/sleep",
                    "/usr/bin/uname",
                    "/usr/bin/pidstat",
                    NULL
                   };
    int i;

    for (i = 0; exes[i]; i++)
        ac_setup(AL_TYPE_EXE, exes[i], strlen(exes[i]));
}

static void process_trusted_cmds(void)
{
    char *cmds[] = {"test/rst -i 10",
                    "test/rst -i 20",
                    "test/rst -i 30",
                    NULL
                   };
    int i;

    for (i = 0; cmds[i]; i++)
        ac_setup(AL_TYPE_ARGV, cmds[i], strlen(cmds[i]));
}

static void process_block_md5(char *name)
{
    char *data = NULL;
    FILE *fp;
    int len;

    fp = fopen(name, "rb");
    if (!fp)
        return;
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    data = malloc(len + 1);
    if (!data)
        goto out;
    fread(data, 1, len, fp);
    data[len] = 0;
    ac_setup(BL_JSON_MD5, data, len);

out:
    if (fp)
        fclose(fp);
    if (data)
        free(data);
}

static void process_block_exe(char *name)
{
    char *data = NULL;
    FILE *fp;
    int len;

    fp = fopen(name, "rb");
    if (!fp)
        return;
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    data = malloc(len + 1);
    if (!data)
        goto out;
    fread(data, 1, len, fp);
    data[len] = 0;
    ac_setup(BL_JSON_EXE, data, len);

out:
    if (fp)
        fclose(fp);
    if (data)
        free(data);
}

static void psad_set_ip4(void)
{
    char ips[16] = {0};
    struct psad_ip_list *list;

    list = (struct psad_ip_list *)ips;
    list->type = 4; /* 4: ipv4, 10: ipv6 */
    list->nips = 2;
    list->ips[0] = 0x0106a8c0; /* 192.168.6.1 */
    list->ips[1] = 0x0206a8c0; /* 192.168.6.2 */
    ac_setup(AL_TYPE_PSAD, &ips[0], sizeof(ips));
}

static void psad_set_ip6(void)
{
    char ips[4 * 2 + 4 * 4 * 2] = {0};
    struct psad_ip_list *list;
    struct ipaddr_v6 *a6;

    list = (struct psad_ip_list *)ips;
    a6 = (struct ipaddr_v6 *)list->ips;
    list->type = 10; /* 4: ipv4, 10: ipv6 */
    list->nips = 2;

    /* fdbd:ff1:ce00:608c:e2d:dc43:dd70:2d71  */
    a6[0].v6_addr16[0] = 0xbdfd;
    a6[0].v6_addr16[1] = 0xf1f0;
    a6[0].v6_addr16[2] = 0x00ce;
    a6[0].v6_addr16[3] = 0x6c60;
    a6[0].v6_addr16[4] = 0x2d0e;
    a6[0].v6_addr16[5] = 0x43dc;
    a6[0].v6_addr16[6] = 0x70dd;
    a6[0].v6_addr16[7] = 0x712d;

    /* fd21:468:181:f100::1 */
    a6[1].v6_addr16[0] = 0x21fd;
    a6[1].v6_addr16[1] = 0x6804;
    a6[1].v6_addr16[2] = 0x8101;
    a6[1].v6_addr16[3] = 0x00f1;
    a6[1].v6_addr16[4] = 0;
    a6[1].v6_addr16[5] = 0;
    a6[1].v6_addr16[6] = 0;
    a6[1].v6_addr16[7] = 0x0100;

    ac_setup(AL_TYPE_PSAD, &ips[0], sizeof(ips));
}

static void psad_clear_ips(void)
{
    ac_clear(AL_TYPE_PSAD);
}

static void psad_clear_ip4(void)
{
    char ips[8] = {0};
    struct psad_ip_list *list;

    list = (struct psad_ip_list *)ips;
    list->type = 4; /* 4: ipv4, 10: ipv6 */
    list->nips = 0;
    ac_setup(AL_TYPE_PSAD, &ips[0], sizeof(ips));
}

static void psad_clear_ip6(void)
{
    char ips[8] = {0};
    struct psad_ip_list *list;

    list = (struct psad_ip_list *)ips;
    list->type = 10; /* 4: ipv4, 10: ipv6 */
    list->nips = 0;
    ac_setup(AL_TYPE_PSAD, &ips[0], sizeof(ips));
}

static void help(char *arg)
{
    printf("Usage: %s [-d hids_driver] [-q] [-i 10] [-a cmd+path]\n", arg);

    printf("Examples: dump messages (CTRL+C to break):\n");
    printf("       rst -i 10\n");
    printf("       rst -i 10 -q\n");

    printf("Examples: add exe to allowlist:\n");
    printf("       rst -aF/usr/bin/top\n");
    printf("       rst -aF\"/home/any body/any dir/any executable\"\n");
    printf("       rst -a\"F/home/any body/any dir/any executable\"\n");
    printf("Examples: check if exe is in allowlist:\n");
    printf("       rst -az/usr/bin/top\n");
    printf("       rst -az\"/home/any body/any dir/any executable\"\n");
    printf("       rst -a\"z/home/any body/any dir/any executable\"\n");
    printf("Examples: delete exe from allowlist:\n");
    printf("       rst -aY/usr/bin/top\n");
    printf("       rst -aY\"/home/any body/any dir/any executable\"\n");
    printf("       rst -a\"Y/home/any body/any dir/any executable\"\n");
    printf("Examples: show all exe items in allowlist:\n");
    printf("       rst -a*\n");
    printf("       rst -a\\*\n");
    printf("Examples: delete all exe items from allow list:\n");
    printf("       rst -aq\n");

    printf("Examples: add cmd to allowlist:\n");
    printf("       rst -aJ\"rst -i 10\"\n");
    printf("       rst -a\"Jls -l\"\n");
    printf("Examples: check if cmd is in allowlist:\n");
    printf("       rst -ak\"rst -i 10\"\n");
    printf("       rst -a\"kls -l\"\n");
    printf("Examples: delete cmd from allowlist:\n");
    printf("       rst -am\"rst -i 10\"\n");
    printf("       rst -a\"mls -l\"\n");
    printf("Examples: show all cmd items in allowlist:\n");
    printf("       rst -a+\n");
    printf("       rst -a\\+\n");
    printf("Examples: delete all cmd items from allow list:\n");
    printf("       rst -an\n");
    printf("\n");
    printf("Examples: set allowlist and then dump messages:\n");
    printf("       rst -i 10 -d smith -aF/usr/bin/top -aF\"/home/any body/any dir/any executable\" -aF/usr/bin/ls -a* -q -C\n");
    exit(1);
}

#define BUF_SZ  (65536)
#define LKM_PATH "/sys/module/%s/parameters/control_trace"
char g_control[512] = "/sys/module/smith/parameters/control_trace";

int main(int argc, char *argv[])
{
    struct ring_stat start = {0}, now = {0}, last;
    int interval = 5, c, cont = 0;

    while (c = getopt(argc, argv, "HhQqI:i:A:a:D:d:Cc")) {
        if (argc <= 1 || c == -1 || c == '?')
            break;
        switch (c) {
        case 'D':
        case 'd':
            if (!optarg)
                help(argv[0]);
            if (optarg[0] == '/')
                snprintf(g_control, sizeof(g_control), "%s", optarg);
            else
                snprintf(g_control, sizeof(g_control), LKM_PATH, optarg);
            break;
        case 'Q':
        case 'q':
            g_tb_quiet = 1;
            break;
        case 'C':
        case 'c':
            cont = 1;
            break;
        case 'H':
        case 'h':
            help(argv[0]);
            break;
        }
    }

    if (c == '?' || optind < argc) {
        printf("%s unknown option: %s\n", argv[0], argv[optind]);
        help(argv[0]);
    }

    optind = 0;
    while (c = getopt(argc, argv, "HhQqI:i:A:a:D:d:Cc")) {
        if (argc <= 1 || c == -1 || c == '?')
            break;
        switch (c) {
        case 'D':
        case 'd':
            /* to be ignored */
            break;
        case 'Q':
        case 'q':
            break;
        case 'i':
        case 'I':
            if (optarg)
                interval = atoi(optarg);
            else
                help(argv[0]);
            break;
        case 'A':
        case 'a':
        {
            char *buf = malloc(BUF_SZ);
            if (!optarg)
                help(argv[0]);
            if (!buf) {
                ac_process(RING_KMOD, g_control, optarg, strlen(optarg), 1);
            } else {
                memset(buf, 0, BUF_SZ);
                strncpy(buf, optarg, BUF_SZ);
                ac_process(RING_KMOD, g_control, buf, BUF_SZ, g_tb_quiet);
                free(buf);
            }
            if (cont > 0)
                cont++;
            else
                cont--;
            break;
        }
        case 'C':
        case 'c':
            break;
        case 'H':
        case 'h':
            help(argv[0]);
            break;
        }
    }

    if (cont < 0)
        goto errorout;

    if (tb_init_ring(RING_KMOD, g_control)) {
        printf("failed to query trace: %s.\n", g_control);
        return -1;
    }

    /* testing md5 blocklist */
    process_block_md5("md5.json");

    /* testing exe/cmd blocklist */
    process_block_exe("exe1.json");
    process_block_exe("exe2.json");
    ac_clear(BL_JSON_EXE);
    process_block_exe("exe1.json");

    psad_set_ip4();
    psad_set_ip6();

    /* reset to check the replacing */
    psad_set_ip4();
    psad_set_ip6();

    printf("mode: %s\tinterval: %d seconds\n", g_tb_quiet ? "quiet" : "noisy", interval);
    interval = interval * 1000000; /* second to us */

    tb_stat_ring(&start);
    last = start;

    /* do consuming */
    signal(SIGINT, tb_sigint_catch);
    while (!g_tb_exit) {
        c = tb_read_ring(g_tb_msg, MSG_SLOT_LEN,
                         tb_cont, (int *)&g_tb_exit);
        if (c > 0 && !g_tb_quiet)
            tb_show_message(g_tb_msg, c);

        if (tb_is_passed(&last.tv, interval)) {
            tb_stat_ring(&now);
            tb_show_ring(&start, &last, &now);
            tb_show_ring(&start, &start, &now);
            last = now;
        }
    }
    printf("\n\nSummary:\n");
    tb_stat_ring(&now);
    tb_show_ring(&start, &start, &now);

errorout:
    tb_fini_ring();
    return 0;
}
