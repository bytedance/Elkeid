
#define _FILE_OFFSET_BITS 64
#define _TIME_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <linux/limits.h>

#define BLOCKSZ 512

#define SAFE_BOOT_MAGIC ((uint32_t)0x42534442)
struct elkeid_safe_boot {
	uint32_t     magic;
	uint32_t     flags;
	uint32_t     limits;
	uint32_t     nboots;
	union {
	    uint64_t timestamp;
	    uint64_t bootts[61];
	};
};

static char *safeboot_build_path(char *name)
{
    char dir[PATH_MAX] = {0}, *parent, *path = NULL;
    ssize_t count = readlink("/proc/self/exe", dir, PATH_MAX);

    if (count == -1)
       goto errout;
    parent = dirname(dir);
    if (!parent)
	goto errout;
    path = (char *)malloc(PATH_MAX);
    if (!path)
	goto errout;
    strncpy(path, parent, PATH_MAX - 1);
    strncat(path, "/", PATH_MAX - 1);
    strncat(path, name, PATH_MAX - 1);

errout:
    return path;
}

static time_t safeboot_query_time(void)
{
    struct timeval now = {0};

    gettimeofday(&now, NULL);
    return now.tv_sec;
}

int safeboot_check(void)
{
    char dat[BLOCKSZ] = {0};
    char *path = NULL;
    struct stat st = {0};
    struct elkeid_safe_boot *sb = (void *)dat;
    int fd = -1, invalid = 1;

    path = safeboot_build_path("safeboot.dat");
    if (!path)
	goto errout;

    fd = open(path, O_RDWR | O_SYNC |  O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0)
	goto errout;

    fstat(fd, &st);
    if (st.st_size >= BLOCKSZ) {
        time_t now;
        size_t count;
        lseek(fd, 0, SEEK_SET);
        count = read(fd, dat, BLOCKSZ);
        if (count < BLOCKSZ)
            goto create;
        if (sb->magic != SAFE_BOOT_MAGIC)
            goto create;
        now = safeboot_query_time();
        if (sb->timestamp > now)
            goto create;
        /* just incremented less than 1 minute ago */
        if (sb->timestamp + 60 - 1 >= now)
            goto errout;
        sb->nboots++;
        memmove(&sb->bootts[1], &sb->bootts[0], 60*8);
        sb->timestamp = safeboot_query_time();
        lseek(fd, 0, SEEK_SET);
        write(fd, dat, BLOCKSZ);
        fsync(fd);
        invalid = 0;
    }

create:
    if (invalid) {
        sb->magic = SAFE_BOOT_MAGIC;
        sb->flags = 0;
        sb->limits = 3;
        sb->nboots = 1;
        sb->timestamp = safeboot_query_time();
        lseek(fd, 0, SEEK_SET);
        write(fd, dat, BLOCKSZ);
        fsync(fd);
    }

errout:
    if (fd >= 0)
        close(fd);
    if (path)
        free(path);

    return (sb->nboots <= sb->limits);
}

int safeboot_clear(void)
{
    char dat[BLOCKSZ] = {0};
    char *path = NULL;
    struct stat st = {0};
    struct elkeid_safe_boot *sb = (void *)dat;
    int fd = -1, invalid = 1, rc;

    path = safeboot_build_path("safeboot.dat");
    if (!path)
        goto errout;

    fd = open(path, O_RDWR | O_SYNC |  O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        rc = unlink(path);
        goto errout;
    }
    fstat(fd, &st);
    if (st.st_size >= BLOCKSZ) {
        size_t  count;
        lseek(fd, 0, SEEK_SET);
        count = read(fd, dat, BLOCKSZ);
        if (count < BLOCKSZ)
            goto create;
        if (sb->magic != SAFE_BOOT_MAGIC)
            goto create;
        if (sb->timestamp > safeboot_query_time())
            goto create;
        sb->nboots = 0;
        sb->timestamp |= (uint64_t)0x8000000000000000;
        memmove(&sb->bootts[1], &sb->bootts[0], 60*8);
        sb->timestamp = safeboot_query_time();
        lseek(fd, 0, SEEK_SET);
        write(fd, dat, BLOCKSZ);
        fsync(fd);
        invalid = 0;
        rc = 0;
    }

create:
    if (invalid) {
        sb->magic = SAFE_BOOT_MAGIC;
        sb->flags = 0;
        sb->limits = 3;
        sb->nboots = 0;
        sb->timestamp = safeboot_query_time();
        lseek(fd, 0, SEEK_SET);
        write(fd, dat, BLOCKSZ);
        fsync(fd);
        rc = 0;
    }

errout:
    if (fd >= 0)
        close(fd);
    if (path)
        free(path);
    return rc;
}