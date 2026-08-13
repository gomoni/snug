// nsowner — for each namespace of a pid, print the user namespace that owns it.
//
// This is the fact that decides whether "attach" is possible at all: setns(2)
// into a non-user namespace requires CAP_SYS_ADMIN in the user namespace that
// OWNS that namespace, which is not necessarily the user namespace the target
// process is currently in.
//
// usage: nsowner PID

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef NS_GET_USERNS
#define NSIO 0xb7
#define NS_GET_USERNS _IO(NSIO, 0x1)
#define NS_GET_PARENT _IO(NSIO, 0x2)
#endif

static void describe(int fd, char *out, size_t n) {
    struct stat st;
    if (fstat(fd, &st) < 0) {
        snprintf(out, n, "?");
        return;
    }
    snprintf(out, n, "[%lu]", (unsigned long)st.st_ino);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: nsowner PID\n");
        return 2;
    }
    const char *kinds[] = {"user", "mnt", "pid", "net", "ipc", "uts", "cgroup", NULL};
    for (int i = 0; kinds[i]; i++) {
        char path[128], self[64] = "?", owner[64] = "?";
        snprintf(path, sizeof(path), "/proc/%s/ns/%s", argv[1], kinds[i]);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            printf("%-7s open: %s\n", kinds[i], strerror(errno));
            continue;
        }
        describe(fd, self, sizeof(self));
        int ufd = ioctl(fd, NS_GET_USERNS);
        if (ufd < 0) {
            snprintf(owner, sizeof(owner), "NS_GET_USERNS: %s", strerror(errno));
        } else {
            describe(ufd, owner, sizeof(owner));
            close(ufd);
        }
        printf("%-7s ns=%-14s owned-by-userns=%s\n", kinds[i], self, owner);
        close(fd);
    }
    return 0;
}
