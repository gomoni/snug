// nsdgraft — nsdmount, generalised to SEVERAL grafts and instrumented, so that
// the collision between a graft and a grant can be measured rather than argued.
//
// usage: nsdgraft [-r] [-d] PID SRC:DST [SRC:DST ...] -- CMD [ARGS...]
//
//   -r  try to clear MS_RDONLY on "/" in the DERIVED view before mkdir.
//       snug's sandbox root is a read-only tmpfs (`--remount-ro /`), so a graft
//       whose destination does not already exist cannot even be created without
//       this. That is a result, not a nuisance: see run-graft.sh G1/G2.
//   -d  drop every capability before exec, so the command in the derived view
//       runs with the authority a payload has rather than the stage's.
//
// It differs from nsdmount.c in three ways, all of them so that a FAILED graft
// is data instead of an early exit:
//
//   1. every graft reports open_tree / mkdir / move_mount separately, on stdout,
//      as a line beginning GRAFT= — so a shell can assert on the outcome;
//   2. a failed graft does not stop the others, and does not stop the exec. The
//      question "what does the derived view look like when a graft did not
//      land" is exactly the question a supervisor has to answer;
//   3. all sources are open_tree'd BEFORE the setns, for the same reason
//      nsdjoin.c opens all seven namespace fds first: after setns(CLONE_NEWNS)
//      the host paths are simply not there any more.
//
// Everything else — open_tree(OPEN_TREE_CLONE), setns without joining the user
// namespace, unshare + MS_REC|MS_PRIVATE, move_mount — is nsdmount.c's sequence
// unchanged, because that is the sequence under test.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

#define MAXG 16

static int open_tree_(int dfd, const char *path, unsigned int flags) {
    return (int)syscall(SYS_open_tree, dfd, path, flags);
}
static int move_mount_(int from_dfd, const char *from, int to_dfd, const char *to,
                       unsigned int flags) {
    return (int)syscall(SYS_move_mount, from_dfd, from, to_dfd, to, flags);
}

static int drop_all_caps(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    for (int c = 0; c <= 63; c++)
        if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) < 0 && errno != EINVAL) return -1;
    struct __user_cap_header_struct hdr = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof(data));
    if (syscall(SYS_capset, &hdr, data) < 0) return -1;
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0 && errno != EINVAL) return -1;
    return 0;
}

int main(int argc, char **argv) {
    int remount_rw = 0, dropcaps = 0, i = 1;
    for (; i < argc && argv[i][0] == '-' && argv[i][1] != '-'; i++) {
        if (!strcmp(argv[i], "-r")) remount_rw = 1;
        else if (!strcmp(argv[i], "-d")) dropcaps = 1;
        else { fprintf(stderr, "nsdgraft: unknown flag %s\n", argv[i]); return 2; }
    }
    if (i >= argc) { fprintf(stderr, "usage: nsdgraft [-r] [-d] PID SRC:DST ... -- CMD\n"); return 2; }
    pid_t target = (pid_t)atoi(argv[i++]);

    char *src[MAXG], *dst[MAXG];
    int fd[MAXG], n = 0;
    for (; i < argc && strcmp(argv[i], "--"); i++) {
        char *colon = strchr(argv[i], ':');
        if (!colon || n >= MAXG) { fprintf(stderr, "nsdgraft: bad graft %s\n", argv[i]); return 2; }
        *colon = '\0';
        src[n] = argv[i];
        dst[n] = colon + 1;
        n++;
    }
    if (i >= argc || strcmp(argv[i], "--")) { fprintf(stderr, "nsdgraft: missing --\n"); return 2; }
    i++;
    if (i >= argc) { fprintf(stderr, "nsdgraft: missing command\n"); return 2; }

    // 1. Clone every host subtree while the host tree is still visible.
    for (int g = 0; g < n; g++) {
        fd[g] = open_tree_(AT_FDCWD, src[g], OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE);
        if (fd[g] < 0)
            printf("GRAFT=%s open_tree=ERR:%s\n", dst[g], strerror(errno));
    }

    // 2. Adopt the sandbox's view. The user namespace is deliberately NOT joined.
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", (int)target);
    int nsfd = open(path, O_RDONLY | O_CLOEXEC);
    if (nsfd < 0 || setns(nsfd, CLONE_NEWNS) < 0) {
        printf("GRAFT-FAIL setns mnt: %s\n", strerror(errno));
        return 3;
    }
    close(nsfd);

    // 3. Our own copy of it: invisible to the sandbox from here on.
    if (unshare(CLONE_NEWNS) < 0 || mount("", "/", "", MS_REC | MS_PRIVATE, NULL) < 0) {
        printf("GRAFT-FAIL private: %s\n", strerror(errno));
        return 3;
    }

    // 4. Optionally make the derived root writable. snug remounts / read-only,
    //    and MS_RDONLY is a per-mount flag the copy inherits.
    if (remount_rw) {
        if (mount("", "/", "", MS_REMOUNT | MS_BIND, NULL) < 0)
            printf("ROOTRW=ERR:%s\n", strerror(errno));
        else
            printf("ROOTRW=OK\n");
    }

    // 5. Graft.
    for (int g = 0; g < n; g++) {
        if (fd[g] < 0) continue;
        const char *mk = "OK";
        if (mkdir(dst[g], 0700) < 0) {
            if (errno == EEXIST) mk = "EEXIST";
            else {
                printf("GRAFT=%s mkdir=ERR:%s\n", dst[g], strerror(errno));
                continue;
            }
        }
        if (move_mount_(fd[g], "", AT_FDCWD, dst[g], MOVE_MOUNT_F_EMPTY_PATH) < 0) {
            printf("GRAFT=%s mkdir=%s move_mount=ERR:%s\n", dst[g], mk, strerror(errno));
            continue;
        }
        printf("GRAFT=%s mkdir=%s move_mount=OK\n", dst[g], mk);
        close(fd[g]);
    }
    fflush(stdout);

    if (dropcaps && drop_all_caps() < 0) {
        fprintf(stderr, "GRAFT-FAIL dropcaps: %s\n", strerror(errno));
        return 4;
    }

    execvp(argv[i], &argv[i]);
    fprintf(stderr, "GRAFT-FAIL exec %s: %s\n", argv[i], strerror(errno));
    return 127;
}
