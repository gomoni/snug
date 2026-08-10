// nsdmount — run a command in a mount namespace DERIVED FROM THE SANDBOX'S,
// plus exactly one host path grafted in from outside.
//
// usage: nsdmount TARGET_PID HOST_SRC DEST CMD [ARGS...]
//
// This is the experiment that decides how much of the container proxy has to
// exist. If the engine's mount namespace is a copy of the SANDBOX's view rather
// than the host's, then a container bind mount can only ever name a path the
// sandbox can already see, and the proxy's bind-mount rules stop being a
// parallel implementation of the policy and start being unnecessary.
//
// The mechanism is the new mount API: open_tree(OPEN_TREE_CLONE) detaches a
// mount from the tree it was found in and hands back a descriptor. A descriptor
// does not care about mount namespaces, so it survives setns — which is the same
// property that makes a stray dirfd a complete sandbox bypass (CLAUDE.md). Here
// it is used deliberately, by the process that owns the policy, from outside.
//
// The unshare BEFORE move_mount is not optional: without it the graft lands in
// the SANDBOX's own mount namespace, and snug would be handing the payload the
// container storage.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

static int open_tree_(int dfd, const char *path, unsigned int flags) {
    return (int)syscall(SYS_open_tree, dfd, path, flags);
}
static int move_mount_(int from_dfd, const char *from, int to_dfd, const char *to,
                       unsigned int flags) {
    return (int)syscall(SYS_move_mount, from_dfd, from, to_dfd, to, flags);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: nsdmount PID HOST_SRC DEST CMD [ARGS...]\n");
        return 2;
    }
    pid_t target = (pid_t)atoi(argv[1]);
    const char *src = argv[2], *dst = argv[3];

    // 1. Clone the host subtree while we can still see it.
    int tree = open_tree_(AT_FDCWD, src,
                          OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE);
    if (tree < 0) {
        fprintf(stderr, "MOUNT-FAIL open_tree %s: %s\n", src, strerror(errno));
        return 3;
    }

    // 2. Adopt the sandbox's view. The user namespace is NOT joined: the
    //    capabilities that make the next two steps legal are the ones this
    //    process already holds in the stage's own user namespace, which is an
    //    ancestor of the one that owns these mounts.
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", (int)target);
    int nsfd = open(path, O_RDONLY | O_CLOEXEC);
    if (nsfd < 0 || setns(nsfd, CLONE_NEWNS) < 0) {
        fprintf(stderr, "MOUNT-FAIL setns mnt: %s\n", strerror(errno));
        return 3;
    }
    close(nsfd);

    // 3. Our OWN copy of it. Everything after this point is invisible to the
    //    sandbox, which is the entire safety argument.
    if (unshare(CLONE_NEWNS) < 0) {
        fprintf(stderr, "MOUNT-FAIL unshare: %s\n", strerror(errno));
        return 3;
    }
    if (mount("", "/", "", MS_REC | MS_PRIVATE, NULL) < 0) {
        fprintf(stderr, "MOUNT-FAIL make-private: %s\n", strerror(errno));
        return 3;
    }

    // 4. Graft the host subtree in. mkdir first: the destination lives on the
    //    sandbox's tmpfs root, which is writable in this private copy.
    if (mkdir(dst, 0700) < 0 && errno != EEXIST) {
        fprintf(stderr, "MOUNT-FAIL mkdir %s: %s\n", dst, strerror(errno));
        return 3;
    }
    if (move_mount_(tree, "", AT_FDCWD, dst, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
        fprintf(stderr, "MOUNT-FAIL move_mount -> %s: %s\n", dst, strerror(errno));
        return 3;
    }
    close(tree);

    execvp(argv[4], &argv[4]);
    fprintf(stderr, "MOUNT-FAIL exec %s: %s\n", argv[4], strerror(errno));
    return 127;
}
