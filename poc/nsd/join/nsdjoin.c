// nsdjoin — put a new process into an already-running sandbox's namespaces.
//
// usage: nsdjoin TARGET_PID DROP_CAPS(0|1) CMD [ARGS...]
//
// Why this is C and not Go: setns(2) with CLONE_NEWUSER requires the caller to
// be single-threaded, and the Go runtime is multithreaded before main() runs.
// The production shapes are the same three anyone else uses — a cgo constructor
// (runc's nsexec), a re-exec through a tiny static helper (this file), or
// nsenter(1). None of them is "call setns from Go".
//
// The capability story is the entire security argument for this file:
// joining a user namespace via setns grants the joiner a FULL capability set in
// it. A process that attaches to a sandbox and does not drop them is CAP_SYS_ADMIN
// inside a sandbox whose payload has none.

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/capability.h>

static int join(pid_t pid, const char *kind, int nstype) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/ns/%s", (int)pid, kind);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "JOIN-FAIL open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (setns(fd, nstype) < 0) {
        fprintf(stderr, "JOIN-FAIL setns %s: %s\n", kind, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int drop_all_caps(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "DROP-FAIL no_new_privs: %s\n", strerror(errno));
        return -1;
    }
    for (int c = 0; c <= 63; c++) {
        // EINVAL simply means the kernel does not know that capability.
        if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) < 0 && errno != EINVAL) {
            fprintf(stderr, "DROP-FAIL capbset %d: %s\n", c, strerror(errno));
            return -1;
        }
    }
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof(data));
    if (syscall(SYS_capset, &hdr, data) < 0) {
        fprintf(stderr, "DROP-FAIL capset: %s\n", strerror(errno));
        return -1;
    }
    // Ambient set follows permitted, but be explicit.
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0 && errno != EINVAL) {
        fprintf(stderr, "DROP-FAIL ambient: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

// The order is not a style choice — it is the whole trick. MEASURED on this
// host: bwrap creates TWO user namespaces. The mount, pid, ipc, uts and cgroup
// namespaces are owned by the FIRST one (where bwrap does its setup as root);
// the payload runs in the SECOND, a child of it, so that the sandbox cannot
// touch the uid_map or the mounts of the namespace that built it.
//
// setns into a non-user namespace needs CAP_SYS_ADMIN in the user namespace that
// OWNS it. P1 has that over both, by the ancestor rule — but only while it is
// still in U. Join the payload's user namespace first and you drop into a
// grandchild that has no authority over its own grandparent's mounts:
//
//     JOIN-FAIL setns mnt: Operation not permitted
//
// So: every non-user namespace first, using P1's ancestor authority, and the
// user namespace last.
static const char *default_order = "mnt,pid,ipc,uts,net,cgroup,user";

struct nsdef {
    const char *name;
    int flag;
};
static const struct nsdef ALL[] = {
    {"user", CLONE_NEWUSER}, {"mnt", CLONE_NEWNS},   {"pid", CLONE_NEWPID},
    {"ipc", CLONE_NEWIPC},   {"uts", CLONE_NEWUTS},  {"net", CLONE_NEWNET},
    {"cgroup", CLONE_NEWCGROUP}, {NULL, 0},
};

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: nsdjoin PID DROPCAPS CMD [ARGS...]\n");
        return 2;
    }
    pid_t target = (pid_t)atoi(argv[1]);
    int dropcaps = atoi(argv[2]);

    const char *order = getenv("NSDJOIN_ORDER");
    if (!order || !*order) order = default_order;
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", order);

    // Every descriptor is opened BEFORE the first setns. After joining the
    // sandbox's mount namespace, /proc is the sandbox's own — a different pid
    // namespace, where the target's pid number means something else entirely.
    int fds[8];
    int flags[8];
    int n = 0;
    for (char *tok = strtok(buf, ","); tok && n < 8; tok = strtok(NULL, ",")) {
        int flag = 0;
        for (int i = 0; ALL[i].name; i++)
            if (!strcmp(ALL[i].name, tok)) flag = ALL[i].flag;
        if (!flag) {
            fprintf(stderr, "JOIN-FAIL unknown namespace %s\n", tok);
            return 2;
        }
        char path[128];
        snprintf(path, sizeof(path), "/proc/%d/ns/%s", (int)target, tok);
        fds[n] = open(path, O_RDONLY | O_CLOEXEC);
        if (fds[n] < 0) {
            fprintf(stderr, "JOIN-FAIL open %s: %s\n", path, strerror(errno));
            return 3;
        }
        flags[n] = flag;
        n++;
    }
    for (int i = 0; i < n; i++) {
        if (setns(fds[i], flags[i]) < 0) {
            fprintf(stderr, "JOIN-FAIL setns #%d flag=0x%x: %s\n", i, flags[i], strerror(errno));
            return 3;
        }
        close(fds[i]);
    }

    if (dropcaps && drop_all_caps() < 0) return 4;

    // setns(CLONE_NEWPID) moves only our CHILDREN into the target pid
    // namespace, so the exec has to happen after a fork.
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "JOIN-FAIL fork: %s\n", strerror(errno));
        return 5;
    }
    if (child == 0) {
        execvp(argv[3], &argv[3]);
        fprintf(stderr, "JOIN-FAIL exec %s: %s\n", argv[3], strerror(errno));
        _exit(127);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) return 6;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 128 + WTERMSIG(status);
}
