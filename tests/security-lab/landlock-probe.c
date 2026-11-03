// Minimal Landlock exec probe.
//
// Reproduces the anomaly observed during the Vorynex Tier 0 milestone: a
// Landlock rule granting EXECUTE on a subdirectory did not permit executing
// files inside it on kernel 7.2.8 (local) or 7.0.0-azure (CI), while a rule on
// /usr (or /) did. This is a standalone C program so the result is independent
// of the Go implementation.
//
// Build: clang -o landlock-probe landlock-probe.c
// Usage: ./landlock-probe <dir-to-grant-rx> <binary-to-exec>
//
// Prints "RAN" (exec permitted) or "DENIED" (exec blocked).

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/landlock.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <dir> <binary>\n", argv[0]);
        return 2;
    }
    const char *dir = argv[1];
    const char *target = argv[2];

    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        fprintf(stderr, "landlock unavailable: abi=%d\n", abi);
        return 2;
    }

    struct landlock_ruleset_attr rs = {0};
    rs.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
                           LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_WRITE_FILE |
                           LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR |
                           LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR;
    int fd = syscall(SYS_landlock_create_ruleset, &rs, sizeof(rs), 0);
    if (fd < 0) { perror("landlock_create_ruleset"); return 2; }

    struct landlock_path_beneath_attr pb = {0};
    pb.allowed_access = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
                        LANDLOCK_ACCESS_FS_READ_DIR;
    pb.parent_fd = open(dir, O_PATH | O_CLOEXEC);
    if (pb.parent_fd < 0) { perror("open"); return 2; }
    if (syscall(SYS_landlock_add_rule, fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0)) {
        perror("landlock_add_rule");
        return 2;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("prctl"); return 2; }
    if (syscall(SYS_landlock_restrict_self, fd, 0)) { perror("landlock_restrict_self"); return 2; }
    close(fd);

    execl(target, target, "-c", "echo RAN", NULL);
    printf("DENIED (abi=%d, rule dir=%s, target=%s)\n", abi, dir, target);
    return 1;
}
