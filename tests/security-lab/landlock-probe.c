// Landlock exec-semantics probe.
//
// A small, standalone way to check what a host's kernel actually requires to
// execute a binary under Landlock. It helped find that executing a dynamically
// linked binary needs EXECUTE on the ELF interpreter's directory too
// (e.g. /lib64), not just the binary's own directory.
//
// Build: clang -o landlock-probe landlock-probe.c
// Usage: ./landlock-probe <binary> <dir-to-grant-rx> [more dirs...]
//
// Prints "RAN" (exec permitted) or "DENIED".
//
// Examples:
//   ./landlock-probe /usr/bin/bash /usr/bin            -> DENIED  (interpreter
//                                                         not executable)
//   ./landlock-probe /usr/bin/bash /usr/bin /lib64     -> RAN

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/landlock.h>

static void grant(int ruleset_fd, const char *dir) {
    struct landlock_path_beneath_attr pb = {0};
    pb.allowed_access = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
                        LANDLOCK_ACCESS_FS_READ_DIR;
    pb.parent_fd = open(dir, O_PATH | O_CLOEXEC);
    if (pb.parent_fd < 0) { perror(dir); return; }
    if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0))
        perror("landlock_add_rule");
    close(pb.parent_fd);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <binary> <dir> [more dirs...]\n", argv[0]);
        return 2;
    }
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) { fprintf(stderr, "landlock unavailable (abi=%d)\n", abi); return 2; }

    struct landlock_ruleset_attr rs = {0};
    rs.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
                           LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_WRITE_FILE |
                           LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR |
                           LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR;
    int fd = syscall(SYS_landlock_create_ruleset, &rs, sizeof(rs), 0);
    if (fd < 0) { perror("landlock_create_ruleset"); return 2; }

    for (int i = 2; i < argc; i++) grant(fd, argv[i]);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("prctl"); return 2; }
    if (syscall(SYS_landlock_restrict_self, fd, 0)) { perror("landlock_restrict_self"); return 2; }
    close(fd);

    execl(argv[1], argv[1], "-c", "echo RAN", NULL);
    printf("DENIED (abi=%d)\n", abi);
    return 1;
}
