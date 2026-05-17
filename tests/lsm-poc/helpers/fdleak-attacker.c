/*
 * fdleak-attacker — the unprivileged side of the FS-006 PoC.
 *
 * Threat scenario: a setuid helper opened /etc/shadow as root, then
 * dropped privs (typical pattern for any helper that needs to read
 * shadow but should not stay root). The opened fd survives the priv
 * drop because struct file's f_cred was captured at open(2) time and
 * is never updated. If a non-root task later reads through that fd,
 * the kernel sees cur_euid != 0 but file->f_cred->euid == 0 — the
 * canonical fd-leak fingerprint.
 *
 * The harness sets up the victim side in fs-006-fdleak.sh: a small
 * privileged helper opens /etc/shadow, drops to TEST_UID, then
 * read()s from the open fd. CFML-FS-006 fires.
 *
 * This file builds a standalone victim that combines both steps,
 * because doing it in a single binary is the most reliable cross-
 * kernel approach (we don't need to chase the pidfd_getfd race
 * which depends on ptrace_scope state).
 *
 * Usage: fdleak-attacker SENSITIVE_PATH DROP_UID
 *   SENSITIVE_PATH must be in the cfm-lsm watched-inodes map
 *   (/etc/shadow, /etc/sudoers, /root/.ssh/id_*, etc).
 *   DROP_UID is the non-root uid to setuid into before reading.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s SENSITIVE_PATH DROP_UID\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    uid_t drop_uid = (uid_t)strtoul(argv[2], NULL, 10);
    if (drop_uid == 0) {
        fprintf(stderr, "DROP_UID must be non-root\n");
        return 2;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "must run as root so the open(2) f_cred is root\n");
        return 2;
    }

    /* Step 1: open as root. f_cred is captured here. */
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    /* Step 2: drop privileges entirely. setresuid with all three
     * arguments equal kills the saved-uid escape hatch, so the task
     * is genuinely a non-root euid from the kernel's POV. */
    if (setresuid(drop_uid, drop_uid, drop_uid) < 0) {
        perror("setresuid");
        return 1;
    }
    if (geteuid() == 0) {
        fprintf(stderr, "setresuid did not take effect\n");
        return 1;
    }

    /* Step 3: read through the still-open fd. file_permission fires;
     * cur_euid != 0 (we just dropped) and f_cred->euid == 0 — the
     * exact FS-006 trigger condition. */
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {
        perror("read");
        return 1;
    }
    /* Don't print the bytes — we don't care about the contents, just
     * that read() succeeded and the LSM hook saw the cred mismatch. */
    fprintf(stderr, "fdleak: read %zd bytes through root-opened fd as uid=%u\n",
            n, drop_uid);
    close(fd);
    return 0;
}
