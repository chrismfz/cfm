/*
 * knob-writer — write a sentinel value to a /proc/sys or /sys file.
 *
 * Threat scenario: kernel-exploit completion. After any write-
 * primitive bug, the next step is to pivot through one of the
 * "magic" /proc/sys or /sys knobs that gives the writer code-exec
 * on the next triggering event:
 *
 *   /proc/sys/kernel/core_pattern   — pipe-to-program on coredump
 *   /proc/sys/kernel/modprobe_path  — substitute modprobe binary
 *   /proc/sysrq-trigger             — magic sysrq arbitrary action
 *   /sys/kernel/uevent_helper       — modern uevent helper
 *
 * The scenario renames this binary to a non-trusted comm (anything
 * that's NOT cfm / sysctl / systemd / systemd-sysctl) so the BPF
 * program's trusted-writer allowlist doesn't suppress the event.
 *
 * CFML-FS-008's file_permission hook fires on the write — emits
 * an event with the comm and the basename of the knob path.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s KNOB_PATH VALUE\n", argv[0]);
        return 2;
    }
    int fd = open(argv[1], O_WRONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    ssize_t n = write(fd, argv[2], strlen(argv[2]));
    int werr = (n < 0) ? errno : 0;
    close(fd);
    if (n < 0) {
        errno = werr;
        perror("write");
        return 1;
    }
    return 0;
}
