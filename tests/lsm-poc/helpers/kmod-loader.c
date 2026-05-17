/*
 * kmod-loader — invoke finit_module(2) on /dev/null.
 *
 * Threat scenario: a kernel-rootkit installer calling
 * init_module(2) / finit_module(2) to load a malicious .ko. The
 * CFML-EXEC-007 tracepoint fires on syscall ENTRY — before the
 * kernel has done anything with the args — so we don't actually
 * need a valid kernel module image. /dev/null as the module fd
 * makes the syscall return -ENOEXEC, but the tracepoint already
 * landed and emitted the event.
 *
 * The scenario renames this binary to a non-trusted comm before
 * executing so the BPF program's trusted-loader allowlist
 * (modprobe / insmod / kmod / systemd / systemd-modules /
 * systemd-udevd) doesn't suppress the event.
 *
 * We try finit_module(/dev/null, "", 0). If the kernel rejects it
 * before reading args, we also try init_module(NULL, 0, "") for
 * coverage of the second tracepoint.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    /* finit_module: pass /dev/null as the module fd. The tracepoint
     * sys_enter_finit_module fires before the kernel touches the
     * fd, so the event lands even though the syscall will return
     * -ENOEXEC. */
    int fd = open("/dev/null", O_RDONLY);
    if (fd >= 0) {
        long r = syscall(SYS_finit_module, fd, "", 0);
        fprintf(stderr, "finit_module returned %ld (errno=%d %s)\n",
                r, errno, strerror(errno));
        close(fd);
    }

    /* init_module: pass NULL/0. Same deal — entry tracepoint fires
     * regardless of the syscall ultimately returning -EINVAL / -EFAULT.
     * Covering both tracepoints in one helper means the operator
     * sees TWO CFML-EXEC-007 events from a single PoC run, with
     * op=init_module and op=finit_module respectively. */
    long r = syscall(SYS_init_module, NULL, 0, "");
    fprintf(stderr, "init_module returned %ld (errno=%d %s)\n",
            r, errno, strerror(errno));

    return 0;
}
