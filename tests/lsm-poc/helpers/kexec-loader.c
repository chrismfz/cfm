/*
 * kexec-loader — invoke kexec_load(2) and kexec_file_load(2).
 *
 * Threat scenario: a rootkit-persistence installer calling
 * kexec_load(2) / kexec_file_load(2) to stage a backdoored kernel
 * image into the reserved kexec slot. The next kexec_reboot would
 * boot that image without going through firmware — defeating every
 * audit that compares the running kernel hash to its package on
 * disk.
 *
 * The CFML-EXEC-008 tracepoint fires on syscall ENTRY — before the
 * kernel does anything with the args — so we don't actually need a
 * valid kernel image. We pass deliberately bogus args; the syscall
 * will fail with -EPERM (CAP_SYS_BOOT missing or
 * kernel.kexec_load_disabled=1) or -EINVAL / -EBADF, but the
 * tracepoint already landed and emitted the event.
 *
 * The scenario renames this binary to a non-trusted comm before
 * executing so the BPF program's trusted-loader allowlist
 * (kexec / systemctl) doesn't suppress the event.
 *
 * We try kexec_file_load(/dev/null, …) first, then kexec_load(0, 0, …)
 * for coverage of the second tracepoint.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Fallback syscall numbers for hosts whose libc headers don't ship
 * the __NR_kexec_{,file_}load defines (musl, very old glibc, some
 * cross-compile environments). Numbers are arch-specific — using the
 * x86_64 values on arm64 would issue the wrong syscall (mq_open on
 * arm64), the kexec tracepoint would never fire, and the PoC would
 * silently report failure.
 *
 *   x86_64 (asm/unistd_64.h):    kexec_load=246, kexec_file_load=320
 *   arm64  (asm-generic/unistd): kexec_load=104, kexec_file_load=294
 */
#ifndef __NR_kexec_load
# if defined(__aarch64__)
#  define __NR_kexec_load 104
# else
#  define __NR_kexec_load 246
# endif
#endif
#ifndef __NR_kexec_file_load
# if defined(__aarch64__)
#  define __NR_kexec_file_load 294
# else
#  define __NR_kexec_file_load 320
# endif
#endif

int main(void)
{
    /* kexec_file_load: pass /dev/null as the kernel fd, initrd_fd=-1.
     * The tracepoint sys_enter_kexec_file_load fires before the kernel
     * validates anything, so the event lands even though the syscall
     * will return -EPERM / -EINVAL / -ENOEXEC. */
    int fd = open("/dev/null", O_RDONLY);
    if (fd >= 0) {
        long r = syscall(__NR_kexec_file_load, fd, -1, 0, "", 0);
        fprintf(stderr, "kexec_file_load returned %ld (errno=%d %s)\n",
                r, errno, strerror(errno));
        close(fd);
    }

    /* kexec_load: pass entry=0, nr_segments=0, segments=NULL, flags=0.
     * Same deal — entry tracepoint fires regardless of the syscall
     * ultimately returning -EPERM / -EINVAL. */
    long r = syscall(__NR_kexec_load, (unsigned long)0, (unsigned long)0,
                     (void *)0, (unsigned long)0);
    fprintf(stderr, "kexec_load returned %ld (errno=%d %s)\n",
            r, errno, strerror(errno));

    return 0;
}
