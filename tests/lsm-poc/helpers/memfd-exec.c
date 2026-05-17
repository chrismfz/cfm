/*
 * memfd-exec — fileless ELF loader.
 *
 * Threat scenario: an attacker has code-exec inside a web worker and
 * wants to run a payload without ever touching disk. The classic
 * pattern: memfd_create() an anonymous file in tmpfs, write the ELF
 * bytes, fexecve() the fd. There is no path on disk that scanners or
 * forensics can examine — the inode lives only in the kernel's
 * tmpfs cache, identified by the dentry name "memfd:<tag>".
 *
 * CFML-EXEC-001 catches the exec at bprm_check_security by spotting
 * the tmpfs superblock + memfd: dentry-name pair on bprm->file.
 *
 * Usage: memfd-exec /path/to/host/binary [args...]
 *
 * Copies the host binary's bytes into a memfd and execs the memfd.
 * The host binary is just a vehicle — pick anything tiny and harmless
 * like /usr/bin/id or /bin/echo. The point is to demonstrate that
 * the resulting execve carries a memfd: backing inode.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static int do_memfd_create(const char *name, unsigned int flags)
{
    return (int)syscall(SYS_memfd_create, name, flags);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s /path/to/host/binary [args...]\n", argv[0]);
        return 2;
    }
    const char *host = argv[1];

    int src = open(host, O_RDONLY | O_CLOEXEC);
    if (src < 0) {
        perror("open host");
        return 1;
    }
    struct stat st;
    if (fstat(src, &st) < 0) {
        perror("fstat");
        return 1;
    }

    int mfd = do_memfd_create("cfm-poc-fileless", MFD_CLOEXEC);
    if (mfd < 0) {
        perror("memfd_create");
        return 1;
    }

    char buf[64 * 1024];
    ssize_t n;
    off_t copied = 0;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        char *p = buf;
        while (n > 0) {
            ssize_t w = write(mfd, p, (size_t)n);
            if (w < 0) {
                perror("write memfd");
                return 1;
            }
            p += w; n -= w; copied += w;
        }
    }
    if (n < 0) {
        perror("read host");
        return 1;
    }
    close(src);

    if (copied != st.st_size) {
        fprintf(stderr, "short copy: %ld of %ld bytes\n",
                (long)copied, (long)st.st_size);
        return 1;
    }

    /* fexecve via the explicit /proc path so we work on every kernel
     * regardless of glibc fexecve packaging. The kernel still sees
     * the memfd's tmpfs+memfd: identity in bprm->file. */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", mfd);

    /* Build child argv: shift past helper-name + host-binary. */
    char **child_argv = &argv[2];
    if (argc == 2) {
        /* No args given — pass just the binary name. */
        static char *defv[] = { (char *)"cfm-poc-fileless", NULL };
        child_argv = defv;
    }

    execv(proc_path, child_argv);
    perror("execv memfd");
    return 1;
}
