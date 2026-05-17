/*
 * deleted-exec — drop, unlink, exec.
 *
 * Threat scenario: webshell wants to run a binary but cover its tracks.
 * The trick is: open the binary for reading, unlink the path from the
 * filesystem, then fexecve() the still-open fd. The inode's i_nlink
 * drops to 0 but the kernel keeps the inode alive while the fd is
 * referenced. To a forensic investigator after the fact, there is no
 * binary on disk to recover.
 *
 * CFML-EXEC-004 catches the exec at bprm_check_security by spotting
 * either an unlinked inode (i_nlink == 0) or an unhashed dentry
 * (d_hash.pprev == NULL) on bprm->file, when the calling uid is in
 * cfm_watched_uids.
 *
 * Usage: deleted-exec STAGE_DIR /path/to/source/binary [args...]
 *
 * Copies the source binary into a fresh STAGE_DIR/.cfmpoc-XXXXXX
 * file, opens it, unlinks the path, then execs the open fd. The
 * harness passes SCRATCH_DIR (typically /var/lib/cfmpoc/) as STAGE_DIR
 * so the staged file lives on an exec-capable mount; passing /tmp on
 * a hardened host (noexec) makes the final execve fail before the
 * LSM hook even runs.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s STAGE_DIR /path/to/source/binary [args...]\n", argv[0]);
        return 2;
    }
    const char *stage_dir = argv[1];
    const char *src_path = argv[2];

    /* Build the template inside STAGE_DIR rather than hard-coding /tmp,
     * because /tmp is noexec on hardened EL10 hosts. */
    char tmp_path[PATH_MAX];
    int written = snprintf(tmp_path, sizeof(tmp_path), "%s/.cfmpoc-deleted-XXXXXX", stage_dir);
    if (written <= 0 || written >= (int)sizeof(tmp_path)) {
        fprintf(stderr, "STAGE_DIR too long\n");
        return 2;
    }
    int tmp = mkstemp(tmp_path);
    if (tmp < 0) { perror("mkstemp"); return 1; }
    if (fchmod(tmp, 0700) < 0) { perror("fchmod"); return 1; }

    int src = open(src_path, O_RDONLY);
    if (src < 0) { perror("open source"); return 1; }

    char buf[64 * 1024];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        char *p = buf;
        while (n > 0) {
            ssize_t w = write(tmp, p, (size_t)n);
            if (w < 0) { perror("write tmp"); return 1; }
            p += w; n -= w;
        }
    }
    if (n < 0) { perror("read src"); return 1; }
    close(src);
    close(tmp);

    /* Re-open the staged file for read+exec, then unlink the path
     * before exec'ing. The fd keeps the inode alive but the dentry is
     * unhashed and i_nlink drops to 0 — exactly the EXEC-004
     * fingerprint. */
    int fd = open(tmp_path, O_RDONLY);
    if (fd < 0) { perror("re-open tmp"); return 1; }

    if (unlink(tmp_path) < 0) { perror("unlink"); return 1; }

    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);

    char **child_argv = &argv[3];
    if (argc == 3) {
        static char *defv[] = { (char *)"cfm-poc-deleted", NULL };
        child_argv = defv;
    }
    execv(proc_path, child_argv);
    perror("execv deleted");
    return 1;
}
