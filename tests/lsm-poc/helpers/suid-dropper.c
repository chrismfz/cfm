/*
 * suid-dropper — non-root → root via CAP_SETUID file capability.
 *
 * Threat scenario: realistic Linux post-exploit persistence. After
 * gaining root once (via any privesc bug), the attacker drops a
 * helper binary with `setcap cap_setuid+ep` (file capabilities) into
 * a writeable directory. Subsequent unprivileged shells can run the
 * helper and call setuid(0) — the file capability satisfies the
 * kernel's CAP_SETUID check without the binary ever having the
 * traditional setuid bit. This pattern is harder to spot than the
 * old `chmod 4755 /tmp/.sh` trick: `ls -l` shows mode 0755, no leading
 * `s`, only `getcap` reveals the privilege; many ad-hoc auditing
 * scripts only look for setuid-bit binaries.
 *
 * Why setuid bit alone does NOT trigger CFML-CRED-002:
 *   - execve sees the setuid bit and calls bprm_creds_for_exec to
 *     update the new process's creds (euid -> binary owner).
 *   - task_fix_setuid is the LSM hook for the setuid SYSCALL family
 *     (setuid / setresuid / setreuid). It is NOT called from execve's
 *     suid-bit handling.
 *   - By the time the binary's main() runs setuid(0), the process's
 *     euid is already 0 from the suid-bit elevation. task_fix_setuid
 *     fires with new_euid=0 AND old_euid=0 → CRED-002 returns early
 *     because old_euid==0 means "already root, not an escalation".
 *
 * Why cap_setuid+ep DOES trigger CFML-CRED-002:
 *   - execve does NOT change euid (no setuid bit). Process starts
 *     with euid=cfmpoc but with CAP_SETUID in its effective set.
 *   - main() calls setuid(0). Kernel checks CAP_SETUID — present.
 *     Allows the call.
 *   - task_fix_setuid fires with new_euid=0, old_euid=cfmpoc — the
 *     canonical CFML-CRED-002 fingerprint.
 *
 * The dropper does setuid(0) then execv /bin/id so the operator can
 * confirm "yes, that PoC really did gain root". /bin/id IS in
 * setuid_inodes (it's in the disk-walk roots) so it won't itself
 * fire CRED-002 a second time.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    if (geteuid() == 0) {
        fprintf(stderr, "suid-dropper: already root before setuid(0); "
                        "the harness ran me with the wrong identity\n");
        return 1;
    }

    /* setuid(0) succeeds because cap_setuid+ep is in our effective
     * capability set (file caps applied via `setcap` by the harness).
     * This is the non-root → root transition the LSM hook sees. */
    if (setuid(0) < 0) {
        perror("setuid(0)");
        fprintf(stderr, "suid-dropper: cap_setuid file capability missing? "
                        "check `getcap` on this binary\n");
        return 1;
    }

    fprintf(stderr, "suid-dropper: now uid=%u euid=%u (CRED-002 fired above)\n",
            (unsigned)getuid(), (unsigned)geteuid());
    char *exec_argv[] = { (char *)"id", NULL };
    execv("/bin/id", exec_argv);
    perror("execv /bin/id");
    return 1;
}
