/*
 * suid-dropper — minimal setuid-root "stash binary".
 *
 * Threat scenario: classic Linux post-exploit persistence. After
 * gaining root once (via any privesc bug or stolen credential), the
 * attacker drops a setuid-root binary somewhere writeable —
 * /tmp/.<obfuscated> is the textbook spot — and chmods it 4755. Any
 * subsequent unprivileged shell can re-execute it to regain root
 * without re-exploiting the original bug. This pattern shows up in
 * incident reports under every name: "magic suid", "stash shell",
 * "backdoor binary".
 *
 * CFML-CRED-002 catches the second-use exactly. The setuid_inodes
 * BPF map is populated by walking the canonical setuid-binary roots
 * (/usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin, /bin,
 * /sbin) PLUS the operator-supplied allow_exe paths. Anything else
 * — /tmp/, /var/tmp/, /dev/shm/, /home/<user>/ — is NOT in the
 * setuid_inodes map. When a non-root user execve's such a binary
 * and the kernel auto-sets euid=0 from the setuid bit, task_fix_setuid
 * fires with the exe NOT in the allowlist → CRED-002 emits.
 *
 * Behaviour: setuid(0), then drop the original argv to /bin/id so
 * the harness can observe "we became root" without invoking a real
 * shell. The PoC's value is in tripping the rule, not in actually
 * privesc-ing the test box.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    /* setuid(0) succeeds because the binary's setuid bit means our
     * saved-uid is 0 already; we just promote real+effective to 0
     * too. This is the operation the LSM hook sees as the
     * non-root → root transition. */
    if (setuid(0) < 0) {
        perror("setuid(0)");
        return 1;
    }

    /* Confirm to the harness via stderr that the priv-gain worked,
     * then exec /bin/id so the resulting process is observably root.
     * /bin/id is a real binary in the setuid_inodes walk so it
     * won't itself trip CRED-002 — we just need the prior setuid
     * event to land on this dropper, which is what BPF saw. */
    fprintf(stderr, "suid-dropper: now uid=%u euid=%u\n",
            (unsigned)getuid(), (unsigned)geteuid());
    char *exec_argv[] = { (char *)"id", NULL };
    execv("/bin/id", exec_argv);
    perror("execv /bin/id");
    return 1;
}
