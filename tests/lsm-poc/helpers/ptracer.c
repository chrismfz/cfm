/*
 * ptracer — PTRACE_ATTACH to a sibling process owned by the same uid.
 *
 * Threat scenario: a compromised vhost user attaches to a sibling
 * process (PHP-FPM worker, long-running cron) and uses
 * PTRACE_PEEKDATA / PTRACE_GETREGS to steal in-memory secrets, or
 * PTRACE_POKETEXT to inject shellcode. Same-uid ptrace is allowed by
 * kernel.yama.ptrace_scope=1 (the default), so any of the user's own
 * running processes is a credential-theft target.
 *
 * The CFML-OBS-004 LSM hook (ptrace_access_check) fires on every
 * ptrace attempt by a watched (web-class) uid against any other
 * process — the kernel invokes the hook BEFORE deciding the access,
 * so the rule sees both accepted and denied attempts.
 *
 * Harness shape:
 *   1. fork() a sleep-style child (the "victim").
 *   2. parent waits a moment to let the child reach pause() / sleep().
 *   3. parent calls ptrace(PTRACE_ATTACH, child_pid, ...).
 *   4. regardless of whether the attach actually succeeds (yama,
 *      ptrace_scope, container restrictions can deny), the
 *      ptrace_access_check hook fired and the event landed.
 *   5. parent cleans up (PTRACE_DETACH + waitpid + kill).
 *
 * Runs as $TEST_USER from the harness — same uid for both parent and
 * child, exercising the same-uid sibling-worker pattern.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void victim(void)
{
    /* Block in pause() until parent attaches and SIGKILLs us. The
     * ptrace_access_check hook fires on the parent's PTRACE_ATTACH
     * regardless of what the victim is doing. */
    pause();
    _exit(0);
}

int main(void)
{
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        return 1;
    }
    if (child == 0) {
        victim();
        _exit(0);
    }

    /* Give the child a moment to enter pause(). 100ms is generous
     * enough for the kernel to schedule it and tight enough not to
     * stall the PoC harness. */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
    nanosleep(&ts, NULL);

    /* PTRACE_ATTACH triggers the kernel's ptrace_access_check LSM
     * hook with the child as the target task. PTRACE_MODE_ATTACH
     * (bit 1) and PTRACE_MODE_REALCREDS (bit 4) are set by the
     * kernel; OBS-004 surfaces the ATTACH bit in event flags. */
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) < 0) {
        /* Common cases this can fail:
         *   - kernel.yama.ptrace_scope=2 → -EPERM (no parent→non-child
         *     attach without PR_SET_PTRACER on the target side)
         *   - container with --cap-drop=SYS_PTRACE → -EPERM
         *   - host hardened SECCOMP allow-list → -EPERM
         * Regardless of outcome, ptrace_access_check fired and OBS-004
         * emitted, so we report the syscall failure (informational)
         * and continue to cleanup. */
        fprintf(stderr, "PTRACE_ATTACH child=%d failed: %s\n",
                child, strerror(errno));
    } else {
        /* Attached; wait for the SIGSTOP delivery, then detach. */
        int status = 0;
        waitpid(child, &status, 0);
        ptrace(PTRACE_DETACH, child, NULL, NULL);
    }

    /* Reap the victim. */
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return 0;
}
