/*
 * cap-raiser — invoke prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, ...)
 * to move a capability from inheritable into the ambient set.
 *
 * Threat scenario: a watched-uid task that holds CAP_X in its
 * inheritable set (via file capabilities or a previous
 * commit_creds) calls prctl to push the cap into ambient. Ambient
 * capabilities survive execve(), so the attacker can drop into a
 * shell or call another binary and keep the elevated privilege —
 * the canonical credential-survives-process-boundary pattern.
 *
 * Setup the scenario performs before running this helper:
 *   setcap cap_net_bind_service+pi <this-binary>
 *
 * That puts CAP_NET_BIND_SERVICE into both the permitted and
 * inheritable file-capability sets. When the watched user execs
 * this binary, the kernel grants CAP_NET_BIND_SERVICE in
 * cap_permitted and cap_inheritable. Then PR_CAP_AMBIENT_RAISE
 * succeeds (it requires the cap to be in BOTH permitted and
 * inheritable) and the ambient set gains the bit — which is
 * exactly what CFML-CRED-004 detects.
 *
 * We pick CAP_NET_BIND_SERVICE (bit 10) because it's the most
 * "boring" cap to grant a non-root user and shouldn't be in their
 * inheritable set under normal hosting setups. The PoC's only
 * privileged step is the setcap call by root in the harness.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

/* From include/uapi/linux/prctl.h. Inlined to avoid pulling
 * libcap headers; values are stable kernel ABI. */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_RAISE
#define PR_CAP_AMBIENT_RAISE 2
#endif

/* From include/uapi/linux/capability.h. CAP_NET_BIND_SERVICE = 10. */
#ifndef CAP_NET_BIND_SERVICE
#define CAP_NET_BIND_SERVICE 10
#endif

int main(void)
{
    long r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
                   (unsigned long)CAP_NET_BIND_SERVICE,
                   0UL, 0UL);
    if (r < 0) {
        fprintf(stderr,
            "prctl(PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE) failed: %s\n"
            "  (helper must have cap_net_bind_service+pi set via setcap;\n"
            "   the scenario performs that setup before exec'ing this binary)\n",
            strerror(errno));
        return 1;
    }
    fprintf(stderr, "PR_CAP_AMBIENT_RAISE(CAP_NET_BIND_SERVICE) succeeded\n");
    return 0;
}
