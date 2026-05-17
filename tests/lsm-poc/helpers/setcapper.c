/*
 * setcapper — write the security.capability xattr to demonstrate
 * the file-capability install pattern that CFML-FS-007 catches.
 *
 * Threat scenario: an attacker has root momentarily (any kernel /
 * userland privesc), drops a binary, and grants it cap_setuid+ep
 * via setcap(8) so a later unprivileged shell can re-enter root via
 * setuid(0) without re-exploiting. The setuid-bit equivalent is in
 * cred-002-suid-dropper.sh; this is the harder-to-spot variant
 * (no `s` in ls -l, only `getcap` reveals the privilege).
 *
 * Why a helper instead of /sbin/setcap directly: setxattr on the
 * security.capability xattr requires CAP_SETFCAP, which the test
 * user cfmpoc doesn't have. The harness invokes us with cap_setfcap
 * granted via file caps on this helper itself (`setcap cap_setfcap+ep
 * helpers/bin/setcapper`), so when cfmpoc execs us we run with
 * CAP_SETFCAP, uid=cfmpoc — exactly the realistic threat-model
 * shape (the attacker had CAP_SETFCAP somehow).
 *
 * Sets cap_setuid+ep on the target. CFML-FS-007's inode_setxattr
 * hook fires on the security.capability write, emits with
 * primitive=file_cap.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>

/* VFS_CAP_REVISION_2 layout, two-word permitted+inheritable. We hand-
 * roll the struct so we don't need libcap headers. */
struct cfm_vfs_cap_v2 {
    uint32_t magic_etc;
    struct {
        uint32_t permitted;
        uint32_t inheritable;
    } data[2];
};

#define VFS_CAP_REVISION_2     0x02000000
#define VFS_CAP_FLAGS_EFFECTIVE 0x000001
#define CAP_SETUID             7

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s TARGET\n", argv[0]);
        return 2;
    }

    struct cfm_vfs_cap_v2 cap = {
        .magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE,
    };
    cap.data[0].permitted = 1U << CAP_SETUID;

    if (setxattr(argv[1], "security.capability", &cap, sizeof(cap), 0) != 0) {
        perror("setxattr security.capability");
        fprintf(stderr,
                "setcapper: failed to write file-cap to %s — "
                "harness should have granted cap_setfcap+ep on this helper\n",
                argv[1]);
        return 1;
    }
    return 0;
}
