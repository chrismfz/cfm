#!/usr/bin/env bash
# CFML-CRED-004 — capability-set raise by watched (web-class) uid.
#
# Threat model: post-exploit capability hoarding. A watched-uid
# task that holds CAP_X in its inheritable set (granted via file
# capabilities or a previous commit_creds) calls
# prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_X, 0, 0) to push
# the cap into ambient. Ambient capabilities survive execve(), so
# the attacker can drop into a shell or call another binary and
# keep the elevated privilege — the canonical credential-survives-
# process-boundary pattern.
#
# Scenario shape:
#   1. setcap cap_net_bind_service+pi on the helper (root step;
#      grants CAP_NET_BIND_SERVICE in both permitted and inheritable
#      file caps). The harness performs this before execing as
#      TEST_USER.
#   2. runuser -u $TEST_USER -- helper. The helper inherits the
#      file caps in cap_permitted + cap_inheritable, then calls
#      prctl(PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE, ...).
#   3. The kernel commit_creds the new cred (ambient has bit 10
#      set, old didn't). CFML-CRED-004 fires.
#
# We pick CAP_NET_BIND_SERVICE (bit 10) because it's the most
# "boring" cap — the only thing it lets the holder do is bind to
# privileged ports — and shouldn't exist in any watched uid's
# inheritable set under normal hosting setups. The PoC's only
# privileged step is the setcap call by root.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[CRED-004] capability-set raise by watched uid $TEST_USER"
require_policy_enabled CFML-CRED-004
ensure_test_user
ensure_scratch_dir
require_test_user_watched CFML-CRED-004

if ! command -v setcap >/dev/null 2>&1; then
    warn "CRED-004 SKIP: setcap not on PATH (libcap-utils package missing)"
    exit 0
fi
if ! command -v getcap >/dev/null 2>&1; then
    warn "CRED-004 SKIP: getcap not on PATH (libcap-utils package missing)"
    exit 0
fi

helper=$(stage_helper cap-raiser) || exit 1

# Grant CAP_NET_BIND_SERVICE in permitted+inheritable via file
# capabilities. PR_CAP_AMBIENT_RAISE requires the cap to be in
# BOTH sets, so +pi is the minimal config.
if ! setcap cap_net_bind_service+pi "$helper" 2>/dev/null; then
    warn "CRED-004 SKIP: setcap cap_net_bind_service+pi $helper failed"
    warn "  (no xattr support on this filesystem? nouserxattr mount?)"
    exit 0
fi
if ! getcap "$helper" 2>/dev/null | grep -q cap_net_bind_service; then
    warn "CRED-004 SKIP: getcap shows no cap_net_bind_service on $helper"
    exit 0
fi

start_pos=$(mark_log_position)
trace "runuser -u $TEST_USER -- $helper"
# rc is the helper's prctl outcome; in practice it succeeds with
# the file caps we just set. CRED-004 fires either way as long as
# commit_creds runs with a non-empty raised mask.
run_as_test_user "$helper" >/dev/null 2>&1 || true

if hit=$(expect_event "$start_pos" "CFML-CRED-004"); then
    pass "CRED-004 fired: $hit"
    exit 0
fi
fail "no CFML-CRED-004 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1
