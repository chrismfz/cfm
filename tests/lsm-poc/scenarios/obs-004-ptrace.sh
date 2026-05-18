#!/usr/bin/env bash
# CFML-OBS-004 — ptrace by a watched (web-class) uid.
#
# Threat model: post-exploit credential theft. A compromised vhost
# user PTRACE_ATTACHes to a sibling process they own (PHP-FPM worker,
# long-running cron) and uses PTRACE_PEEKDATA to read in-memory
# secrets or PTRACE_POKETEXT to inject shellcode. Same-uid ptrace is
# allowed by kernel.yama.ptrace_scope=1 (the default), so any of the
# user's own running processes is a viable target.
#
# Companion telemetry to kernsec's kernel.yama.ptrace_scope=2 sysctl
# on yama≤1 hosts (the distro default). On yama=2 hosts the BPF LSM
# hook is pre-empted by yama's earlier -EPERM in the LSM chain, so
# OBS-004 records nothing there — the kernel block IS the protection.
# This PoC therefore expects to run on a yama≤1 host; on yama=2 it
# will see PTRACE_ATTACH fail with -EPERM AND no CFML-OBS-004 event,
# which is the documented behaviour.
#
# Scenario shape:
#   1. fork() a sleep-style victim child as TEST_USER.
#   2. parent ptrace(PTRACE_ATTACH, child, ...) — fires OBS-004.
#   3. cleanup (detach + kill + reap).
#
# Both parent and child run as TEST_USER, exercising the same-uid
# sibling-worker case (the SAMEUID flag should be set in the event).

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[OBS-004] ptrace by watched uid $TEST_USER"
require_policy_enabled CFML-OBS-004
ensure_test_user
ensure_scratch_dir
require_test_user_watched CFML-OBS-004

helper=$(stage_helper ptracer) || exit 1

start_pos=$(mark_log_position)
trace "runuser -u $TEST_USER -- $helper"
# rc is irrelevant — PTRACE_ATTACH may fail with -EPERM (yama,
# ptrace_scope, container restrictions). On yama≤1 hosts the LSM
# hook fires and OBS-004 emits; on yama=2 hosts the kernel LSM
# chain short-circuits at yama before reaching BPF and OBS-004
# records nothing. The harness fails-loud below if no event lands;
# on yama=2 hosts run this scenario after temporarily setting
# kernel.yama.ptrace_scope=1 to exercise the rule.
run_as_test_user "$helper" >/dev/null 2>&1 || true

if hit=$(expect_event "$start_pos" "CFML-OBS-004"); then
    pass "OBS-004 fired: $hit"
    exit 0
fi
fail "no CFML-OBS-004 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1
