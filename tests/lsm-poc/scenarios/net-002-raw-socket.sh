#!/usr/bin/env bash
# CFML-NET-002 — raw / packet socket from watched (web-class) uid.
#
# Threat model: post-exploit scanner / sniffer / spoofing toolkit
# dropped by a compromised vhost user. Legitimate vhost-user
# workloads (PHP / Python / MySQL clients) never open raw or
# AF_PACKET sockets; root daemons that legitimately do (named for
# DNS, dhclient, NetworkManager, setuid /bin/ping) all run as
# uid 0 and are filtered out by the watched-uid gate.
#
# The CFML-NET-002 LSM hook (socket_create) fires BEFORE the
# capability check, so the PoC succeeds even though the calling
# test user has no CAP_NET_RAW (socket(2) returns -EPERM, but the
# event lands first).
#
# Three legs exercised in sequence — any one firing makes the
# scenario pass:
#   1. AF_INET   + SOCK_RAW + IPPROTO_ICMP    → op=raw_inet
#   2. AF_INET6  + SOCK_RAW + IPPROTO_ICMPV6  → op=raw_inet6
#   3. AF_PACKET + SOCK_RAW + ETH_P_ALL       → op=packet

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

note "[NET-002] raw / packet socket by watched uid $TEST_USER"
require_policy_enabled CFML-NET-002
ensure_test_user
ensure_scratch_dir
require_test_user_watched CFML-NET-002

helper=$(stage_helper raw-socketer) || exit 1

start_pos=$(mark_log_position)
trace "runuser -u $TEST_USER -- $helper"
# rc is irrelevant — socket(2) returns -EPERM for unprivileged
# raw-socket creation. The LSM hook fires BEFORE the capability
# check so NET-002 emits regardless.
run_as_test_user "$helper" >/dev/null 2>&1 || true

if hit=$(expect_event "$start_pos" "CFML-NET-002"); then
    pass "NET-002 fired: $hit"
    exit 0
fi
fail "no CFML-NET-002 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1
