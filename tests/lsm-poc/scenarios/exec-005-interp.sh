#!/usr/bin/env bash
# CFML-EXEC-005 — interpreter exec with one or two remote stdio fds.
#
# What this proves: the "weak" reverse-shell variant. Attackers who
# know about EXEC-003's strict three-fd-all-remote requirement split
# the redirection — e.g. stdin from socket, stdout/stderr to /dev/null
# to suppress local logging — and still get an interactive shell.
# CFML-EXEC-005 catches the partial-remote pattern at exec time on
# a known interpreter (sh/bash/python/perl/php/ruby/node/nc/ncat/socat).

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

PORT="${LISTENER_PORT:-4444}"
note "[EXEC-005] python with stdin on 127.0.0.1:$PORT (1 remote, 2 local)"

listener_log=$(mktemp -t cfmpoc-listener.XXXXXX)
add_cleanup "rm -f '$listener_log'"
python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT))
s.listen(1)
sys.stderr.write('listener up\n'); sys.stderr.flush()
c, addr = s.accept()
c.sendall(b'')        # nothing to send; just need the accept to land
import time; time.sleep(2)
c.close(); s.close()
" >"$listener_log" 2>&1 &
listener_pid=$!
add_cleanup "kill -9 $listener_pid 2>/dev/null"

deadline=$(( $(date +%s) + 5 ))
while ! grep -q "listener up" "$listener_log" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        fail "listener never came up; aborting"
        exit 1
    fi
    sleep 0.1
done

helper="$HELPERS_DIR/bin/interp-stdio-helper"
start_pos=$(mark_log_position)
# fd=0 (stdin) from the remote socket; stdout/stderr stay local.
# That's 1-of-3 remote — the EXEC-005 "weak" pattern with the
# CFM_LSM_F_STDIO_ONE_REMOTE flag.
trace "$helper 0 /usr/bin/python3 127.0.0.1 $PORT"
"$helper" 0 /usr/bin/python3 127.0.0.1 "$PORT" &
trigger_pid=$!
wait "$trigger_pid" 2>/dev/null || true

if hit=$(expect_event "$start_pos" "CFML-EXEC-005"); then
    pass "EXEC-005 fired: $hit"
    exit 0
fi
fail "no CFML-EXEC-005 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1
