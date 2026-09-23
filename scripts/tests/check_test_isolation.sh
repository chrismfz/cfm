#!/usr/bin/env bash
# Fails when the Go test suite writes into CFM's live system directories.
#
# Why this exists (2026-09-23): tests built engines, stores and collectors from
# sparse configs, so the production defaults applied and the suite wrote the
# LIVE files. On any machine where it ran as root — a CFM node, a build host, an
# agent's container — it replaced the operator's manual challenges, added a WAF
# exclude for mysite.com, appended to the notifier history, and left a kernsec
# rollback snapshot of TEST boot args (which the host's first real apply then
# kept, instead of writing its own). CI never noticed: it runs as a non-root
# user, so those writes failed silently and every test still passed. Each writer
# now takes a default its package's TestMain points at a temp dir; this guard
# catches the next one.
#
# Usage, around the Go suite:
#   ./scripts/tests/check_test_isolation.sh arm      # before go test
#   go test -race ./...
#   ./scripts/tests/check_test_isolation.sh verify   # after
#
# arm needs each watched directory to exist and be writable by the user running
# the tests, so that a regressing test's write SUCCEEDS and shows up here
# instead of failing silently (CI creates them with sudo first). It creates any
# it can, then records what is in them. verify fails on anything added, changed
# or removed since. A directory arm can't watch fails it: a guard that cannot
# observe must not report OK (CLAUDE.md §5). On a CFM node the running daemon
# writes to these directories too, and its writes will show up in verify: run
# the suite where CFM isn't running.
set -euo pipefail

DIRS=(/var/lib/cfm /run/cfm /etc/cfm /var/log/cfm)
SNAPSHOT="${TMPDIR:-/tmp}/cfm-test-isolation.$(id -u).snapshot"

fail() { echo "FAIL: $*" >&2; exit 1; }

for tool in find sort diff; do
  command -v "$tool" >/dev/null 2>&1 || fail \
    "$tool is not installed — this guard would pass while checking nothing"
done

# Every entry, the directories themselves included: a file a test created and
# removed again still changes its directory's mtime.
snapshot() { find "${DIRS[@]}" -printf '%p\t%y\t%m\t%s\t%T@\n' | LC_ALL=C sort; }

case "${1:-}" in
arm)
  for d in "${DIRS[@]}"; do
    [ -d "$d" ] || mkdir -p "$d" 2>/dev/null || true
    if [ ! -d "$d" ] || [ ! -w "$d" ]; then
      fail "cannot watch $d: it must exist and be writable by $(id -un), or a test's write there fails silently and this guard sees nothing. Create it once: sudo install -d -o \"\$(id -u)\" -g \"\$(id -g)\" ${DIRS[*]}"
    fi
  done
  snapshot >"$SNAPSHOT" || fail "cannot read ${DIRS[*]} — refusing to report OK"
  echo "OK: watching ${DIRS[*]} ($(wc -l <"$SNAPSHOT" | tr -d ' ') entries); run the Go tests, then: $0 verify"
  ;;
verify)
  [ -f "$SNAPSHOT" ] || fail "no snapshot at $SNAPSHOT — run \"$0 arm\" before the Go tests"
  snapshot >"$SNAPSHOT.now" || fail "cannot read ${DIRS[*]} — refusing to report OK"
  rc=0
  changes=$(diff "$SNAPSHOT" "$SNAPSHOT.now") || rc=$?
  rm -f "$SNAPSHOT.now"
  [ "$rc" -le 1 ] || fail "diff failed with status $rc — refusing to report OK"
  if [ "$rc" -eq 1 ]; then
    echo "FAIL: the Go tests wrote CFM's live system directories:" >&2
    printf '%s\n' "$changes" | sed -n 's/^\([<>]\) \([^\t]*\).*/  \1 \2/p' >&2
    echo "('<' = before, '>' = after.) A test reached a production default path." >&2
    echo "Point it at a temp dir: see the TestMain in internal/webdetector, kernsec or sslcollector." >&2
    echo "If a CFM daemon runs on this host, its own writes show up here too." >&2
    exit 1
  fi
  echo "OK: the Go tests wrote nothing under ${DIRS[*]}"
  ;;
*)
  echo "usage: $0 arm|verify" >&2
  exit 2
  ;;
esac
