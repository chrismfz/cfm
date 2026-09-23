#!/usr/bin/env bash
# Fails when the Go test suite writes into CFM's live system directories.
#
# Why this exists (2026-09-23): tests built engines, stores and collectors from
# sparse configs, so the production defaults applied and the suite wrote the
# LIVE files. On any machine where it ran as root — a CFM node, a build host, an
# agent's container — it replaced the operator's manual challenges, added a WAF
# exclude for mysite.com, appended to the notifier history, and left a kernsec
# rollback snapshot of TEST boot args (which the host's first real apply then
# kept, instead of writing its own) — and the notifier tests saved over the
# live /etc/cfm/notify.conf. CI never noticed: it runs as a non-root user, so
# those writes failed silently and every test still passed. Each writer now
# takes a default the tests point at a temp dir (a TestMain, or the test
# itself); this guard catches the next one.
#
# Usage, around the Go suite:
#   ./scripts/tests/check_test_isolation.sh arm      # before go test
#   go test -race ./...
#   ./scripts/tests/check_test_isolation.sh verify   # after
#
# arm needs each watched directory to exist and be writable by the user running
# the tests, so that a regressing test's write SUCCEEDS and shows up here
# instead of failing silently; then it records what is in them. verify fails on
# anything added, changed or removed since. A directory arm can't watch fails
# it, with the one-time command to create it: a guard that cannot observe must
# not report OK (CLAUDE.md §5). arm never creates them itself — an empty
# /etc/cfm changes where the cfm CLI looks for its config on that machine, so
# that is the operator's call. CI creates them (sudo) and then seeds them like a
# packaged node (ci_seed_cfm_dirs.sh), so a test that writes only to a file
# that already exists shows up too. On a CFM node the running daemon writes to
# these directories as well, and its writes show up in verify: run the suite
# where CFM isn't running.
set -euo pipefail

DIRS=(/var/lib/cfm /run/cfm /etc/cfm /var/log/cfm)
# One snapshot per user and checkout, so two checkouts' preflights can't mix.
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SNAPSHOT="${TMPDIR:-/tmp}/cfm-test-isolation.$(id -u).$(printf '%s' "$ROOT" | cksum | cut -d' ' -f1).snapshot"

fail() { echo "FAIL: $*" >&2; exit 1; }

for tool in find sort diff cksum mktemp; do
  command -v "$tool" >/dev/null 2>&1 || fail \
    "$tool is not installed — this guard would pass while checking nothing"
done

# Every entry, the directories themselves included: a file a test created and
# removed again still changes its directory's mtime. -H follows a watched
# directory that is itself a symlink (e.g. /var/lib/cfm on another volume);
# without it find lists only the link and never looks inside.
snapshot() { find -H "${DIRS[@]}" -printf '%p\t%y\t%m\t%s\t%T@\n' | LC_ALL=C sort; }

case "${1:-}" in
arm)
  for d in "${DIRS[@]}"; do
    if [ ! -d "$d" ] || [ ! -w "$d" ]; then
      fail "cannot watch $d: it must exist and be writable by $(id -un), or a test's write there fails silently and this guard sees nothing. Create it once: sudo install -d -o \"\$(id -u)\" -g \"\$(id -g)\" ${DIRS[*]}"
    fi
  done
  snapshot >"$SNAPSHOT" || fail "cannot read ${DIRS[*]} — refusing to report OK"
  echo "OK: watching ${DIRS[*]} ($(wc -l <"$SNAPSHOT" | tr -d ' ') entries); run the Go tests, then: $0 verify"
  ;;
verify)
  [ -f "$SNAPSHOT" ] || fail "no snapshot at $SNAPSHOT — run \"$0 arm\" before the Go tests"
  now=$(mktemp)
  trap 'rm -f "$now"' EXIT
  snapshot >"$now" || fail "cannot read ${DIRS[*]} — refusing to report OK"
  rc=0
  changes=$(diff "$SNAPSHOT" "$now") || rc=$?
  [ "$rc" -le 1 ] || fail "diff failed with status $rc — refusing to report OK"
  if [ "$rc" -eq 1 ]; then
    echo "FAIL: the Go tests wrote CFM's live system directories:" >&2
    printf '%s\n' "$changes" | sed -n 's/^\([<>]\) \([^\t]*\).*/  \1 \2/p' >&2
    echo "('<' = before, '>' = after.) A test reached a production default path." >&2
    echo "Point it at a temp dir: see the TestMain in internal/webdetector, kernsec, sslcollector or apiserver." >&2
    echo "If a CFM daemon runs on this host, its own writes show up here too." >&2
    exit 1
  fi
  rm -f "$SNAPSHOT"
  echo "OK: the Go tests wrote nothing under ${DIRS[*]}"
  ;;
*)
  echo "usage: $0 arm|verify" >&2
  exit 2
  ;;
esac
