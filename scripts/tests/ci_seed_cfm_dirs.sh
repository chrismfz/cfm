#!/usr/bin/env bash
# CI only: make CFM's system directories look like a packaged node's before the
# Go tests run, so check_test_isolation.sh also catches a test that writes only
# to a file that ALREADY exists — the class an empty directory can't reveal.
# The notifier tests, for one, fell back to the live /etc/cfm/notify.conf and
# saved over it on every node, while CI's empty /etc/cfm showed nothing.
#
# Seeds, each from its single source in the tree:
#   - every packaged /etc/cfm conffile (packaging/debian/DEBIAN/conffiles),
#     copied from configs/ as the package does;
#   - the shared Lua modules under /var/lib/cfm/lua (configs/lua/*.lua);
#   - each /var/log/cfm/*.log path the Go sources name, as a one-line log.
#
# Never run it on a real host: it refuses unless CI=true, and it refuses to
# overwrite anything that already exists.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }

cd "$(dirname "$0")/../.."

[ "${CI:-}" = true ] || fail "CI only (CI=true): this seeds CFM's system directories like a packaged node"
for tool in grep sort tr install mktemp; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

CONFFILES=packaging/debian/DEBIAN/conffiles
[ -f "$CONFFILES" ] || fail "$CONFFILES not found"

n=0
seed() { # <dst> <src-file>
  [ -e "$1" ] && fail "$1 already exists — refusing to overwrite it (is this a real host?)"
  install -D -m 0644 "$2" "$1"
  n=$((n + 1))
}

while IFS= read -r dst; do
  case "$dst" in /etc/cfm/*) ;; *) continue ;; esac
  src="configs/${dst#/etc/cfm/}"
  [ -f "$src" ] || fail "$CONFFILES lists $dst but $src does not exist"
  seed "$dst" "$src"
done <"$CONFFILES"

for src in configs/lua/*.lua; do
  seed "/var/lib/cfm/lua/${src##*/}" "$src"
done

logline=$(mktemp)
trap 'rm -f "$logline" "$logline.list"' EXIT
echo "2026-01-01 00:00:00 seeded by ci_seed_cfm_dirs.sh" >"$logline"
rc=0
grep -rhoE --include='*.go' --exclude='*_test.go' '"/var/log/cfm/[A-Za-z0-9._-]+\.log"' internal cmd \
  | tr -d '"' | LC_ALL=C sort -u >"$logline.list" || rc=$?
[ "$rc" -le 1 ] || fail "grep failed with status $rc — refusing to report OK"
while IFS= read -r log; do
  seed "$log" "$logline"
done <"$logline.list"

[ "$n" -gt 0 ] || fail "seeded nothing — refusing to report OK"
echo "OK: seeded $n files under /etc/cfm, /var/lib/cfm/lua and /var/log/cfm"
