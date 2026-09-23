#!/usr/bin/env bash
# CI only: make CFM's system directories look like a packaged node's before the
# Go tests run, so check_test_isolation.sh also catches a test that writes only
# to a file that ALREADY exists — the class an empty directory can't reveal.
# The notifier tests, for one, fell back to the live /etc/cfm/notify.conf and
# saved over it on every node, while CI's empty /etc/cfm showed nothing.
#
# Seeds, each list derived from its source in the tree (no hand-kept copy):
#   - every packaged /etc/cfm conffile (packaging/debian/DEBIAN/conffiles),
#     copied from configs/ as the package does;
#   - the shared Lua modules under /var/lib/cfm/lua (configs/lua/*.lua);
#   - each CFM log the Go sources name — a "/var/log/cfm/….log" literal or a
#     webdetector defaultLogPath("….log") — as a one-line log;
#   - each piece of runtime state they name under /var/lib/cfm — a
#     "/var/lib/cfm/[dir/]….{json,jsonl,db,bak}" literal or a webdetector
#     defaultStatePath("…") — as an empty placeholder (only existence matters).
#
# Never run it on a real host: it refuses unless CI=true, and it checks EVERY
# destination before writing any, refusing if even one already exists.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }

cd "$(dirname "$0")/../.."

[ "${CI:-}" = true ] || fail "CI only (CI=true): this seeds CFM's system directories like a packaged node"
for tool in grep sed sort tr cut uniq install mktemp; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

CONFFILES=packaging/debian/DEBIAN/conffiles
[ -f "$CONFFILES" ] || fail "$CONFFILES not found"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# grep exits 0 (matched) or 1 (nothing matched); anything else is a broken
# matcher and must abort.
g() { # <out-file> <grep args...>
  local out=$1 rc=0
  shift
  grep "$@" >"$out" || rc=$?
  [ "$rc" -le 1 ] || fail "grep $* failed with status $rc — refusing to report OK"
}

# ── the plan: "<dst>\t<src>" lines; src "-" = placeholder ──────────────────────
: >"$tmp/plan"
while IFS= read -r dst; do
  case "$dst" in /etc/cfm/*) ;; *) continue ;; esac
  src="configs/${dst#/etc/cfm/}"
  [ -f "$src" ] || fail "$CONFFILES lists $dst but $src does not exist"
  printf '%s\t%s\n' "$dst" "$src" >>"$tmp/plan"
done <"$CONFFILES"
for src in configs/lua/*.lua; do
  printf '%s\t%s\n' "/var/lib/cfm/lua/${src##*/}" "$src" >>"$tmp/plan"
done

GO=(-r --include=*.go --exclude=*_test.go internal cmd)
g "$tmp/logs.lit" -hoE '"/var/log/cfm/[A-Za-z0-9._-]+\.log"' "${GO[@]}"
g "$tmp/logs.fn" -hoE 'defaultLogPath\("[A-Za-z0-9._-]+\.log"\)' "${GO[@]}"
{ tr -d '"' <"$tmp/logs.lit"; sed 's#^defaultLogPath("\(.*\)")$#/var/log/cfm/\1#' "$tmp/logs.fn"; } |
  LC_ALL=C sort -u >"$tmp/logs"
[ -s "$tmp/logs" ] || fail "found no CFM log paths in the Go sources — refusing to report OK"
sed 's/$/\t=log/' "$tmp/logs" >>"$tmp/plan"

g "$tmp/state.lit" -hoE '"/var/lib/cfm/([A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+\.(json|jsonl|db|bak)"' "${GO[@]}"
g "$tmp/state.fn" -hoE 'defaultStatePath\("[A-Za-z0-9._-]+"\)' "${GO[@]}"
{ tr -d '"' <"$tmp/state.lit"; sed 's#^defaultStatePath("\(.*\)")$#/var/lib/cfm/\1#' "$tmp/state.fn"; } |
  LC_ALL=C sort -u >"$tmp/state"
[ -s "$tmp/state" ] || fail "found no CFM runtime-state paths in the Go sources — refusing to report OK"
sed 's/$/\t-/' "$tmp/state" >>"$tmp/plan"

# ── phase 1: every destination must be absent — nothing is written otherwise ──
dups=$(cut -f1 "$tmp/plan" | LC_ALL=C sort | uniq -d)
[ -z "$dups" ] || fail "the seed plan names a path twice: $dups"
while IFS=$'\t' read -r dst _; do
  [ -e "$dst" ] && fail "$dst already exists — refusing to seed anything (is this a real host?)"
done <"$tmp/plan"

# ── phase 2: write ────────────────────────────────────────────────────────────
echo "2026-01-01 00:00:00 seeded by ci_seed_cfm_dirs.sh" >"$tmp/logline"
: >"$tmp/empty"
n=0
while IFS=$'\t' read -r dst src; do
  case "$src" in
  -) src="$tmp/empty" ;;
  =log) src="$tmp/logline" ;;
  esac
  install -D -m 0644 "$src" "$dst"
  n=$((n + 1))
done <"$tmp/plan"

echo "OK: seeded $n files under /etc/cfm, /var/lib/cfm and /var/log/cfm"
