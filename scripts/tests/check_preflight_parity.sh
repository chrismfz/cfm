#!/usr/bin/env bash
# Keeps the two hand-kept copies of the CI gate list in sync with CI itself.
#
# Why this exists (2026-09-22): `.github/workflows/security.yml` is the source
# of truth for what a PR must pass, and two copies of that list are kept by
# hand — the `/preflight` command (.claude/commands/preflight.md), which is
# what contributors and agents actually run before pushing, and the CLAUDE.md
# §3 block. Both drifted, twice: preflight.md once silently stopped covering
# seven gates, and later missed check_site_cache_config.sh, while CLAUDE.md §3
# never listed release_notes_test.sh. A preflight that skips a CI gate is a
# green local run followed by a red CI one — the false confidence the
# guardrails exist to prevent.
#
# The check: every command CI runs (a `run:` step of security.yml) must appear
# in BOTH copies, and neither copy may list a command CI does not run. Setup
# steps (go version, go mod tidy, the apt-get install) are skipped explicitly;
# any other new `run:` form fails until it is listed in both copies (or added
# to the skip list here, with a reason).
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }

cd "$(dirname "$0")/../.."

WORKFLOW=.github/workflows/security.yml
PREFLIGHT=.claude/commands/preflight.md
CLAUDE_MD=CLAUDE.md

# A guardrail that cannot run its matcher must FAIL, never report OK (CLAUDE.md §5).
for tool in grep sed sort comm; do
  command -v "$tool" >/dev/null 2>&1 || fail \
    "$tool is not installed — this guard would pass while checking nothing"
done
for f in "$WORKFLOW" "$PREFLIGHT" "$CLAUDE_MD"; do
  [ -f "$f" ] || fail "$f not found — this guard would pass while checking nothing"
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# grep exits 0 (matched) or 1 (nothing matched); anything else is a broken
# matcher and must abort — `|| true` would swallow it along with "no match".
g() { # <out-file> <grep args...>
  local out=$1 rc=0
  shift
  grep "$@" >"$out" || rc=$?
  [ "$rc" -le 1 ] || fail "grep $* failed with status $rc — refusing to report OK"
  return "$rc"
}

# ── CI: every single-line `run:` command ─────────────────────────────────────
sed -n 's/^[[:space:]]*\(-[[:space:]]*\)\{0,1\}run:[[:space:]]*//p' "$WORKFLOW" |
  sed 's/[[:space:]]*$//' >"$tmp/ci.raw"
# A block scalar (`run: |` / `run: >`) hides its commands on the lines below;
# this parser can't see them, so refuse rather than silently skip them.
if g "$tmp/blocks" -E '^[|>][+-]?$' "$tmp/ci.raw"; then
  fail "$WORKFLOW has a multi-line run: block — this guard only reads one-line run: steps; split it or extend the guard"
fi
# Setup steps, not gates: nothing a contributor runs as a check.
g "$tmp/ci.f" -vE '^(go version|go mod tidy|sudo apt-get .*)$' "$tmp/ci.raw" || :
sort -u "$tmp/ci.f" >"$tmp/ci"
[ -s "$tmp/ci" ] || fail "extracted no CI commands from $WORKFLOW — refusing to report OK"

# ── preflight.md: the backticked command opening each numbered step ─────────
sed -n 's/^[0-9][0-9]*\.[[:space:]]*`\([^`]*\)`.*/\1/p' "$PREFLIGHT" | sort -u >"$tmp/preflight"
[ -s "$tmp/preflight" ] || fail "extracted no commands from $PREFLIGHT — refusing to report OK"

# ── CLAUDE.md §3: the first ```bash block of the section ─────────────────────
sed -n '/^## 3\./,/^## 4\./p' "$CLAUDE_MD" |
  sed -n '/^```bash/,/^```$/{/^```/d;p;}' |
  sed 's/[[:space:]]#.*$//; s/[[:space:]]*$//' >"$tmp/claude.raw"
g "$tmp/claude.f" -v '^$' "$tmp/claude.raw" || :
sort -u "$tmp/claude.f" >"$tmp/claude"
[ -s "$tmp/claude" ] || fail "extracted no commands from $CLAUDE_MD §3 — refusing to report OK"

violations=()
check() { # <label> <file>
  local missing extra
  missing=$(comm -23 "$tmp/ci" "$2")
  extra=$(comm -13 "$tmp/ci" "$2")
  while IFS= read -r c; do
    [ -n "$c" ] && violations+=("$1 is missing a gate CI runs: $c")
  done <<<"$missing"
  while IFS= read -r c; do
    [ -n "$c" ] && violations+=("$1 lists a command CI does not run: $c")
  done <<<"$extra"
  return 0
}
check "$PREFLIGHT" "$tmp/preflight"
check "$CLAUDE_MD §3" "$tmp/claude"

if [ "${#violations[@]}" -gt 0 ]; then
  for v in "${violations[@]}"; do echo "FAIL: $v" >&2; done
  echo "Keep $PREFLIGHT and the $CLAUDE_MD §3 block in sync with $WORKFLOW." >&2
  exit 1
fi

echo "OK: $PREFLIGHT and $CLAUDE_MD §3 list exactly the $(wc -l <"$tmp/ci" | tr -d ' ') commands CI runs"
