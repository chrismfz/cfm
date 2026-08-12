#!/usr/bin/env bash
#
# release_notes_test.sh — regression test for scripts/release-notes.sh
# (the GitHub-release notes extractor used by `make release`).
set -euo pipefail

HERE="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$HERE/scripts/release-notes.sh"
[ -x "$SCRIPT" ] || { echo "FAIL: $SCRIPT not executable"; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cl="$tmp/CHANGELOG.md"

fail() { echo "FAIL: $1"; exit 1; }

cat > "$cl" <<'EOF'
# Changelog

## [Unreleased]

_Nothing yet._

## 2026.08.12

### Added
- alpha thing
- beta thing

## 2026.08.01

- old entry
EOF

# 1. Present section → exact body, leading/trailing blanks trimmed.
out="$("$SCRIPT" 2026.08.12 "$cl")"
expected="### Added
- alpha thing
- beta thing"
[ "$out" = "$expected" ] || fail "present-section body mismatch; got:
$out"

# 2. First printed line is not blank, last is not blank.
[ -n "$(printf '%s' "$out" | head -n1)" ] || fail "leading blank not trimmed"
[ -n "$(printf '%s' "$out" | tail -n1)" ] || fail "trailing blank not trimmed"

# 3. It must NOT bleed into the next dated section.
printf '%s\n' "$out" | grep -q 'old entry' && fail "notes bled into the next section"

# 4. Absent section → single-line fallback.
out="$("$SCRIPT" 2026.07.07 "$cl")"
[ "$out" = "Automated release 2026.07.07" ] || fail "absent-section fallback mismatch; got: $out"

# 5. Missing changelog file → fallback (never errors the release).
out="$("$SCRIPT" 2026.07.07 "$tmp/nope.md")"
[ "$out" = "Automated release 2026.07.07" ] || fail "missing-file fallback mismatch; got: $out"

# 6. Malformed date → non-zero exit.
if "$SCRIPT" 2026-07-07 "$cl" >/dev/null 2>&1; then fail "malformed date accepted"; fi

# 7. Last-in-file section (no following heading) → still bounded to that section.
out="$("$SCRIPT" 2026.08.01 "$cl")"
[ "$out" = "- old entry" ] || fail "last-section extraction mismatch; got: $out"

# 8. Oversized section → capped to the byte budget + a truncation footer, and it
#    must NOT come back empty (regression: `head|sed` under `set -o pipefail`
#    aborted on SIGPIPE and emitted nothing). Build a big section.
big="$tmp/big.md"
{ echo "## 2026.09.09"; echo; for i in $(seq 1 5000); do echo "- filler bullet line number $i with some padding text"; done; } > "$big"
out="$(RELEASE_NOTES_MAX_BYTES=4000 "$SCRIPT" 2026.09.09 "$big")"
[ -n "$out" ] || fail "oversized section produced EMPTY notes (pipefail/SIGPIPE regression)"
bytes="$(printf '%s' "$out" | wc -c)"
[ "$bytes" -le 4000 ] || fail "capped notes exceed budget: $bytes > 4000"
printf '%s' "$out" | grep -q 'truncated to fit' || fail "capped notes missing truncation footer"

# 9. Under-budget section → emitted verbatim, no footer.
out="$(RELEASE_NOTES_MAX_BYTES=100000 "$SCRIPT" 2026.08.12 "$cl")"
printf '%s' "$out" | grep -q 'truncated to fit' && fail "small section should not be truncated"

echo "OK: release-notes.sh — all cases pass"
