#!/usr/bin/env bash
#
# Regression test for scripts/stamp-changelog.sh — the CHANGELOG date stamper
# run by `make release`. Self-contained: builds temp fixtures, runs the stamper,
# asserts the result. Exit non-zero on any failure.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
STAMP="$HERE/../stamp-changelog.sh"
[ -x "$STAMP" ] || { echo "FAIL: $STAMP not executable"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $1"; exit 1; }

# ── Case 1: [Unreleased] with content, no section for the date → rename ──
cat > "$WORK/c1.md" <<'EOF'
# Changelog

## [Unreleased]

### Fixed
- **A fix.** Body.

## 2026.08.01
- old
EOF
"$STAMP" 2026.08.05 "$WORK/c1.md" >/dev/null
grep -q '^## 2026\.08\.05$' "$WORK/c1.md" || fail "c1: dated heading not created"
grep -q '^_Nothing yet\._$' "$WORK/c1.md" || fail "c1: fresh empty [Unreleased] missing"
# The fix must now sit under the dated section, above the older one.
awk '/^## 2026\.08\.05$/{a=NR} /A fix/{b=NR} /^## 2026\.08\.01$/{c=NR} END{exit !(a<b && b<c)}' "$WORK/c1.md" \
  || fail "c1: content not filed under the new dated section"

# ── Case 2: empty [Unreleased] → no-op (byte-identical) ──
cat > "$WORK/c2.md" <<'EOF'
# Changelog

## [Unreleased]

_Nothing yet._

## 2026.08.01
- old
EOF
cp "$WORK/c2.md" "$WORK/c2.orig"
"$STAMP" 2026.08.05 "$WORK/c2.md" >/dev/null
cmp -s "$WORK/c2.md" "$WORK/c2.orig" || fail "c2: empty [Unreleased] was modified (should be a no-op)"

# ── Case 3: a section for the date already exists → append under it ──
cat > "$WORK/c3.md" <<'EOF'
# Changelog

## [Unreleased]

### Fixed
- **Second-build fix.**

## 2026.08.05

### Added
- **Earlier same-day entry.**

## 2026.08.01
- old
EOF
"$STAMP" 2026.08.05 "$WORK/c3.md" >/dev/null
# Exactly ONE section for the date (no duplicate dated heading).
[ "$(grep -c '^## 2026\.08\.05$' "$WORK/c3.md")" -eq 1 ] || fail "c3: duplicate dated section created"
# Both entries must appear after the single dated heading and before the older one.
awk '
  /^## 2026\.08\.05$/{d=NR}
  /Second-build fix/{s=NR}
  /Earlier same-day entry/{e=NR}
  /^## 2026\.08\.01$/{o=NR}
  END{ exit !(d<s && d<e && s<o && e<o) }' "$WORK/c3.md" \
  || fail "c3: same-day append did not land both entries under the dated section"

# ── Case 4: bad date is rejected ──
if "$STAMP" not-a-date "$WORK/c1.md" >/dev/null 2>&1; then
  fail "c4: bad date was accepted"
fi

echo "OK: stamp-changelog.sh — all cases pass"
