#!/usr/bin/env bash
#
# stamp-changelog.sh — move the "## [Unreleased]" section of CHANGELOG.md under
# a dated "## <YYYY.MM.DD>" heading and leave a fresh empty "## [Unreleased]".
#
# The date is passed in (never computed here) so it is ALWAYS the exact same
# value the Makefile stamps on the package/tag — CHANGELOG date == VERSION ==
# git tag, no drift. `make release` passes the UTC release date.
#
# Idempotent and safe to run repeatedly:
#   - Unreleased has no bullets (only "_Nothing yet._") → no-op, exit 0.
#   - A "## <date>" section already exists (a second build the same day) →
#     the Unreleased bullets are appended UNDER that existing dated section,
#     keeping one section per day (CLAUDE.md §8 "the date is the unit of
#     release"); a fresh empty Unreleased is still left at the top.
#   - Otherwise → rename Unreleased to "## <date>" and add a fresh Unreleased.
#
# Usage: scripts/stamp-changelog.sh <YYYY.MM.DD> [changelog-file]
set -euo pipefail

DATE="${1:?usage: stamp-changelog.sh YYYY.MM.DD [changelog-file]}"
FILE="${2:-CHANGELOG.md}"

case "$DATE" in
  [0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]) ;;
  *) echo "stamp-changelog: date must be YYYY.MM.DD, got '$DATE'" >&2; exit 2 ;;
esac
[ -f "$FILE" ] || { echo "stamp-changelog: no such file: $FILE" >&2; exit 2; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

awk -v date="$DATE" '
  BEGIN { n = 0 }
  { line[n++] = $0 }
  END {
    # Locate the Unreleased block: from its heading to the line before the
    # next "## " heading (or EOF).
    us = -1
    for (i = 0; i < n; i++) if (line[i] == "## [Unreleased]") { us = i; break }
    if (us < 0) { for (i = 0; i < n; i++) print line[i]; exit 0 }  # nothing to do
    ue = n
    for (i = us + 1; i < n; i++) if (line[i] ~ /^## /) { ue = i; break }

    # Does the Unreleased body carry a real bullet?
    has = 0
    for (i = us + 1; i < ue; i++) if (line[i] ~ /^- /) { has = 1; break }
    if (!has) { for (i = 0; i < n; i++) print line[i]; exit 0 }  # empty → no-op

    # Extract the body, trimmed of leading/trailing blank lines.
    bn = 0
    for (i = us + 1; i < ue; i++) body[bn++] = line[i]
    bs = 0; while (bs < bn && body[bs] ~ /^[[:space:]]*$/) bs++
    be = bn - 1; while (be >= bs && body[be] ~ /^[[:space:]]*$/) be--

    # Is there already a section for this exact date?
    dhead = "## " date
    di = -1
    for (i = ue; i < n; i++) if (line[i] == dhead) { di = i; break }

    # Emit preamble (everything before Unreleased heading).
    for (i = 0; i < us; i++) print line[i]

    # Fresh empty Unreleased.
    print "## [Unreleased]"
    print ""
    print "_Nothing yet._"
    print ""

    if (di < 0) {
      # New dated section right here, then the untouched remainder.
      print dhead
      print ""
      for (i = bs; i <= be; i++) print body[i]
      print ""
      for (i = ue; i < n; i++) print line[i]
    } else {
      # Append the moved body under the existing dated section: print the
      # remainder, and right after the dated heading splice the body in.
      for (i = ue; i < n; i++) {
        print line[i]
        if (i == di) {
          print ""
          for (j = bs; j <= be; j++) print body[j]
        }
      }
    }
  }
' "$FILE" > "$tmp"

if cmp -s "$FILE" "$tmp"; then
  echo "stamp-changelog: [Unreleased] empty — nothing to stamp for $DATE"
  exit 0
fi
cat "$tmp" > "$FILE"
echo "stamp-changelog: moved [Unreleased] → ## $DATE in $FILE (commit it with the release)"
