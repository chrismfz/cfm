#!/usr/bin/env bash
#
# release-notes.sh — print the CHANGELOG.md body for a given "## YYYY.MM.DD"
# section, for use as GitHub release notes (`gh release create --notes`).
#
# `make release` builds tag-only GitHub releases (no .deb/.rpm assets — those
# ship via `make sync` to the apt/yum repo), so the notes are the one useful
# payload: this prints that day's changelog entries. If the dated section is
# absent (e.g. a same-day rebuild with an empty [Unreleased]) it falls back to a
# one-line default so the release always has non-empty notes.
#
# Usage: scripts/release-notes.sh <YYYY.MM.DD> [changelog-file]
set -euo pipefail

DATE="${1:?usage: release-notes.sh YYYY.MM.DD [changelog-file]}"
FILE="${2:-CHANGELOG.md}"

case "$DATE" in
  [0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]) ;;
  *) echo "release-notes: date must be YYYY.MM.DD, got '$DATE'" >&2; exit 2 ;;
esac

body=""
if [ -f "$FILE" ]; then
  body="$(awk -v h="## $DATE" '
    $0 == h { f = 1; next }         # start at the dated heading
    f && /^## / { exit }            # stop at the next section heading
    f {
      if (!started && $0 ~ /^[[:space:]]*$/) next   # skip leading blank lines
      started = 1
      buf[n++] = $0
    }
    END {
      while (n > 0 && buf[n-1] ~ /^[[:space:]]*$/) n--   # drop trailing blanks
      for (i = 0; i < n; i++) print buf[i]
    }
  ' "$FILE")"
fi

if [ -n "$(printf '%s' "$body" | tr -d '[:space:]')" ]; then
  printf '%s\n' "$body"
else
  printf 'Automated release %s\n' "$DATE"
fi
