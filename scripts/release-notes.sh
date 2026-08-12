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
  out="$body"
else
  out="Automated release $DATE"
fi

# GitHub caps a release body at ~125,000 characters (and Linux caps a single
# argv entry at 128 KiB), so a huge accumulated section — the very backlog this
# tool exists to drain — must be trimmed or the release fails. Keep whole lines
# up to a byte budget (bytes >= chars, so this stays under GitHub's char limit)
# and append a pointer to the full CHANGELOG section.
CAP="${RELEASE_NOTES_MAX_BYTES:-100000}"
if [ "$(printf '%s' "$out" | wc -c)" -gt "$CAP" ]; then
  keep=$(( CAP > 200 ? CAP - 160 : CAP ))
  # Keep whole lines up to the byte budget. A here-string (not a pipe) feeds awk
  # so its early `exit` can't SIGPIPE a producer and trip `set -o pipefail`;
  # LC_ALL=C makes awk's length() count bytes, not locale characters.
  trimmed="$(LC_ALL=C awk -v cap="$keep" '{ n += length($0) + 1; if (n > cap) exit; print }' <<< "$out")"
  out="$trimmed
… (release notes truncated to fit GitHub's limit — see the full ## $DATE section in CHANGELOG.md)"
fi

printf '%s\n' "$out"
