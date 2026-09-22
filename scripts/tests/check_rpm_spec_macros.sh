#!/usr/bin/env bash
# Rejects unescaped RPM macros in spec comments.
#
# Why this exists (measured, 2026-09-22 — it broke a release):
#   /usr/lib/rpm/redhat/macros on EL/Fedora defines %install as a MACRO whose
#   expansion ends in a newline followed by "%install". rpm expands macros on
#   EVERY spec line, comments included, and then splits the expanded buffer on
#   newlines — so a comment merely MENTIONING %install injects a real section
#   header and the build dies with:
#       error: line NNN: second %install
#   Debian/Ubuntu rpm does not ship redhat/macros, so `rpmspec -P` there parses
#   the same spec happily. That asymmetry is the trap: the spec looked fine on
#   the dev box and only failed on the EL build host, at `make release` time,
#   after the change had already merged.
#
# Rule 1 is the canonical RPM convention (write %% in comments); rule 2 pins the
# exact macro that bit us, including inline comments rule 1 cannot see.
# Both were verified by reintroducing the failure and confirming this rejects it.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }

shopt -s nullglob
specs=(packaging/rpm/SPECS/*.spec)
[ "${#specs[@]}" -gt 0 ] || fail \
  "no spec found under packaging/rpm/SPECS/ — this guard would pass while checking nothing"

# Collapse escaped macros (%%) so only *live* macro references remain. Doing it
# with a placeholder keeps a stray odd %% from re-pairing across the deletion.
unescaped() { sed 's/%%/\x01/g' "$1"; }

for spec in "${specs[@]}"; do
  # ── 1. A whole-line comment must not reference a macro ───────────────────
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    fail "$spec:${hit%%:*} — comment references an unescaped macro; rpm expands macros inside comments (write %% instead): ${hit#*:}"
  done < <(unescaped "$spec" | grep -nE '^[[:space:]]*#.*%' || true)

  # ── 2. %install may appear ONLY as its own section header ────────────────
  # Catches the same bug in a trailing comment on a code line, which rule 1
  # cannot distinguish from a shell '#' inside quotes or a URL fragment.
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    line="${hit#*:}"
    if [ "$(printf '%s' "$line" | tr -d '[:space:]')" = "%install" ]; then
      continue
    fi
    fail "$spec:${hit%%:*} — bare %install outside its section header expands to a newline + '%install' on EL and starts a second install section (write %%install): $line"
  done < <(unescaped "$spec" | grep -n '%install' || true)
done

echo "OK: rpm spec comments carry no unescaped macros"
