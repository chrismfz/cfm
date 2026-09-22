#!/usr/bin/env bash
# Rejects unescaped RPM macros in spec comments, and a stray %install section.
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
# Rule 1 flags MACRO-SHAPED references only (%name, %{name}): a bare percentage
# ("grew 50%") is harmless to rpm and telling someone to double it would be bad
# advice. A printf format in a comment ("%s") IS macro-shaped and is flagged on
# purpose — %%s is the correct way to write it in a spec, and it renders the
# same. Rule 1 is the canonical RPM convention (write %% in comments); rule 2 pins the
# exact macro that bit us — including a trailing comment on a code line, and a
# duplicated section header, neither of which rule 1 can see.
# Both were verified by reintroducing each failure mode and confirming this
# script rejects it.
#
# Rule 3 (added the same day, same EL-only class of trap): the TOP %changelog
# entry must be the build-dated `* %{cfm_changelog_date} …` one. EL10
# rpmbuild derives SOURCE_DATE_EPOCH from the newest entry and clamps every
# packaged file's mtime to it — a hand-dated "May 04 2026" top entry made
# installed files read "May 4" for months. And the usual RPM habit of adding a
# new entry on top breaks silently: an entry above the auto one is out of
# chronological order on any later build day, which EL9/EL10 report as an
# error yet still exit 0 — keeping ONLY the hand entry and dropping the rest
# of the changelog — while EL8 fails the build.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }

# A guardrail that cannot run its matcher must FAIL, never report OK (CLAUDE.md
# §5) — hence this check AND the exit-status check in scan() below, which is
# what actually catches a grep that dies at runtime.
for tool in grep sed; do
  command -v "$tool" >/dev/null 2>&1 || fail \
    "$tool is not installed — this guard would pass while checking nothing"
done

# grep exits 0 (matched) or 1 (no match); anything else is a broken matcher and
# must abort. This runs in the MAIN shell on purpose: inside $(...) the fail()
# would exit only the subshell and the guard would carry on reporting OK.
scan() { # <pattern> <file> -> sets $HITS
  local rc=0
  HITS=$(unescaped "$2" | grep -nE "$1") || rc=$?
  [ "$rc" -le 1 ] || fail "grep failed with status $rc on $2 — refusing to report OK"
}

# Collapse escaped macros (%%) so only *live* macro references remain. The
# placeholder keeps a stray odd %% from re-pairing across the deletion.
unescaped() { sed 's/%%/\x01/g' "$1"; }

shopt -s nullglob
specs=(packaging/rpm/SPECS/*.spec)
[ "${#specs[@]}" -gt 0 ] || fail \
  "no spec found under packaging/rpm/SPECS/ — this guard would pass while checking nothing"

violations=()

for spec in "${specs[@]}"; do
  # ── 1. A whole-line comment must not reference a macro ───────────────────
  # Macro-shaped only: a bare '%' (a percentage, a printf format) is harmless,
  # and telling someone to double it would be wrong advice.
  scan '^[[:space:]]*#.*%[A-Za-z_{]' "$spec"
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    violations+=("$spec:${hit%%:*} — comment references a macro; rpm expands macros inside comments, so write %% instead: ${hit#*:}")
  done <<< "$HITS"

  # ── 2. %install may appear ONLY as the one real section header ───────────
  # Anything else — a trailing comment on a code line, a heredoc, or a second
  # copy of the header itself — becomes "error: line NNN: second %install" on
  # EL. The word boundary keeps legitimate macros like %install_info out.
  scan '%install([^A-Za-z0-9_]|$)' "$spec"
  header_seen=0
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    line="${hit#*:}"
    # A real header sits at column 0 and carries nothing else. Only the first
    # one is the section; a second is exactly the failure we are guarding.
    if [ "$header_seen" -eq 0 ] && [ "$(printf '%s' "$line" | sed 's/[[:space:]]*$//')" = "%install" ]; then
      header_seen=1
      continue
    fi
    violations+=("$spec:${hit%%:*} — %install outside its section header; on EL it expands to a newline + '%install' and starts a second install section: $line")
  done <<< "$HITS"

  # ── 3. The top %changelog entry must be the build-dated one ──────────────
  scan '^%changelog[[:space:]]*$' "$spec"
  if [ -n "$HITS" ]; then
    first="${HITS%%$'\n'*}"
    cl="${first%%:*}"
    top=""
    while IFS= read -r l; do
      case "$l" in '*'*) top="$l"; break ;; esac
    done < <(sed -n "$((cl + 1)),\$p" "$spec")
    case "$top" in
      '* %{cfm_changelog_date} '*) ;;
      *) violations+=("$spec:$cl — the top %changelog entry must be '* %{cfm_changelog_date} …' (build-dated); found: ${top:-<no entry>}. EL10 rpmbuild dates every packaged file from the newest entry, and an entry above the auto one silently truncates the changelog on EL9/EL10 (EL8 fails the build). Add hand-written entries BELOW it.") ;;
    esac
  fi
done

if [ "${#violations[@]}" -gt 0 ]; then
  # Report every hit: the first one found is not necessarily the one that
  # breaks the build.
  for v in "${violations[@]}"; do echo "FAIL: $v" >&2; done
  exit 1
fi

echo "OK: rpm spec comments carry no unescaped macros; top %changelog entry is build-dated"
