#!/usr/bin/env bash
# The .deb ships NO dpkg conffile under /etc/cfm; postinst seeds those files
# from packaging/etc-cfm-files.list instead, the rpm's %config(noreplace)
# done by hand (an edited file is kept, the new default lands beside it as
# .dpkg-dist).
#
# Why (2026-11-23): every /etc/cfm file was a dpkg conffile, and CFM itself
# edits several of them (cfm allow / block, the WebUI's notify and detectors
# editors, cfm edge ipv6, cfm kernsec). On every upgrade whose package changed
# one of them, dpkg stopped to ask "keep or install the maintainer's
# version?": `apt upgrade -y` cannot answer that question, a broadcast
# multi-host session hung on every Debian node, and unattended-upgrades
# skipped cfm altogether ("conffile prompt"), so those nodes silently stayed
# on the old version. The rpm never had the problem (%config(noreplace) keeps
# the file and writes .rpmnew without asking).
#
# Pins:
#   1. packaging/debian/DEBIAN/conffiles does not exist (nor any /etc/cfm line
#      in one), and the deb target installs nothing into $(PKGROOT)/etc/cfm/;
#   2. every listed file exists in configs/ and has a valid mode;
#   3. the list names exactly the rpm spec's /etc/cfm %config(noreplace) files,
#      so the two packages seed the same set;
#   4. the deb target ships the list where postinst reads it, and postinst
#      reads it from there.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }

cd "$(dirname "$0")/../.."

LIST=packaging/etc-cfm-files.list
POSTINST=packaging/debian/DEBIAN/postinst
SPEC=packaging/rpm/SPECS/cfm.spec

# A guardrail that cannot run its matcher must FAIL, never report OK (CLAUDE.md §5).
for tool in grep sed sort comm awk; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed — this guard would pass while checking nothing"
done
for f in "$LIST" "$POSTINST" "$SPEC" Makefile; do
  [ -f "$f" ] || fail "$f not found — this guard would pass while checking nothing"
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# 1. no conffiles, no /etc/cfm payload
[ ! -e packaging/debian/DEBIAN/conffiles ] \
  || fail "packaging/debian/DEBIAN/conffiles is back: a conffile CFM or the operator edits stops every apt upgrade to ask, and unattended-upgrades skips cfm. Add the file to $LIST instead"
awk '/^deb:/{d=1; next} d && /^[^[:space:]#]/{d=0} d' Makefile >"$tmp/deb.mk"
[ -s "$tmp/deb.mk" ] || fail "could not find the deb target in the Makefile — refusing to report OK"
if grep -nE 'PKGROOT\)/etc/cfm/' "$tmp/deb.mk" >"$tmp/etc.hits"; then
  cat "$tmp/etc.hits" >&2
  fail "the deb target installs a file into /etc/cfm/: dpkg owns it as a plain file and overwrites the operator's copy on upgrade. Seed it from $LIST instead"
fi

# 2. the list is well-formed and every source exists
grep -Ev '^[[:space:]]*(#|$)' "$LIST" >"$tmp/list" || true
[ -s "$tmp/list" ] || fail "$LIST lists no file — refusing to report OK"
while read -r name mode extra; do
  [ -z "${extra:-}" ] || fail "$LIST: '$name $mode $extra' has more than two fields"
  case "$name" in ''|*/*|.*) fail "$LIST: bad file name '$name' (a plain name under /etc/cfm)" ;; esac
  case "$mode" in 0[0-7][0-7][0-7]) ;; *) fail "$LIST: $name has no valid octal mode ('$mode')" ;; esac
  [ -f "configs/$name" ] || fail "$LIST lists $name but configs/$name does not exist"
done <"$tmp/list"
awk '{print $1}' "$tmp/list" | LC_ALL=C sort >"$tmp/deb"
dups=$(uniq -d "$tmp/deb")
[ -z "$dups" ] || fail "$LIST lists a file twice: $dups"

# 3. same set as the rpm's %config(noreplace)
grep -E '^[^#]*%config\(noreplace\)[[:space:]]+/etc/cfm/' "$SPEC" \
  | sed -E 's#.*/etc/cfm/##; s/[[:space:]]+$//' | LC_ALL=C sort -u >"$tmp/rpm"
[ -s "$tmp/rpm" ] || fail "found no /etc/cfm %config(noreplace) entry in $SPEC — refusing to report OK"
if ! comm -3 "$tmp/deb" "$tmp/rpm" >"$tmp/diff" || [ -s "$tmp/diff" ]; then
  echo "only in $LIST (left) / only in $SPEC (right):" >&2
  cat "$tmp/diff" >&2
  fail "the .deb and the .rpm would seed different /etc/cfm files"
fi

# 4. shipped where postinst reads it
grep -qF 'install -m0644 packaging/etc-cfm-files.list "$(PKGROOT)/usr/share/cfm/etc-cfm-files.list"' "$tmp/deb.mk" \
  || fail "the deb target does not ship $LIST to /usr/share/cfm/etc-cfm-files.list"
grep -qE '^CFM_ETC_LIST=/usr/share/cfm/etc-cfm-files\.list$' "$POSTINST" \
  || fail "$POSTINST does not read the list from /usr/share/cfm/etc-cfm-files.list"

echo "OK: the .deb seeds $(wc -l <"$tmp/deb") /etc/cfm files (no conffile), the same set as the rpm's %config(noreplace)"
