#!/usr/bin/env bash
# Asserts the invariants the Lua delivery chain depends on.
#
# Lua modules ship ONLY as /var/lib/cfm/lua/*, owned by the package, so that an
# upgrade installs new modules, refreshes changed ones and REMOVES the ones a
# release dropped. Every link is load-bearing and none of it had a test — which
# is how an unfiltered `cp -a configs` shipped a duplicate copy of every module
# inside each rpm for months, feeding a postinst loop that re-copied it over the
# files rpm had just installed correctly.
#
# Static assertions on the build definitions: they cannot replace a real package
# build (no rpmbuild/fakeroot in CI), but they pin the mistakes that have
# actually happened here. Each one below was verified by reintroducing its
# failure mode and confirming this script rejects it.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }

MK=Makefile
SPEC=packaging/rpm/SPECS/cfm.spec
POSTINST=packaging/debian/DEBIAN/postinst

# rpm/shell comments must never satisfy an assertion — an earlier version of
# this file passed on a commented-out %files entry.
uncommented() { sed 's/[[:space:]]*#.*$//' "$1"; }

# ── 1. Every rsync into the Lua payload uses --delete ──────────────────────
# This is THE guarantee that a module deleted from the repo leaves the package
# (the deb target additionally wipes PKGROOT first; stage-pkgroot, which the
# rpm path uses, does not — so --delete is what both rely on).
mapfile -t lua_rsyncs < <(grep -nE 'rsync .*\$\(PKGROOT\)/var/lib/cfm/lua/' "$MK" || true)
[ "${#lua_rsyncs[@]}" -gt 0 ] || fail \
  "no rsync stages \$(CONFIG_DIR)/lua/ into \$(PKGROOT)/var/lib/cfm/lua/ — the Lua payload would ship stale or empty"
for line in "${lua_rsyncs[@]}"; do
  case "$line" in
    *--delete*) ;;
    *) fail "Makefile:${line%%:*} stages the Lua payload without --delete — a module deleted from the repo would survive in the package" ;;
  esac
done

# ── 2. Every rsync into the reference-config tree excludes lua/ ────────────
# A second copy there is what the retired postinst loop used to copy FROM.
mapfile -t cfg_rsyncs < <(grep -nE 'rsync .*\$\(PKGROOT\)/usr/share/cfm/configs/' "$MK" || true)
[ "${#cfg_rsyncs[@]}" -gt 0 ] || fail "no rsync stages the reference configs — check the Makefile"
for line in "${cfg_rsyncs[@]}"; do
  case "$line" in
    *'--exclude "lua/"'*) ;;
    *) fail "Makefile:${line%%:*} copies configs/ into usr/share/cfm/configs/ WITHOUT --exclude \"lua/\" — that ships a duplicate copy of every Lua module" ;;
  esac
done

# ── 3. The rpm %install must not undo rule 2 ───────────────────────────────
# %install re-copies %{projectroot}/configs over the staged tree, unfiltered.
# Required unconditionally: harmless if that copy is ever removed, and NOT
# gated on matching the copy's exact quoting (which made this check vacuous).
uncommented "$SPEC" | grep -qE 'rm -rf .*\{buildroot\}.*(_datadir\}|/usr/share)/cfm/configs/lua' || fail \
  "%install must rm -rf the Lua tree under the buildroot's cfm/configs — its unfiltered cp -a of configs/ otherwise ships every module a second time"

# ── 4. The rpm takes /var from the staged tree (where --delete applied) ────
uncommented "$SPEC" | grep -qE 'cp -a .*\{pkgroot\}/var' || fail \
  "%install must populate /var from %{pkgroot} — that is the only tree where the --delete staging applied"

# ── 5. %files OWNS each Lua file — this is what removes dropped modules ────
# Body lines start with file-attribute directives (%attr/%dir/%config), so the
# section can only end on a real section keyword.
uncommented "$SPEC" \
  | awk '/^%files([[:space:]]|$)/{f=1;next}
         f&&/^%(package|description|prep|build|install|check|clean|pre|post|preun|postun|posttrans|triggerin|changelog)([[:space:]]|$)/{f=0}
         f' \
  | grep -qE '(^|[[:space:]])(/var/lib/cfm/lua/\*|%\{_sharedstatedir\}/cfm/lua/\*)[[:space:]]*$' \
  || fail "the %files section must own /var/lib/cfm/lua/* — unowned files are never removed on upgrade, so a retired module lingers on every node forever"

# ── 6. Nothing reintroduces a second delivery path ────────────────────────
# The postinst loop that copied from /usr/share/cfm/configs/lua was removed
# 2026-09-22. No shipped script may read that path again, in any spelling.
for f in "$POSTINST" "$SPEC" scripts/package-proxy-config-deploy.sh \
         scripts/install-angie.sh scripts/install-openresty.sh; do
  [ -f "$f" ] || continue
  # A line that DELETES the path is the fix, not the failure — only reads count.
  if uncommented "$f" \
     | grep -vE '(^|[[:space:]])rm[[:space:]]+-[rf]' \
     | grep -qE '(share/cfm/configs/lua|share/cfm/lua|\{_datadir\}/cfm/configs/lua)'; then
    fail "$f reads a packaged Lua source path outside a comment — Lua has exactly one delivery path (/var/lib/cfm/lua, via the package manager)"
  fi
done

echo "OK: package Lua delivery invariants hold"
