#!/usr/bin/env bash
set -euo pipefail

# The set of Lua modules the package ships is NOT hand-listed here: it IS
# configs/lua/*.lua, which the Makefile rsyncs verbatim (--delete) into
# /var/lib/cfm/lua/ for both the .deb and the .rpm. The installers cannot read
# the repo at install time, so each carries a literal CFM_LUA_MANIFEST array
# for its pre-flight ("are all required modules actually on disk before we
# reload the edge?"). This script's job is to keep those two arrays mechanically
# equal to the packaged set, so the list has ONE source of truth and cannot
# drift — which is exactly what went wrong before: three copies existed (here,
# and one per installer) and all three disagreed. Four modules were missing from
# both installer manifests, among them cfm_fppolicy.lua: its call sites are
# pcall-guarded and fail OPEN, so a package that failed to deliver it would have
# passed pre-flight and then silently stopped enforcing armed fingerprint
# policies — no error, no log line, just a security control that is no longer
# there. That is the case this pre-flight is most worth having for.

packaged_lua() {
  local f
  for f in configs/lua/*.lua; do basename "$f"; done | sort
}

installer_manifest() {
  awk '/^readonly CFM_LUA_MANIFEST=\(/ {inside=1; next} inside && /^\)/ {inside=0} inside' "$1" \
    | sed 's/#.*//' | tr -s ' \t' '\n' | sed '/^$/d' | sort
}

# No engine-specific Lua path may survive in a shipped conf: every engine reads
# the SHARED /var/lib/cfm/lua.
for conf in configs/angie.conf configs/openresty.conf configs/cfm-panel-listeners.conf.in; do
  if rg -n '/etc/angie/lua/(cfm|log-cfm|sslcollector)|/usr/local/openresty/nginx/lua/(cfm|log-cfm|sslcollector)' "$conf" >/dev/null; then
    echo "legacy engine-specific Lua path found in $conf" >&2
    exit 1
  fi
done

for script in scripts/install-angie.sh scripts/install-openresty.sh; do
  if ! diff_out="$(diff <(packaged_lua) <(installer_manifest "$script"))"; then
    echo "CFM_LUA_MANIFEST in $script does not match the packaged set (configs/lua/*.lua):" >&2
    echo "$diff_out" | sed -n 's/^< /  missing from the installer: /p;s/^> /  in the installer but not packaged: /p' >&2
    echo "  fix the array in $script (the packaged directory is the source of truth)" >&2
    exit 1
  fi
  rg -q 'CFM_SHARED_LUA_DIR="/var/lib/cfm/lua"' "$script" || { echo "missing shared dir in $script" >&2; exit 1; }
done

echo "OK: shared lua layout + installer manifest checks passed"

if [ -e configs/angie-cfm-panel-listeners.conf ] || [ -e configs/openresty-cfm-panel-listeners.conf ]; then
  echo "legacy duplicated panel listener templates must not exist" >&2
  exit 1
fi

rg -q "cfm-panel-listeners.conf.in" scripts/install-angie.sh || { echo "install-angie.sh must render canonical panel listener template" >&2; exit 1; }
rg -q "cfm-panel-listeners.conf.in" scripts/install-openresty.sh || { echo "install-openresty.sh must render canonical panel listener template" >&2; exit 1; }

echo "OK: single template ownership enforced"
