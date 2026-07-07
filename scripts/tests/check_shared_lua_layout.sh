#!/usr/bin/env bash
set -euo pipefail

manifest='cfm.lua cfm_panel.lua cfm_rules.lua cfm_stats.lua cfm_waf.lua cfm_waf_util.lua cfm_waf_detectors.lua cfm_waf_excl.lua cfm_clamav.lua cfm_cache_log.lua cfm_clearance.lua cfm_geo.lua cfm_purge.lua cfm_filecache.lua cfm_origin_ka.lua log-cfm.lua sslcollector.lua'

for conf in configs/angie.conf configs/openresty.conf configs/cfm-panel-listeners.conf.in; do
  if rg -n '/etc/angie/lua/(cfm|log-cfm|sslcollector)|/usr/local/openresty/nginx/lua/(cfm|log-cfm|sslcollector)' "$conf" >/dev/null; then
    echo "legacy engine-specific Lua path found in $conf" >&2
    exit 1
  fi
done

for script in scripts/install-angie.sh scripts/install-openresty.sh; do
  for f in $manifest; do
    rg -q "configs/$f\"" "$script" || { echo "missing deploy entry for $f in $script" >&2; exit 1; }
  done
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
