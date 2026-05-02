#!/usr/bin/env bash
set -euo pipefail

manifest='cfm.lua cfm_panel.lua cfm_rules.lua cfm_stats.lua cfm_waf.lua cfm_clamav.lua cfm_cache_log.lua log-cfm.lua sslcollector.lua'

for conf in configs/angie.conf configs/openresty.conf configs/angie-cfm-panel-listeners.conf configs/openresty-cfm-panel-listeners.conf; do
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
