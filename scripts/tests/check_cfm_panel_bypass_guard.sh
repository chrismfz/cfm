#!/usr/bin/env bash
set -euo pipefail

lua_file="${1:-configs/lua/cfm.lua}"

[[ -f "$lua_file" ]] || { echo "missing file: $lua_file" >&2; exit 2; }

# Ensure Step 0 bypass is guarded by explicit trusted bypass and policy-active deny.
rg -q 'explicit_trusted_bypass' "$lua_file"
rg -q 'not panel_challenge_policy_active' "$lua_file"

# Ensure canonical panel host prefixes can still flow into challenge policy path
# (i.e., no unconditional return based solely on prefix/path).
if rg -n 'if \(pfx == "cpanel" or pfx == "webmail" or pfx == "whm" or pfx == "mail"\)' "$lua_file" >/dev/null; then
  echo "found legacy unconditional panel-prefix bypass" >&2
  exit 1
fi

echo "panel bypass guard logic present in $lua_file"
