#!/usr/bin/env bash
set -euo pipefail

# A guardrail that cannot run its own matcher must FAIL, never report OK.
# check_cli_transport.sh used to pipe `rg ... || true`, so on a runner without
# ripgrep it read zero matches and printed success while a real violation sat
# in the tree (found 2026-09-22).
command -v rg >/dev/null 2>&1 || {
  echo "FAIL: ripgrep (rg) is required by $(basename "$0") and is not installed" >&2
  exit 1
}


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
