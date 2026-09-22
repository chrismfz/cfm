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


tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/runtime.conf" <<'EOF'
# access_by_lua_file /etc/angie/lua/cfm.lua;
location / {
  access_by_lua_file /var/lib/cfm/lua/cfm.lua;
}
EOF

active_pattern='^[[:space:]]*(access_by_lua_file|content_by_lua_file|rewrite_by_lua_file|log_by_lua_file|init_by_lua_file|init_worker_by_lua_file|lua_package_path)([[:space:]]|;|$)'
legacy_pattern='/(etc/angie|usr/local/openresty/nginx)/lua/(cfm(_panel)?|cfm_rules|cfm_stats|cfm_waf|cfm_clamav|cfm_cache_log|log-cfm|sslcollector)\.lua'

# comment-only legacy path must pass
if awk -v p="$active_pattern" '($0 !~ /^[[:space:]]*#/ && $0 ~ p) {print FILENAME ":" FNR ":" $0}' "$tmp/runtime.conf" | rg -n "$legacy_pattern" >/dev/null; then
  echo "FAIL: comment-only legacy path should not be detected" >&2
  exit 1
fi

# active legacy path must fail
echo "rewrite_by_lua_file /usr/local/openresty/nginx/lua/cfm_waf.lua;" >>"$tmp/runtime.conf"
if ! awk -v p="$active_pattern" '($0 !~ /^[[:space:]]*#/ && $0 ~ p) {print FILENAME ":" FNR ":" $0}' "$tmp/runtime.conf" | rg -n "$legacy_pattern" >/dev/null; then
  echo "FAIL: active legacy path should be detected" >&2
  exit 1
fi

# shared runtime path in active directive must pass
cat >"$tmp/runtime-shared.conf" <<'EOF'
lua_package_path "/var/lib/cfm/lua/?.lua;;";
EOF
if awk -v p="$active_pattern" '($0 !~ /^[[:space:]]*#/ && $0 ~ p) {print FILENAME ":" FNR ":" $0}' "$tmp/runtime-shared.conf" | rg -n "$legacy_pattern" >/dev/null; then
  echo "FAIL: shared /var/lib/cfm/lua path should not be detected as legacy" >&2
  exit 1
fi

echo "OK: legacy Lua path detection ignores comments and flags active directives only"
