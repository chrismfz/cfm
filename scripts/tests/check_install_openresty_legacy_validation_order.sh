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

conf_dir="$tmp/usr/local/openresty/nginx/conf"
pkg_root="$tmp/usr/share/cfm/configs"
mkdir -p "$conf_dir" "$pkg_root"

cat >"$conf_dir/nginx.conf" <<'CONF'
http {
  rewrite_by_lua_file /usr/local/openresty/nginx/lua/cfm_waf.lua;
}
CONF

cat >"$conf_dir/cfm-panel-listeners.conf" <<'CONF'
server {
  access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua;
}
CONF

cat >"$pkg_root/openresty.conf" <<'CONF'
http {
  include cfm-panel-listeners.conf;
  access_by_lua_file /var/lib/cfm/lua/cfm.lua;
}
CONF

active_pattern='^[[:space:]]*(access_by_lua_file|content_by_lua_file|rewrite_by_lua_file|log_by_lua_file|init_by_lua_file|init_worker_by_lua_file|lua_package_path)([[:space:]]|;|$)'
legacy_pattern='/(etc/angie|usr/local/openresty/nginx)/lua/(cfm(_panel)?|cfm_rules|cfm_stats|cfm_waf|cfm_clamav|cfm_cache_log|log-cfm|sslcollector)\.lua'

check_legacy() {
  local conf_root="$1"
  local entrypoint="$2"
  local -a queue=() files=()
  local -A seen=()
  local current include_path f

  [ -f "$entrypoint" ] || return 0
  queue+=("$entrypoint")

  while [ "${#queue[@]}" -gt 0 ]; do
    current="${queue[0]}"
    queue=("${queue[@]:1}")
    [ -n "${seen["$current"]+x}" ] && continue
    seen["$current"]=1
    [ -f "$current" ] || continue
    files+=("$current")

    while IFS= read -r include_path; do
      include_path="${include_path%;}"
      include_path="${include_path#\"}"
      include_path="${include_path%\"}"
      case "$include_path" in
        /*) ;;
        *) include_path="$conf_root/conf/$include_path" ;;
      esac
      while IFS= read -r f; do
        [ -f "$f" ] || continue
        [ -z "${seen["$f"]+x}" ] && queue+=("$f")
      done < <(compgen -G "$include_path" || true)
    done < <(awk '($0 !~ /^[[:space:]]*#/) {if (match($0, /^[[:space:]]*include[[:space:]]+[^;]+;/)) {line=substr($0, RSTART, RLENGTH); sub(/^[[:space:]]*include[[:space:]]+/, "", line); print line}}' "$current")
  done

  for f in "${files[@]}"; do
    if awk -v p="$active_pattern" '($0 !~ /^[[:space:]]*#/ && $0 ~ p) {print FILENAME ":" FNR ":" $0}' "$f" | rg -n "$legacy_pattern" >/dev/null; then
      return 1
    fi
  done
}

if check_legacy "$tmp/usr/local/openresty/nginx" "$conf_dir/nginx.conf"; then
  echo "FAIL: pre-existing nginx.conf should fail" >&2
  exit 1
fi

if ! check_legacy "$tmp/usr/local/openresty/nginx" "$pkg_root/openresty.conf"; then
  echo "FAIL: packaged openresty.conf + staged includes should pass" >&2
  exit 1
fi

echo "OK: OpenResty candidate bundle validation ignores legacy path in existing deployed config"
