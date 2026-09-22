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

etc_angie="$tmp/etc/angie"
pkg_root="$tmp/usr/share/cfm/configs"
mkdir -p "$etc_angie" "$pkg_root"

cat >"$etc_angie/angie.conf" <<'CONF'
# existing deployed config with legacy path (should be ignored for candidate validation)
http {
  rewrite_by_lua_file /etc/angie/lua/cfm_waf.lua;
}
CONF

cat >"$etc_angie/cfm-panel-listeners.conf" <<'CONF'
server {
  listen 12083;
  access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua;
}
CONF

cat >"$pkg_root/angie.conf" <<'CONF'
# packaged candidate config (should be validated)
http {
  include cfm-panel-listeners.conf;
  lua_package_path "/var/lib/cfm/lua/?.lua;;";
  access_by_lua_file /var/lib/cfm/lua/cfm.lua;
}
CONF

active_pattern='^[[:space:]]*(access_by_lua_file|content_by_lua_file|rewrite_by_lua_file|log_by_lua_file|init_by_lua_file|init_worker_by_lua_file|lua_package_path)([[:space:]]|;|$)'
legacy_pattern='/(etc/angie|usr/local/openresty/nginx)/lua/(cfm(_panel)?|cfm_rules|cfm_stats|cfm_waf|cfm_clamav|cfm_cache_log|log-cfm|sslcollector)\.lua'

check_legacy() {
  local conf_root="$1"
  local entrypoint="$2"
  local -a queue=()
  local -a files=()
  local -A seen=()
  local current include_path f

  [ -f "$entrypoint" ] || return 0
  queue+=("$entrypoint")

  while [ "${#queue[@]}" -gt 0 ]; do
    current="${queue[0]}"
    queue=("${queue[@]:1}")

    if [ -n "${seen["$current"]+x}" ]; then
      continue
    fi
    seen["$current"]=1

    [ -f "$current" ] || continue
    files+=("$current")

    while IFS= read -r include_path; do
      include_path="${include_path%;}"
      include_path="${include_path#\"}"
      include_path="${include_path%\"}"
      case "$include_path" in
        /*) ;;
        *) include_path="$conf_root/$include_path" ;;
      esac
      while IFS= read -r f; do
        [ -f "$f" ] || continue
        if [ -z "${seen["$f"]+x}" ]; then
          queue+=("$f")
        fi
      done < <(compgen -G "$include_path" || true)
    done < <(awk '($0 !~ /^[[:space:]]*#/) {if (match($0, /^[[:space:]]*include[[:space:]]+[^;]+;/)) {line=substr($0, RSTART, RLENGTH); sub(/^[[:space:]]*include[[:space:]]+/, "", line); print line}}' "$current")
  done

  for f in "${files[@]}"; do
    if awk -v p="$active_pattern" '($0 !~ /^[[:space:]]*#/ && $0 ~ p) {print FILENAME ":" FNR ":" $0}' "$f" | rg -n "$legacy_pattern" >/dev/null; then
      return 1
    fi
  done
}

# Regression assertion: validating current deployed tree fails because legacy path exists.
if check_legacy "$etc_angie" "$etc_angie/angie.conf"; then
  echo "FAIL: pre-existing /etc/angie/angie.conf should fail legacy-path check" >&2
  exit 1
fi

# Candidate-flow assertion: validating package candidate + staged includes passes.
if ! check_legacy "$etc_angie" "$pkg_root/angie.conf"; then
  echo "FAIL: packaged angie.conf + staged includes should pass legacy-path check" >&2
  exit 1
fi

echo "OK: candidate config bundle validation ignores legacy paths in pre-existing deployed angie.conf"
