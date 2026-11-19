#!/bin/sh
# render-cfm-edge-conf.sh — derive configs/cfm-edge.conf from configs/openresty.conf.
#
# cfm-edge (chrismfz/cfm-edge) runs the OpenResty edge config unchanged except
# for its paths: it is packaged like a distro nginx (/etc/cfm-edge,
# /var/log/cfm-edge, /run/cfm-edge.pid) instead of under /usr/local/openresty.
# One template, one derivation: never edit configs/cfm-edge.conf by hand; edit
# openresty.conf and re-run this. scripts/tests/check_cfm_edge_conf.sh fails CI
# when the committed file differs from a fresh render, or when any
# /usr/local/openresty path survives the map.
#
#   scripts/render-cfm-edge-conf.sh            # rewrite configs/cfm-edge.conf
#   scripts/render-cfm-edge-conf.sh SRC DST    # render SRC to DST (the check)
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=${1:-$ROOT/configs/openresty.conf}
DST=${2:-$ROOT/configs/cfm-edge.conf}

[ -f "$SRC" ] || { echo "render-cfm-edge-conf: missing $SRC" >&2; exit 1; }

tmp=$(mktemp "${DST}.XXXXXX")
trap 'rm -f "$tmp"' EXIT

# Order matters: the pid file and the legacy Lua dir before the generic dirs.
#   - pid: the unit's PIDFile=/run/cfm-edge.pid. A pid line that disagrees
#     makes systemd (Type=forking) wait for a file that never appears and
#     kill the edge.
#   - lua_package_path: cfm-edge never had a legacy Lua dir (CFM's Lua lives
#     only in /var/lib/cfm/lua), so that entry goes.
#   - the comment about OpenResty's default temp dirs names cfm-edge's.
{
    sed -n '1p' "$SRC"
    echo "#"
    echo "# GENERATED from configs/openresty.conf by scripts/render-cfm-edge-conf.sh."
    echo "# Do not edit: change openresty.conf and re-render (CI checks they match)."
    sed '1d' "$SRC"
} | sed \
    -e 's|/usr/local/openresty/nginx/logs/nginx\.pid|/run/cfm-edge.pid|g' \
    -e 's|;/usr/local/openresty/nginx/lua/?\.lua;|;|g' \
    -e 's|/usr/local/openresty/nginx/\*_temp|/var/lib/cfm-edge/*|g' \
    -e 's|^# the OpenResty package as root-owned|# the cfm-edge package as root-owned|' \
    -e 's|/usr/local/openresty/nginx/conf/|/etc/cfm-edge/|g' \
    -e 's|/usr/local/openresty/nginx/logs/|/var/log/cfm-edge/|g' \
    > "$tmp"

if grep -n '/usr/local/openresty' "$tmp" >&2; then
    echo "render-cfm-edge-conf: the lines above still name /usr/local/openresty; map them in this script" >&2
    exit 1
fi

chmod 0644 "$tmp"
mv -f "$tmp" "$DST"
trap - EXIT
