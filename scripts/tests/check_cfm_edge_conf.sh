#!/usr/bin/env bash
# check_cfm_edge_conf.sh — configs/cfm-edge.conf must equal a fresh render of
# configs/openresty.conf (scripts/render-cfm-edge-conf.sh).
#
# cfm-edge runs the OpenResty edge config with its own paths. The config is
# generated, never hand-edited: a hand edit would be lost on the next render,
# and an openresty.conf change that was not re-rendered would ship a cfm-edge
# edge that silently lacks it (a WAF rule, a Site Cache rail). `make release`
# re-renders and commits it; this check catches a PR that changed
# openresty.conf without doing so. The render itself fails if any
# /usr/local/openresty path survives the map.
set -euo pipefail

cd "$(dirname "$0")/../.."

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -f configs/openresty.conf ] || fail "configs/openresty.conf missing"
[ -f configs/cfm-edge.conf ] || fail "configs/cfm-edge.conf missing (run: make cfm-edge-conf)"

tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT

./scripts/render-cfm-edge-conf.sh configs/openresty.conf "$tmpdir/cfm-edge.conf" \
    || fail "render-cfm-edge-conf.sh failed (see above)"

if ! diff -u configs/cfm-edge.conf "$tmpdir/cfm-edge.conf" >"$tmpdir/diff"; then
    head -40 "$tmpdir/diff" >&2
    fail "configs/cfm-edge.conf is stale or hand-edited; run: make cfm-edge-conf (and edit configs/openresty.conf, never cfm-edge.conf)"
fi

# The mappings that matter, named one by one (a render that went wrong in one
# of them would still be "current"):
#   - no pid directive: the package's compiled default is the unit's PIDFile
#     (Type=forking: a mismatch gets the edge killed), and cfm-edge moves it
#     without a CFM release;
#   - mime.types / sidecars from /etc/cfm-edge (the cfm-edge package ships
#     mime.types there; CFM's deploy puts the sidecars next to it);
#   - logs in /var/log/cfm-edge (rotated by the cfm-edge package);
#   - Lua only from the shared /var/lib/cfm/lua (no legacy edge Lua dir).
want() { grep -qE "$1" configs/cfm-edge.conf || fail "configs/cfm-edge.conf lacks: $2"; }
if grep -nE '^[[:space:]]*pid[[:space:]]' configs/cfm-edge.conf; then
    fail "configs/cfm-edge.conf sets pid (line above): the cfm-edge package owns it (its compiled default = its unit's PIDFile)"
fi
want '^# pid: set by the cfm-edge package' "the comment saying the package owns pid"
want '^[[:space:]]*include[[:space:]]+/etc/cfm-edge/mime\.types;' "include /etc/cfm-edge/mime.types"
want '^[[:space:]]*include[[:space:]]+/etc/cfm-edge/trusted_proxies\.conf;' "include /etc/cfm-edge/trusted_proxies.conf"
want '^[[:space:]]*include[[:space:]]+/etc/cfm-edge/cfm-panel-listeners\.conf;' "include /etc/cfm-edge/cfm-panel-listeners.conf"
want '^error_log[[:space:]]+/var/log/cfm-edge/error\.log' "error_log /var/log/cfm-edge/error.log"
want "^[[:space:]]*lua_package_path[[:space:]]+'/var/lib/cfm/lua/\\?\\.lua;;';" "lua_package_path '/var/lib/cfm/lua/?.lua;;'"
# Every log path stays under /var/log/cfm-edge (the vendor-rotated dir).
if grep -nE '^[[:space:]]*(access_log|error_log)[[:space:]]+/' configs/cfm-edge.conf | grep -vE '[[:space:]]/var/log/cfm-edge/'; then
    fail "configs/cfm-edge.conf logs outside /var/log/cfm-edge (lines above)"
fi

echo "[cfm-edge-conf] OK: configs/cfm-edge.conf is the current render of configs/openresty.conf, with cfm-edge's conf, log and Lua paths, and no pid (the package's)."
