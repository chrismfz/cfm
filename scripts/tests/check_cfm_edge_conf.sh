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

# The derivation is paths only, plus the generated header: anything else in the
# diff would mean the map rewrote a directive it should not have.
changed=$(diff configs/openresty.conf configs/cfm-edge.conf | grep -c '^>' || true)
[ "$changed" -le 25 ] || fail "cfm-edge.conf differs from openresty.conf in $changed lines; the render is meant to change paths only"

echo "[cfm-edge-conf] OK: configs/cfm-edge.conf is the current render of configs/openresty.conf ($changed lines differ)."
