#!/usr/bin/env bash
# check_edge_peer_header.sh — every edge proxy_pass sends the edge's own TCP
# peer as X-CFM-Peer; a client's own never reaches the origin. The parser and
# the reasons are in check_edge_peer_header.py.
#
# Usage: scripts/tests/check_edge_peer_header.sh [conf...]
#   default: configs/openresty.conf configs/angie.conf configs/cfm-edge.conf
set -euo pipefail
cd "$(dirname "$0")/../.."
command -v python3 >/dev/null || { echo "check_edge_peer_header: python3 missing" >&2; exit 1; }
exec python3 -I scripts/tests/check_edge_peer_header.py "$@"
