#!/usr/bin/env bash
set -euo pipefail

# Guardrail: the auto-generated challenge/WAF bypass list (configs/challenge_waf_bypass.conf)
# is a geo include whose every prefix disables WAF + challenge for that IP space. This runs the
# offline validator + generator-logic unit tests (no network) so an over-broad/private/malformed
# prefix, or a regression in the generator's safety bounds, fails CI.
#
# Mirrors the generator's own rules by importing build_bypass_list — single source of truth.

cd "$(dirname "$0")/../.."

# The generator needs Python >= 3.9 (str.removeprefix; EL8's python3 is 3.6).
# BYPASS_PYTHON pins the interpreter; otherwise the newest python3.x >= 3.9 on
# PATH. None = FAIL, never a silent OK. This is the ONE interpreter selector:
# `make bypass-list` asks it with --which-python (prints the choice, exits).
#
# No bytecode: the test imports the generator from scripts/, and a
# scripts/__pycache__ left behind would be shipped by the deb/rpm copies.
export PYTHONDONTWRITEBYTECODE=1
py_ok() { command -v "$1" >/dev/null 2>&1 && "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; }
PY="${BYPASS_PYTHON:-}"
if [ -n "$PY" ]; then
  if ! py_ok "$PY"; then
    echo "[bypass-list] ERROR: BYPASS_PYTHON=$PY is missing or older than Python 3.9" >&2
    exit 1
  fi
else
  for c in python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
    if py_ok "$c"; then PY="$c"; break; fi
  done
fi
if [ -z "$PY" ]; then
  echo "[bypass-list] ERROR: no Python >= 3.9 on PATH (required to validate challenge_waf_bypass.conf; EL8: dnf install python39)" >&2
  exit 1
fi

if [ "${1:-}" = "--which-python" ]; then
  echo "$PY"
  exit 0
fi

"$PY" scripts/tests/bypass_list_test.py
echo "[bypass-list] OK: challenge_waf_bypass.conf validated and generator safety-logic tests passed."
