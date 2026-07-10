#!/usr/bin/env bash
set -euo pipefail

# Guardrail: the auto-generated challenge/WAF bypass list (configs/challenge_waf_bypass.conf)
# is a geo include whose every prefix disables WAF + challenge for that IP space. This runs the
# offline validator + generator-logic unit tests (no network) so an over-broad/private/malformed
# prefix, or a regression in the generator's safety bounds, fails CI.
#
# Mirrors the generator's own rules by importing build_bypass_list — single source of truth.

cd "$(dirname "$0")/../.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "[bypass-list] ERROR: python3 not found (required to validate challenge_waf_bypass.conf)" >&2
  exit 1
fi

python3 scripts/tests/bypass_list_test.py
echo "[bypass-list] OK: challenge_waf_bypass.conf validated and generator safety-logic tests passed."
