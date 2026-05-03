#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${1:-/var/log/openresty/access-panel.log}"

if [[ ! -f "$LOG_FILE" ]]; then
  echo "missing log file: $LOG_FILE" >&2
  exit 2
fi

# Expect at least one challenged request and one resumed/origin request for panel prefixes.
challenge_re='host=(cpanel\.|whm\.|webmail\.|webdisk\.).*decision=challenge'
resume_re='host=(cpanel\.|whm\.|webmail\.|webdisk\.).*(reason=challenge_pass_cookie|reason=challenge_bypass_ttl|decision=allow)'

if ! grep -E "$challenge_re" "$LOG_FILE" >/dev/null; then
  echo "no challenged panel-host entries found" >&2
  exit 1
fi

if ! grep -E "$resume_re" "$LOG_FILE" >/dev/null; then
  echo "no post-solve allow/resume panel-host entries found" >&2
  exit 1
fi

echo "panel challenge flow observed in $LOG_FILE"
