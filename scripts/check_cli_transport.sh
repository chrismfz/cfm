#!/usr/bin/env bash
set -euo pipefail

# Guardrail: CLI runtime HTTP calls must go through clihttp for consistent auth/transport behavior.
# Exceptions are allowed only when explicitly documented on the same line with:
#   clihttp-exception: <reason>

patterns=(
  '\bhttp\.Get\('
  '\bhttp\.Post\('
  '\bhttp\.DefaultClient\.Do\('
)

globs=(
  'internal/webdetector/*cli*.go'
  'internal/webdetector/live.go'
  'internal/detectors/mysql/*cli*.go'
  'internal/detectors/mysql/mysql_live.go'
)

status=0
for pat in "${patterns[@]}"; do
  rg_args=()
  for g in "${globs[@]}"; do
    rg_args+=("-g" "$g")
  done

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ "$line" == *"clihttp-exception:"* ]]; then
      continue
    fi

    if [[ $status -eq 0 ]]; then
      echo "[cli-transport] Found forbidden direct net/http calls in CLI runtime code:"
    fi
    echo "  $line"
    status=1
  done < <(rg -n --no-heading "${rg_args[@]}" "$pat" internal/webdetector internal/detectors/mysql || true)
done

if [[ $status -ne 0 ]]; then
  cat <<'MSG'

Use clihttp.Get/clihttp.Post/clihttp.Do instead.
If a direct net/http call is truly required (e.g., local Unix socket non-auth flow),
keep it and add an inline comment: // clihttp-exception: <why>
MSG
  exit 1
fi

echo "[cli-transport] OK: CLI runtime HTTP calls use clihttp (or documented exceptions)."
