#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

# Guardrail (CLAUDE.md §5): CLI runtime HTTP calls go through internal/clihttp,
# which sends the admin token the daemon API checks. A direct net/http call is
# allowed only with an inline comment ON THE SAME LINE:
#   clihttp-exception: <reason>
# (an external service such as RIPE, a unix socket with its own token, a probe
# of the edge's listener rather than the API).
#
# A guardrail that cannot run its own matcher must FAIL, never report OK.
# This check used to pipe `rg ... || true`, so on a runner without ripgrep it
# read zero matches and printed success while a real violation sat in the tree
# (found 2026-09-22); and `|| true` also swallowed rg's own errors (exit 2).
command -v rg >/dev/null 2>&1 || {
  echo "FAIL: ripgrep (rg) is required by $(basename "$0") and is not installed" >&2
  exit 1
}

# The direct net/http client calls: the package-level helpers, the default
# client, and a client of one's own (http.Client{...}).
patterns=(
  '\bhttp\.(Get|Head|Post|PostForm)\('
  '\bhttp\.DefaultClient\b'
  '(^|[^*.\w])http\.Client\s*\{'
  '\bnew\(http\.Client\)'
)
# (a `*http.Client {` is a return type, not a client: the [^*] excludes it.)

# The CLI runtime code: the packages that serve a `cfm <command>` and call the
# daemon API. Whole directories, so a new file in them is covered; a missing
# path fails the check (a rename must not silently drop a package). Mixed
# packages (dnat, status) carry daemon-side clients too, each marked with an
# exception.
paths=(
  cmd/cfm
  internal/cli
  internal/dnat
  internal/edgecli
  internal/healthcli
  internal/lvecpu
  internal/mailqcli
  internal/srcreportcli
  internal/status
  internal/sslcollector/cli.go
)
# webdetector and mysql mix the daemon with their CLI: only the CLI files.
globbed_dirs=(internal/webdetector internal/detectors/mysql)
globs=(
  'internal/webdetector/*cli*.go'
  'internal/webdetector/live.go'
  'internal/detectors/mysql/*cli*.go'
  'internal/detectors/mysql/mysql_live.go'
)

for p in "${paths[@]}" "${globbed_dirs[@]}"; do
  [[ -e "$p" ]] || { echo "FAIL: $(basename "$0"): $p does not exist (renamed? update the list)" >&2; exit 1; }
done

# rg: 0 = matches, 1 = none, anything else = it could not search (a fail).
search() {
  local out rc=0
  out="$(rg -n --no-heading -g '!*_test.go' "$@")" || rc=$?
  if [[ $rc -gt 1 ]]; then
    echo "FAIL: rg failed (exit $rc): rg $*" >&2
    exit 1
  fi
  printf '%s' "$out"
}

glob_args=()
for g in "${globs[@]}"; do
  glob_args+=("-g" "$g")
done

status=0
for pat in "${patterns[@]}"; do
  hits="$(search "$pat" "${paths[@]}")"$'\n'"$(search "${glob_args[@]}" "$pat" "${globbed_dirs[@]}")"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" == *"clihttp-exception:"* ]] && continue
    # A Go comment line (file:line:  // ...) mentions, it does not call.
    code="${line#*:*:}"
    [[ "${code#"${code%%[![:space:]]*}"}" == //* ]] && continue
    if [[ $status -eq 0 ]]; then
      echo "[cli-transport] Found forbidden direct net/http calls in CLI runtime code:"
    fi
    echo "  $line"
    status=1
  done <<<"$hits"
done

if [[ $status -ne 0 ]]; then
  cat <<'MSG'

Use clihttp.Get/clihttp.Post/clihttp.Do instead.
If a direct net/http call is truly required (an external service, a local Unix
socket with its own token, a probe that is not the daemon API), keep it and add
an inline comment on the same line: // clihttp-exception: <why>
MSG
  exit 1
fi

echo "[cli-transport] OK: CLI runtime HTTP calls use clihttp (or documented exceptions)."
