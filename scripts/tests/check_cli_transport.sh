#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

# Guardrail (CLAUDE.md §5): CLI runtime HTTP calls go through internal/clihttp,
# which sends the admin token the daemon API checks. A direct net/http call is
# allowed only with an inline comment ON THE SAME LINE, with a reason:
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

# The direct net/http client uses: the package-level helpers, the default
# client and transport, a client of one's own (a literal, new(), a var of the
# value type), a RoundTrip by hand, and net/http imported under another name
# (which every pattern here would miss). `*http.Client {` is a return type, not
# a client: the [^*] excludes it.
patterns=(
  '\bhttp\.(Get|Head|Post|PostForm)\('
  '\bhttp\.Default(Client|Transport)\b'
  '(^|[^*.\w])http\.Client\s*\{'
  '\bnew\(http\.Client\)'
  '\bvar\s+\w+\s+http\.Client\b'
  '\.RoundTrip\('
  '^\s*(import\s+)?\w+\s+"net/http"'
)

# The CLI runtime code: the packages that serve a `cfm <command>` and call the
# daemon API. Whole directories, so a new file in them is covered; a missing
# path fails the check (a rename must not silently drop a package). Mixed
# packages (dnat, status) carry other clients too, each marked with an
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
  internal/unblock/waf.go
)
# webdetector and mysql mix the daemon with their CLI: only the CLI files.
# Each glob must match a file (a renamed target must not drop out silently).
globbed_dirs=(internal/webdetector internal/detectors/mysql)
globs=(
  'internal/webdetector/cli.go'
  'internal/webdetector/cli_*.go'
  'internal/webdetector/live.go'
  'internal/detectors/mysql/*_cli.go'
  'internal/detectors/mysql/mysql_live.go'
)

for p in "${paths[@]}" "${globbed_dirs[@]}"; do
  [[ -e "$p" ]] || { echo "FAIL: $(basename "$0"): $p does not exist (renamed? update the list)" >&2; exit 1; }
done
for g in "${globs[@]}"; do
  compgen -G "$g" >/dev/null || { echo "FAIL: $(basename "$0"): no file matches $g (renamed? update the list)" >&2; exit 1; }
done

# rg: 0 = matches, 1 = none, anything else = it could not search (a fail).
# Called as `x="$(search ...)" || exit 1`: an exit inside $(...) ends only the
# subshell. The test-file exclusion goes LAST: rg's later -g wins, so before a
# positive glob it would let cli_*_test.go back in.
search() {
  local out rc=0
  out="$(rg -n --no-heading --with-filename "$@" -g '!*_test.go')" || rc=$?
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
  a="$(search -e "$pat" "${paths[@]}")" || exit 1
  b="$(search "${glob_args[@]}" -e "$pat" "${globbed_dirs[@]}")" || exit 1
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # The marker counts only with a reason after it.
    [[ "$line" =~ clihttp-exception:[[:space:]]*[^[:space:]] ]] && continue
    # A Go comment line (file:line:  // ...) mentions, it does not call.
    code="${line#*:*:}"
    [[ "${code#"${code%%[![:space:]]*}"}" == //* ]] && continue
    if [[ $status -eq 0 ]]; then
      echo "[cli-transport] Found forbidden direct net/http calls in CLI runtime code:"
    fi
    echo "  $line"
    status=1
  done <<<"$a"$'\n'"$b"
done

if [[ $status -ne 0 ]]; then
  cat <<'MSG'

Use clihttp.Get/clihttp.Post/clihttp.Do instead, and import net/http as http.
If a direct net/http call is truly required (an external service, a local Unix
socket with its own token, a probe that is not the daemon API), keep it and add
an inline comment on the same line: // clihttp-exception: <why>
MSG
  exit 1
fi

echo "[cli-transport] OK: CLI runtime HTTP calls use clihttp (or documented exceptions)."
