#!/usr/bin/env bash
# check_install_edge.sh — scripts/install-edge.sh stays prepare-only.
#
# The installer adopts cfm-edge and PRINTS the switch; the operator runs it.
# Taking the edge out of the path (`cfm edge off`, `cfm dnat off` on an older
# cfm), swapping the units and putting it back (`cfm edge on`) are the
# operator's calls, so this pins:
#
# 1. No executed line (comments and heredoc bodies, i.e. the printed steps,
#    removed) runs systemctl start/stop/restart/reload/enable/disable/…, a
#    `cfm dnat …` / `cfm edge on|off|panel|…`, or signals an edge
#    (`-s stop|quit|reload`). Read-only systemctl (is-active, status) is fine.
# 2. Its adoption line is the one package-proxy-config-deploy.sh looks for
#    (a drift would leave an adopted cfm-edge un-updated on every upgrade).
# 3. Sidecars + main config are tested together from a stage dir before
#    anything moves into /etc/cfm-edge; the live copy is tested again.
#    The IPv6 listen script runs only as a cfm-edge-scoped `prepare cfm-edge`.
# 4. It parses (bash -n).
# 5. The empty cfm-edge logs its config tests create are dropped again, never
#    while cfm-edge may run, a symlinked log dir included.
# 6. The three installers (edge, openresty, angie) re-run themselves under
#    bash when started with `sh`, before any step: under sh they used to run
#    their first steps and fail half-way (EL8: bash 4.4 in POSIX mode refuses
#    `<(...)`; Debian: dash). The guard is run here for real, under dash,
#    bash --posix, POSIXLY_CORRECT (no loop: one re-exec, then an error) and
#    stdin (no file to re-run: an error).
# shellcheck disable=SC2016,SC2015  # literal $VAR patterns; fail-on-either tests
set -euo pipefail
cd "$(dirname "$0")/../.."

# A guardrail that cannot run its matcher must FAIL, never report OK.
for tool in awk grep bash dash; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: $tool is not installed" >&2; exit 1; }
done

SCRIPT=scripts/install-edge.sh
DEPLOY=scripts/package-proxy-config-deploy.sh
fail() { echo "FAIL: $*" >&2; exit 1; }
[ -f "$SCRIPT" ] || fail "$SCRIPT missing"
[ -f "$DEPLOY" ] || fail "$DEPLOY missing"

bash -n "$SCRIPT" || fail "$SCRIPT does not parse"

# Executed lines only. Continuation lines (`\` at the end) are joined first.
# A heredoc with a QUOTED delimiter (<<'EOF') is plain text: its body is
# dropped. An UNQUOTED one is expanded by bash, so its body lines that hold a
# command substitution ($( or `) are kept. Comment-only lines are dropped.
executed() {
  awk '
    function emit(n, l,   t) { t=l; sub(/^[ \t]+/, "", t); if (substr(t, 1, 1) != "#") print n": "l }
    {
      if (cont != "") { line=cont" "$0; n=cn } else { line=$0; n=NR }
      if (!inhd && line ~ /\\$/) { cont=substr(line, 1, length(line)-1); cn=n; next }
      cont=""
    }
    inhd {
      t=line; sub(/^[ \t]+/, "", t)
      if (t == end) { inhd=0; next }
      if (!quoted && (index(line, "$(") || index(line, "`"))) print n": "line
      next
    }
    {
      if (match(line, /<<-?[ \t]*["\x27]?[A-Za-z_][A-Za-z_0-9]*["\x27]?/) && substr(line, RSTART+2, 1) != "<") {
        w=substr(line, RSTART, RLENGTH); gsub(/^<<-?[ \t]*/, "", w)
        quoted=(w ~ /["\x27]/); gsub(/["\x27]/, "", w)
        end=w; inhd=1
      }
      emit(n, line)
    }' "$1"
}

ex="$(executed "$SCRIPT")"
[ -n "$ex" ] || fail "no executed lines found in $SCRIPT (matcher broken?)"
grep -q 'print_next_steps' <<<"$ex" || fail "matcher lost the executed body of $SCRIPT"
grep -q 'is already the live edge' <<<"$ex" && fail "matcher kept a quoted heredoc body (the printed steps)"
# 'cfm edge off' sits in steps_edge's UNQUOTED rollback heredoc (it carries
# ${old}): keep a line of it unquoted, or this sentinel proves nothing.
# Anchored on the printed rollback line, so an EXECUTED `cfm edge off` is
# reported by the switch check below, not here.
grep -q 'cfm edge off            # (and' <<<"$ex" && fail "matcher kept a heredoc body line without a command substitution (the printed steps)"
# And the other way: an unquoted heredoc line WITH a command substitution
# (the report's "Config test:" line runs the edge's config test) is kept.
grep -qF 'Config test:  $(edge_test' <<<"$ex" || fail "matcher dropped an unquoted heredoc line with a command substitution"

if bad="$(grep -E 'systemctl[[:space:]]+(-[^[:space:]]+[[:space:]]+)*(start|stop|restart|try-restart|reload|reload-or-restart|try-reload-or-restart|enable|disable|reenable|mask|unmask|kill|isolate)\b' <<<"$ex")"; then
  fail "$SCRIPT runs a unit-changing systemctl (it must only print the switch):
$bad"
fi
if bad="$(grep -E '(^|[^A-Za-z_-])cfm["'\'']?[[:space:]]+["'\'']?dnat\b' <<<"$ex")"; then
  fail "$SCRIPT runs \`cfm dnat\` (taking the edge out of / into the path is the operator's call):
$bad"
fi
# `cfm edge` is the same commands under one name: its switches are refused
# too, strictly (web / panel / bypass / ipv6 on|off, even their read-only
# forms such as `panel status`, are not the installer's to run). `cfm edge
# help`, a bare `cfm edge`, `check` and `ipv6 [status]` pass; so does
# `realip`, which the installer runs on purpose (`cfm realip fix`). Like the
# `cfm dnat` check it reads the literal command: an indirect call
# (C=cfm; $C edge on) is not seen, so keep the installer's calls literal.
Q='["'"'"']?'
if bad="$(grep -E "(^|[^A-Za-z_-])cfm${Q}[[:space:]]+${Q}edge${Q}[[:space:]]+${Q}(on|off|panel|cpanel|bypass|web|ipv6${Q}[[:space:]]+${Q}(on|off))\\b" <<<"$ex")"; then
  fail "$SCRIPT runs a \`cfm edge\` switch (the switch is the operator's call):
$bad"
fi
if bad="$(grep -E '[[:space:]]-s[[:space:]]+(stop|quit|reload|reopen)\b|(^|[^A-Za-z_])(kill|pkill|killall)[[:space:]]|(^|[^A-Za-z_])eval[[:space:]]' <<<"$ex")"; then
  fail "$SCRIPT signals a process or evals a command:
$bad"
fi
if bad="$(grep -E '(^|[^A-Za-z_.-])(service|nft|initctl)[[:space:]]+[A-Za-z]' <<<"$ex")"; then
  fail "$SCRIPT runs service / nft (the unit swap and the DNAT are the operator's):
$bad"
fi
# The IPv6 listen script: `render` (also its default, with no argument)
# reloads a running edge, `deploy` is the package's, and `prestart` writes
# nothing new under the default. Only a cfm-edge-scoped `prepare cfm-edge`
# (render's decision, never a reload) may run, with the scope on the SAME
# command; any other use of "$script" is a file test or the feature check.
if bad="$(grep -F '"$script"' <<<"$ex" | grep -vE '\[ !? ?-f "\$script" \]' \
           | grep -vE "^[0-9]+: +if ! grep -q '\\|prepare\\|' \"\\\$script\"; then\$" \
           | grep -vE '^[0-9]+: +CFM_EDGE_ENGINES="cfm-edge\|[^";]*" sh "\$script" prepare cfm-edge \|\| true$')"; then
  fail "$SCRIPT runs the IPv6 listen script other than as the cfm-edge-scoped prepare:
$bad"
fi
if bad="$(grep -E '(listen-v6\.sh|"\$script")[^#]*[[:space:]](render|deploy|prestart)\b' <<<"$ex")"; then
  fail "$SCRIPT runs cfm-edge-listen-v6.sh render/deploy/prestart (a reload of the live edge, the package's run, or no write under the default):
$bad"
fi
# By its literal path: `status` only (no action at all is a render).
if bad="$(grep -E 'listen-v6\.sh' <<<"$ex" | grep -E '(^|[[:space:]])sh[[:space:]]' | grep -vE 'listen-v6\.sh status([[:space:]]|$)')"; then
  fail "$SCRIPT runs cfm-edge-listen-v6.sh by its path other than as \`status\`:
$bad"
fi
# The feature check must still recognise the shipped script, or install-edge.sh
# silently leaves cfm-edge on IPv4 (the check reads its usage line).
if ! grep -q '|prepare|' scripts/cfm-edge-listen-v6.sh; then
  fail "scripts/cfm-edge-listen-v6.sh no longer matches install-edge.sh's feature check grep -q '|prepare|' (keep the usage line, or change both)"
fi
if ! grep -qE '^[0-9]+: +CFM_EDGE_ENGINES="cfm-edge\|[^";]*" sh "\$script" prepare cfm-edge \|\| true$' <<<"$ex"; then
  fail "$SCRIPT no longer runs the cfm-edge-scoped 'prepare cfm-edge' (cfm-edge would start IPv4 only)"
fi

# 2. Adoption marker parity.
mine="$(sed -n "s/^readonly EDGE_ADOPT_MARKER=\"\(.*\)\"$/\1/p" "$SCRIPT")"
theirs="$(sed -n "s/^CFMEDGE_ADOPT_MARKER='\(.*\)'$/\1/p" "$DEPLOY")"
[ -n "$mine" ] || fail "EDGE_ADOPT_MARKER not found in $SCRIPT"
[ -n "$theirs" ] || fail "CFMEDGE_ADOPT_MARKER not found in $DEPLOY"
[ "$mine" = "$theirs" ] || fail "adoption line differs: $SCRIPT '$mine' vs $DEPLOY '$theirs'"

# 3. The staged set is tested (a failure dies), then committed (the main
#    config last), then the live copy is tested.
grep -qE '^[0-9]+: +if ! edge_test -c "\$STAGE/nginx.conf.test"; then$' <<<"$ex" \
  || fail "$SCRIPT must act on the staged test's result (if ! edge_test -c \"\$STAGE/nginx.conf.test\"; then)"
grep -qE '^[0-9]+: +if ! edge_test -q; then$' <<<"$ex" \
  || fail "$SCRIPT must act on the live copy's test result (if ! edge_test -q; then)"
t1="$(grep -nE 'edge_test -c "\$STAGE/nginx.conf.test"' <<<"$ex" | head -1 | cut -d: -f2)"
side="$(grep -nE 'mv -f "\$STAGE/\$f" "\$EDGE_CONF_DIR/\$f"' <<<"$ex" | head -1 | cut -d: -f2)"
inst="$(grep -nE 'mv -f "\$STAGE/nginx.conf" "\$EDGE_MAIN_CONF"' <<<"$ex" | head -1 | cut -d: -f2)"
t2="$(grep -nE 'if ! edge_test -q;' <<<"$ex" | head -1 | cut -d: -f2)"
[ -n "$t1" ] && [ -n "$side" ] && [ -n "$inst" ] && [ -n "$t2" ] || fail "$SCRIPT must test the staged set (-t -c \$STAGE/nginx.conf.test), move the sidecars and the main config in, then test the live copy"
[ "$t1" -lt "$side" ] && [ "$side" -lt "$inst" ] && [ "$inst" -lt "$t2" ] || fail "$SCRIPT must config-test before it moves anything into $EDGE_CONF_DIR (lines $t1 / $side / $inst / $t2)"
# Nothing writes into the live conf dir before the staged test.
if bad="$(awk -F': ' -v t="$t1" '$1+0 < t' <<<"$ex" | grep -E '(install|cp|mv|tee|sed -i|ln)[[:space:]].*("\$EDGE_CONF_DIR/|"\$EDGE_MAIN_CONF"|/etc/cfm-edge/)|>>?[[:space:]]*("\$EDGE_(CONF_DIR/|MAIN_CONF)|/etc/cfm-edge/)')"; then
  fail "$SCRIPT writes into the live conf dir before the staged config test:
$bad"
fi

# 5. The logs its config tests create (nginx -t opens every access_log /
#    error_log it names): only the EMPTY regular files that were not there
#    before go again, never while cfm-edge may run (a unit that is not
#    inactive/failed/unknown, `activating` and `reloading` included, or a
#    cfm-edge process), and a symlinked log dir is followed (trailing /).
#    The functions run as the installer runs them (bash, set -euo pipefail),
#    with systemctl / pgrep shims: the host's own units and processes never
#    decide a case.
for tool in find mktemp; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fns="$tmp/fns.sh"
{
  printf 'readonly EDGE_LOG_DIR="${CFM_CFMEDGE_LOG_DIR:-/var/log/cfm-edge}"\n'
  printf 'LOG_SNAPSHOT=""\nLOG_SNAPSHOT_TAKEN=0\n'
  for fn in log command_exists snapshot_edge_logs cfm_edge_may_run drop_test_created_logs; do
    body="$(awk -v fn="$fn" '$0 ~ "^"fn"\\(\\) *\\{" {p=1} p {print} p && /^}/ {exit}' "$SCRIPT")"
    [ -n "$body" ] || fail "$SCRIPT: function $fn not found"
    printf '%s\n' "$body"
  done
} >"$fns"
grep -qxF 'readonly EDGE_LOG_DIR="${CFM_CFMEDGE_LOG_DIR:-/var/log/cfm-edge}"' "$SCRIPT" \
  || fail "$SCRIPT: EDGE_LOG_DIR must default to /var/log/cfm-edge with the CFM_CFMEDGE_LOG_DIR seam"
mkdir -p "$tmp/bin"
cat >"$tmp/bin/systemctl" <<'EOF_SYSTEMCTL'
#!/bin/sh
case "$*" in
  "is-active cfm-edge.service") st=${FAKE_CFMEDGE_STATE:-inactive}; echo "$st"; [ "$st" = active ] ;;
  "is-active --quiet cfm-edge.service") [ "${FAKE_CFMEDGE_STATE:-inactive}" = active ] ;;
  *) exit 1 ;;
esac
EOF_SYSTEMCTL
cat >"$tmp/bin/pgrep" <<'EOF_PGREP'
#!/bin/sh
[ "$*" = "-x cfm-edge" ] && [ "${FAKE_CFMEDGE_PROC:-0}" = "1" ] && exit 0
exit 1
EOF_PGREP
chmod 0755 "$tmp/bin/systemctl" "$tmp/bin/pgrep"
el="$tmp/logs"
el_reset() {
  rm -rf "$el" "$el.real"; mkdir -p "$el"
  : >"$el/old-empty.log"; printf 'old\n' >"$el/old-full.log"
}
el_list() { (cd "$el" && find . -maxdepth 1 -type f | sort | tr '\n' ' '); }
# el_run BODY [VAR=VALUE...]: snapshot, BODY (the "config test"), drop.
el_run() {
  local body="$1"; shift
  env PATH="$tmp/bin:$PATH" CFM_CFMEDGE_LOG_DIR="$el" "$@" bash -c \
    'set -euo pipefail; . "$1"; snapshot_edge_logs; eval "$2"; drop_test_created_logs; echo rc=$?' sh "$fns" "$body" 2>&1
}
mk=': >"$CFM_CFMEDGE_LOG_DIR/error.log"; : >"$CFM_CFMEDGE_LOG_DIR/access.log"; printf x >"$CFM_CFMEDGE_LOG_DIR/written.log"'

el_reset
out="$(el_run "$mk")"
[ "$(el_list)" = "./old-empty.log ./old-full.log ./written.log " ] \
  || fail "cfm-edge inactive: only the test-created EMPTY logs must go; left: $(el_list) ($out)"
grep -qF "Removed $el/error.log (empty, created by the cfm-edge config test" <<<"$out" || fail "the removal is not reported: $out"
grep -qx 'rc=0' <<<"$out" || fail "drop_test_created_logs did not return 0 under set -e: $out"
for st in failed unknown; do
  el_reset; el_run "$mk" FAKE_CFMEDGE_STATE="$st" >/dev/null
  [ ! -e "$el/error.log" ] || fail "cfm-edge.service $st: the test-created log was kept"
done
for c in FAKE_CFMEDGE_STATE=active FAKE_CFMEDGE_STATE=activating FAKE_CFMEDGE_STATE=reloading FAKE_CFMEDGE_STATE=deactivating FAKE_CFMEDGE_PROC=1; do
  el_reset; el_run "$mk" "$c" >/dev/null
  [ -f "$el/error.log" ] && [ -f "$el/access.log" ] || fail "$c: a cfm-edge that may run lost its new empty logs (left: $(el_list))"
done
# A symlinked log dir (moved to a bigger disk) is cleaned like a plain one,
# and its old empty file is never mistaken for a new one.
el_reset; mv "$el" "$el.real"; ln -s "$el.real" "$el"
el_run "$mk" >/dev/null
[ ! -e "$el.real/error.log" ] && [ -f "$el.real/old-empty.log" ] \
  || fail "a symlinked cfm-edge log dir: left $(ls -A "$el.real" | tr '\n' ' ')"
rm -f "$el"; rm -rf "$el.real"
# A symlink created in the dir is not a log the test created (find -type f
# never lists one; the [ ! -L ] in the drop is the second fence).
el_reset; ln -s "$el/old-full.log" "$el/link.log"
el_run ': >"$CFM_CFMEDGE_LOG_DIR/error.log"' >/dev/null
[ -L "$el/link.log" ] && [ ! -e "$el/error.log" ] || fail "a symlink in the log dir was removed (or the new log kept)"
# Every config test goes through edge_test (-e /dev/null where the binary
# offers it: a test warning never fills a file startup log), and edge_test
# passes -e only where -h lists it (an unknown -e would fail every test).
# A test is the binary ("$EDGE_BIN", ${EDGE_BIN}, unquoted, or its path) in
# command position with a -t / -T flag (alone or combined, e.g. -tq) anywhere
# in that command; only the lines of edge_test's own body are exempt.
et_from="$(grep -nE '^edge_test\(\) *\{' "$SCRIPT" | head -1 | cut -d: -f1 || true)"
et_to="$(awk -v f="${et_from:-0}" 'NR > f && /^}/ { print NR; exit }' "$SCRIPT")"
[ -n "$et_from" ] && [ -n "$et_to" ] || fail "$SCRIPT: edge_test() not found"
et_cmd='(^[0-9]+:[[:space:]]*|[;&|(][[:space:]]*|\$\([[:space:]]*|(if|then|else|elif|do|while|until|!)[[:space:]]+)'
et_bin='"?(\$\{?EDGE_BIN\}?|/usr/sbin/cfm-edge)"?'
et_flag='([[:space:]][^|;&]*)?[[:space:]]-[A-Za-z]*[tT][A-Za-z]*([^A-Za-z0-9_-]|$)'
if bad="$(awk -F': ' -v a="$et_from" -v b="$et_to" '!($1+0 > a && $1+0 < b)' <<<"$ex" | grep -E "$et_cmd$et_bin$et_flag")"; then
  fail "$SCRIPT runs a cfm-edge config test outside edge_test:
$bad"
fi
# The pin catches the rewrites a direct test would take.
for et_case in '"$EDGE_BIN" -t -q' 'if ! "$EDGE_BIN" -c X -t; then' '"$EDGE_BIN" -t&&true' '"$EDGE_BIN" -q -t>/dev/null' \
  '"${EDGE_BIN}" -t -q' '$EDGE_BIN -t -q' '"$EDGE_BIN" -tq' '"$EDGE_BIN" -T -q' 'x="$("$EDGE_BIN" -t 2>&1)"' '/usr/sbin/cfm-edge -t'; do
  grep -qE "$et_cmd$et_bin$et_flag" <<<"1: $et_case" || fail "the edge_test pin misses: $et_case"
done
for et_case in 'die "$EDGE_BIN not found"' 'echo "FAILED: run $EDGE_BIN -t"' '[ -x "$EDGE_BIN" ] || die x' 'help="$("$EDGE_BIN" -h 2>&1 || true)"'; do
  grep -qE "$et_cmd$et_bin$et_flag" <<<"1: $et_case" && fail "the edge_test pin false-positives on: $et_case"
done
# -h is captured before grep reads it: in a pipe under pipefail, an early
# `grep -q` exit could SIGPIPE the binary and read as "no -e".
awk '/^edge_test\(\) *\{/,/^}/' "$SCRIPT" | grep -qF 'help="$("$EDGE_BIN" -h 2>&1 || true)"' \
  || fail "$SCRIPT edge_test: capture -h first (help=\"\$(\"\$EDGE_BIN\" -h 2>&1 || true)\"), never pipe it into grep"
cat >"$tmp/bin/fake-edge" <<'EOF_FAKE'
#!/bin/sh
case "$1" in
  -h) [ "${FAKE_HAS_E:-0}" = 1 ] && echo '  -e filename   : set error log file' >&2; exit 0 ;;
esac
echo "$*" >>"$FAKE_CALLS"
exit 0
EOF_FAKE
chmod 0755 "$tmp/bin/fake-edge"
efn="$(awk '/^edge_test\(\) *\{/,/^}/' "$SCRIPT")"
[ -n "$efn" ] || fail "$SCRIPT: edge_test not found"
for has in 1 0; do
  : >"$tmp/calls"
  FAKE_HAS_E="$has" FAKE_CALLS="$tmp/calls" bash -c 'set -euo pipefail; EDGE_BIN="$1"; eval "$2"; edge_test -q' sh "$tmp/bin/fake-edge" "$efn" \
    || fail "edge_test failed (has -e: $has)"
  want="-t -q"; [ "$has" = 1 ] && want="-e /dev/null -t -q"
  [ "$(cat "$tmp/calls")" = "$want" ] || fail "edge_test with -e offered=$has ran '$(cat "$tmp/calls")', want '$want'"
done
# The EXIT trap drops too (a run interrupted during a test).
awk '/^cleanup\(\) *\{/,/^}/' "$SCRIPT" | grep -qE '^ +drop_test_created_logs$' \
  || fail "$SCRIPT: cleanup (the EXIT trap) must call drop_test_created_logs"
# Without a snapshot (a run that never tested), and a second drop: no-ops.
el_reset; : >"$el/error.log"
env PATH="$tmp/bin:$PATH" CFM_CFMEDGE_LOG_DIR="$el" bash -c 'set -euo pipefail; . "$1"; drop_test_created_logs' sh "$fns" >/dev/null 2>&1 \
  || fail "drop_test_created_logs without a snapshot failed"
[ -f "$el/error.log" ] || fail "a drop without a snapshot removed a log"
el_reset
el_run 'drop_test_created_logs; : >"$CFM_CFMEDGE_LOG_DIR/error.log"' >/dev/null
[ -f "$el/error.log" ] || fail "a second drop on one snapshot must be a no-op"
# A missing log dir: no snapshot, no error, nothing created.
rm -rf "$el"
out="$(el_run ':')"
grep -qx 'rc=0' <<<"$out" && [ ! -e "$el" ] || fail "a missing cfm-edge log dir: $out"

# Every config test in the installer is followed by a drop on a snapshot
# taken before it (the report's own test included).
for fn in adopt_cfm_edge ensure_edge_listen_v6 print_next_steps; do
  body="$(awk -v fn="$fn" '$0 ~ "^"fn"\\(\\) *\\{" {p=1} p {print} p && /^}/ {exit}' "$SCRIPT")"
  sn="$(grep -n 'snapshot_edge_logs' <<<"$body" | head -1 | cut -d: -f1 || true)"
  ts="$(grep -nE 'edge_test |"\$script" prepare cfm-edge' <<<"$body" | grep -v '^[0-9]*: *#' | head -1 | cut -d: -f1 || true)"
  tl="$(grep -nE 'edge_test |"\$script" prepare cfm-edge' <<<"$body" | grep -v '^[0-9]*: *#' | tail -1 | cut -d: -f1 || true)"
  dr="$(grep -n 'drop_test_created_logs' <<<"$body" | tail -1 | cut -d: -f1 || true)"
  [ -n "$sn" ] && [ -n "$ts" ] && [ -n "$dr" ] && [ "$sn" -lt "$ts" ] && [ "$tl" -lt "$dr" ] \
    || fail "$SCRIPT $fn: the cfm-edge config test must sit between snapshot_edge_logs and drop_test_created_logs"
done

# 6. sh -> bash re-exec guard in each installer, before any step.
guard_tmp="$(mktemp -d)"
trap 'rm -rf "${tmp:-}" "$guard_tmp"' EXIT   # keeps the earlier trap's cleanup
for inst in scripts/install-edge.sh scripts/install-openresty.sh scripts/install-angie.sh; do
  [ -f "$inst" ] || fail "$inst missing"
  bash -n "$inst" || fail "$inst does not parse"
  g_start="$(grep -n -m1 '^case "${BASH_VERSION:-}:${SHELLOPTS:-}" in$' "$inst" | cut -d: -f1 || true)"
  [ -n "$g_start" ] || fail "$inst: no sh->bash re-exec guard (case \"\${BASH_VERSION:-}:\${SHELLOPTS:-}\" in)"
  g_end="$(awk -v s="$g_start" 'NR > s && /^esac$/ {print NR; exit}' "$inst")"
  [ -n "$g_end" ] || fail "$inst: the re-exec guard has no esac"
  # Nothing but comments and blank lines before it: it must run first.
  first_cmd="$(awk '!/^[[:space:]]*(#|$)/ {print NR; exit}' "$inst")"
  [ "$first_cmd" = "$g_start" ] || fail "$inst: line $first_cmd runs before the re-exec guard (line $g_start)"
  # Run the guard for real, followed by a bash-only line.
  t="$guard_tmp/$(basename "$inst")"
  { echo '#!/bin/sh'; sed -n "${g_start},${g_end}p" "$inst"; echo 'cat < <(echo "reexec-ok $CFM_BASH_REEXEC")'; } >"$t"
  [ "$(dash "$t" 2>&1)" = "reexec-ok 1" ] || fail "$inst: under dash the guard does not re-run it under bash: $(dash "$t" 2>&1)"
  [ "$(bash --posix "$t" 2>&1)" = "reexec-ok 1" ] || fail "$inst: under bash --posix (EL8 sh) the guard does not re-run it: $(bash --posix "$t" 2>&1)"
  [ "$(bash "$t" 2>&1)" = "reexec-ok " ] || fail "$inst: under plain bash the guard must not re-exec: $(bash "$t" 2>&1)"
  out="$(POSIXLY_CORRECT=1 timeout 10 bash "$t" 2>&1)" && fail "$inst: with POSIXLY_CORRECT the guard must stop with an error, got: $out"
  grep -q 'needs bash' <<<"$out" || fail "$inst: with POSIXLY_CORRECT, expected the needs-bash error, got: $out"
  out="$(timeout 10 dash <"$t" 2>&1)" && fail "$inst: run from stdin the guard must stop with an error, got: $out"
  grep -q 'needs bash' <<<"$out" || fail "$inst: from stdin, expected the needs-bash error, got: $out"
done

echo "OK: install-edge.sh is prepare-only, adoption line matches the deploy, config tested before install, test-created empty logs dropped (never while cfm-edge may run), installers re-run under bash from sh"
