#!/usr/bin/env bash
# check_install_edge.sh — scripts/install-edge.sh stays prepare-only.
#
# The installer adopts cfm-edge and PRINTS the switch; the operator runs it.
# Taking the edge out of the path (`cfm dnat off`), swapping the units and
# putting it back (`cfm dnat on`) are the operator's calls, so this pins:
#
# 1. No executed line (comments and heredoc bodies, i.e. the printed steps,
#    removed) runs systemctl start/stop/restart/reload/enable/disable/…, a
#    `cfm dnat …`, or signals an edge (`-s stop|quit|reload`). Read-only
#    systemctl (is-active, status) is fine.
# 2. Its adoption line is the one package-proxy-config-deploy.sh looks for
#    (a drift would leave an adopted cfm-edge un-updated on every upgrade).
# 3. Sidecars + main config are tested together from a stage dir before
#    anything moves into /etc/cfm-edge; the live copy is tested again.
#    The IPv6 listen script runs only as a cfm-edge-scoped prestart.
# 4. It parses (bash -n).
# shellcheck disable=SC2016,SC2015  # literal $VAR patterns; fail-on-either tests
set -euo pipefail
cd "$(dirname "$0")/../.."

# A guardrail that cannot run its matcher must FAIL, never report OK.
for tool in awk grep bash; do
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
grep -q 'cfm dnat off' <<<"$ex" && fail "matcher kept a quoted heredoc body (the printed steps)"

if bad="$(grep -E 'systemctl[[:space:]]+(-[^[:space:]]+[[:space:]]+)*(start|stop|restart|try-restart|reload|reload-or-restart|try-reload-or-restart|enable|disable|reenable|mask|unmask|kill|isolate)\b' <<<"$ex")"; then
  fail "$SCRIPT runs a unit-changing systemctl (it must only print the switch):
$bad"
fi
if bad="$(grep -E '(^|[^A-Za-z_-])cfm["'\'']?[[:space:]]+["'\'']?dnat\b' <<<"$ex")"; then
  fail "$SCRIPT runs \`cfm dnat\` (taking the edge out of / into the path is the operator's call):
$bad"
fi
if bad="$(grep -E '[[:space:]]-s[[:space:]]+(stop|quit|reload|reopen)\b|(^|[^A-Za-z_])(kill|pkill|killall)[[:space:]]|(^|[^A-Za-z_])eval[[:space:]]' <<<"$ex")"; then
  fail "$SCRIPT signals a process or evals a command:
$bad"
fi
# The IPv6 listen script: `render` walks every engine and reloads the live
# one, `deploy` is the package's. Only a cfm-edge-scoped `prestart` (writes and
# tests, never reloads) may run.
if bad="$(grep -E '(listen-v6\.sh|"\$script")[^#]*[[:space:]](render|deploy)\b' <<<"$ex")"; then
  fail "$SCRIPT runs cfm-edge-listen-v6.sh render/deploy (it reloads the live edge):
$bad"
fi
if bad="$(grep -E '(listen-v6\.sh|"\$script")[^#]*[[:space:]]prestart\b' <<<"$ex" | grep -v 'CFM_EDGE_ENGINES="cfm-edge|')"; then
  fail "$SCRIPT runs cfm-edge-listen-v6.sh prestart for every engine (scope it with CFM_EDGE_ENGINES to cfm-edge):
$bad"
fi

# 2. Adoption marker parity.
mine="$(sed -n "s/^readonly EDGE_ADOPT_MARKER=\"\(.*\)\"$/\1/p" "$SCRIPT")"
theirs="$(sed -n "s/^CFMEDGE_ADOPT_MARKER='\(.*\)'$/\1/p" "$DEPLOY")"
[ -n "$mine" ] || fail "EDGE_ADOPT_MARKER not found in $SCRIPT"
[ -n "$theirs" ] || fail "CFMEDGE_ADOPT_MARKER not found in $DEPLOY"
[ "$mine" = "$theirs" ] || fail "adoption line differs: $SCRIPT '$mine' vs $DEPLOY '$theirs'"

# 3. The staged set is tested, then committed, then the live copy is tested.
t1="$(grep -nE '"\$EDGE_BIN" -t -c "\$STAGE/nginx.conf.test"' <<<"$ex" | head -1 | cut -d: -f2)"
side="$(grep -nE 'mv -f "\$STAGE/\$f" "\$EDGE_CONF_DIR/\$f"' <<<"$ex" | head -1 | cut -d: -f2)"
inst="$(grep -nE 'mv -f "\$STAGE/nginx.conf" "\$EDGE_MAIN_CONF"' <<<"$ex" | head -1 | cut -d: -f2)"
t2="$(grep -nE '"\$EDGE_BIN" -t -q;' <<<"$ex" | head -1 | cut -d: -f2)"
[ -n "$t1" ] && [ -n "$side" ] && [ -n "$inst" ] && [ -n "$t2" ] || fail "$SCRIPT must test the staged set (-t -c \$STAGE/nginx.conf.test), move the sidecars and the main config in, then test the live copy"
[ "$t1" -lt "$side" ] && [ "$t1" -lt "$inst" ] && [ "$inst" -lt "$t2" ] || fail "$SCRIPT must config-test before it moves anything into $EDGE_CONF_DIR (lines $t1 / $side / $inst / $t2)"
# Nothing writes into the live conf dir before the staged test.
if bad="$(awk -F': ' -v t="$t1" '$1+0 < t' <<<"$ex" | grep -E '(install|cp|mv|tee)[[:space:]].*"\$EDGE_CONF_DIR/|>[[:space:]]*"\$EDGE_(CONF_DIR/|MAIN_CONF)')"; then
  fail "$SCRIPT writes into the live conf dir before the staged config test:
$bad"
fi

echo "OK: install-edge.sh is prepare-only, adoption line matches the deploy, config tested before install"
