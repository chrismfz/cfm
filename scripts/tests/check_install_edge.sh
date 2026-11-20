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
# 3. The main config is config-tested before it is installed, and the
#    installed copy is tested again.
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

# Executed lines only: drop heredoc bodies (from a line with <<WORD / <<'WORD'
# / <<-WORD to the line holding WORD alone) and comment-only lines.
executed() {
  awk '
    inhd { t=$0; sub(/^[ \t]+/, "", t); if (t == end) inhd=0; next }
    {
      line=$0
      if (match(line, /<<-?[ \t]*["\x27]?[A-Za-z_][A-Za-z_0-9]*["\x27]?/)) {
        w=substr(line, RSTART, RLENGTH); gsub(/^<<-?[ \t]*/, "", w); gsub(/["\x27]/, "", w)
        end=w; inhd=1
      }
      t=line; sub(/^[ \t]+/, "", t)
      if (substr(t, 1, 1) == "#") next
      print NR": "line
    }' "$1"
}

ex="$(executed "$SCRIPT")"
[ -n "$ex" ] || fail "no executed lines found in $SCRIPT (matcher broken?)"
grep -q 'print_next_steps' <<<"$ex" || fail "matcher lost the executed body of $SCRIPT"

if bad="$(grep -E 'systemctl[[:space:]]+(-[^[:space:]]+[[:space:]]+)*(start|stop|restart|try-restart|reload|reload-or-restart|try-reload-or-restart|enable|disable|reenable|mask|unmask|kill|isolate)\b' <<<"$ex")"; then
  fail "$SCRIPT runs a unit-changing systemctl (it must only print the switch):
$bad"
fi
if bad="$(grep -E '(^|[^A-Za-z_-])cfm[[:space:]]+dnat\b' <<<"$ex")"; then
  fail "$SCRIPT runs \`cfm dnat\` (taking the edge out of / into the path is the operator's call):
$bad"
fi
if bad="$(grep -E '[[:space:]]-s[[:space:]]+(stop|quit|reload|reopen)\b' <<<"$ex")"; then
  fail "$SCRIPT signals an edge process:
$bad"
fi

# 2. Adoption marker parity.
mine="$(sed -n "s/^readonly EDGE_ADOPT_MARKER=\"\(.*\)\"$/\1/p" "$SCRIPT")"
theirs="$(sed -n "s/^CFMEDGE_ADOPT_MARKER='\(.*\)'$/\1/p" "$DEPLOY")"
[ -n "$mine" ] || fail "EDGE_ADOPT_MARKER not found in $SCRIPT"
[ -n "$theirs" ] || fail "CFMEDGE_ADOPT_MARKER not found in $DEPLOY"
[ "$mine" = "$theirs" ] || fail "adoption line differs: $SCRIPT '$mine' vs $DEPLOY '$theirs'"

# 3. Test, then install, then test the installed copy.
t1="$(grep -nE '"\$EDGE_BIN" -t -c "\$EDGE_SRC_CONF"' <<<"$ex" | head -1 | cut -d: -f2)"
inst="$(grep -nE 'install .*"\$EDGE_SRC_CONF" "\$EDGE_MAIN_CONF"' <<<"$ex" | head -1 | cut -d: -f2)"
t2="$(grep -nE '"\$EDGE_BIN" -t -q \|\|' <<<"$ex" | head -1 | cut -d: -f2)"
[ -n "$t1" ] && [ -n "$inst" ] && [ -n "$t2" ] || fail "$SCRIPT must test CFM's config (-t -c), install it, then test the installed copy (-t -q ||)"
[ "$t1" -lt "$inst" ] && [ "$inst" -lt "$t2" ] || fail "$SCRIPT must config-test before it installs the main config (lines $t1 / $inst / $t2)"

echo "OK: install-edge.sh is prepare-only, adoption line matches the deploy, config tested before install"
