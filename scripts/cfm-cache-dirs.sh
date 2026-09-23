#!/bin/sh
# cfm-cache-dirs.sh — create and heal the Site Cache directories. Idempotent;
# run as root. The ONE copy of this logic: the deb postinst, the rpm %post and
# both edge installers (install-openresty.sh / install-angie.sh) call it, and it
# must run BEFORE any `openresty -t` / `angie -t`: every proxy_cache_path dir
# has to exist for the config test to pass, and only the leaf is created by the
# test itself (a missing parent is an [emerg]).
#
# What it guarantees:
#   * /var/cache/nginx exists and is traversable by the edge workers (user
#     cfm). The daemon runs under UMask=0077, so a parent it created used to be
#     root:root 0700 — every armed vhost then 500'd with "Permission denied".
#     A missing parent is created root:root 0755; an existing one only gains
#     a+x (traverse), nothing else is changed about it.
#   * each cache dir listed below is root:cfm 0770 (the cfm group writes).
#   * heal: nginx creates the levels=1:2 subdirs as the worker (cfm). A dir
#     left in another group, or root-owned without group rwx (an older
#     global-cache run, a root-run nginx), blocks the worker. The probe looks
#     at both levels (the cache files live below them and are written by the
#     worker); when it finds one it adds group rw/X first and only then moves
#     the group to cfm, so worker-owned files never lose access mid-heal (the
#     old chown-then-chmod order left them root:cfm 0600 for a moment).
#
# The list below must match the proxy_cache_path dirs in configs/openresty.conf
# and configs/angie.conf and the list in cmd/cfm/main.go —
# scripts/tests/check_site_cache_config.sh enforces that.
#
# Usage: cfm-cache-dirs.sh [ROOT]   (ROOT defaults to /var/cache/nginx; the
# argument exists for scripts/tests/cfm_cache_dirs_test.sh).
# Exit status: 0 when every dir exists with the expected owner/mode at the end,
# 1 otherwise (callers in package scripts ignore it; installers report it).

ROOT=${1:-/var/cache/nginx}
CFM_CACHE_DIRS="cfm_static cfm_micro_1s cfm_micro_2s cfm_micro_5s cfm_micro_10s cfm_micro_30s cfm_micro_60s"

# Without the cfm group (an edge installer run before the package created it)
# the dirs are still created, so `-t` passes; ownership and the heal wait for
# the next run (the daemon also re-applies the zone-dir ownership on start).
have_group=1
getent group cfm >/dev/null 2>&1 || have_group=0

if [ -d "$ROOT" ]; then
    chmod a+x "$ROOT" 2>/dev/null || true
else
    install -d -m 0755 -o root -g root "$ROOT" 2>/dev/null || mkdir -p "$ROOT"
    chmod 0755 "$ROOT" 2>/dev/null || true
fi

rc=0
for n in $CFM_CACHE_DIRS; do
    d="$ROOT/$n"
    [ -d "$d" ] || mkdir -p "$d" 2>/dev/null || true
    chmod 0770 "$d" 2>/dev/null || true
    if [ "$have_group" = 0 ]; then
        [ -d "$d" ] || rc=1
        continue
    fi
    chown root:cfm "$d" 2>/dev/null || true
    if [ -d "$d" ] && find "$d" -mindepth 1 -maxdepth 2 -type d \
            \( ! -group cfm -o \( ! -user cfm ! -perm -g=rwx \) \) \
            -print -quit 2>/dev/null | grep -q .; then
        chmod -R g+rwX "$d" 2>/dev/null || true
        chgrp -R cfm "$d" 2>/dev/null || true
        echo "cfm-cache-dirs: healed cache-tree ownership under $d (group cfm, group rw)"
    fi
    if [ ! -d "$d" ] || [ "$(stat -c '%U:%G %a' "$d" 2>/dev/null)" != "root:cfm 770" ]; then
        echo "cfm-cache-dirs: $d is not root:cfm 0770" >&2
        rc=1
    fi
done
if [ "$have_group" = 0 ]; then
    echo "cfm-cache-dirs: group 'cfm' does not exist yet; dirs created, ownership not applied" >&2
    rc=1
fi
case "$(stat -c '%A' "$ROOT" 2>/dev/null)" in
    d??[xst]??[xst]??[xst]*) ;;
    *) echo "cfm-cache-dirs: $ROOT is not traversable (a+x) by the edge workers" >&2; rc=1 ;;
esac
exit "$rc"
