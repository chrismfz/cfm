#!/bin/sh
# cfm-cache-dirs.sh — create the Site Cache directories (and purge an unusable
# cache tree). Idempotent;
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
#   * an unhealthy cache tree is PURGED, not repaired. nginx creates the
#     levels=1:2 subdirs as the worker (cfm); a level dir left in another
#     group, or root-owned without group rwx (an older global-cache run, a
#     root-run nginx), blocks the worker. The probe checks both dir levels.
#     When it finds one, the zone's contents are deleted with `find -delete`
#     (which never follows a symlink) and nginx refills the cache as MISSes —
#     the cache is disposable. A recursive chmod/chgrp run as root over a tree
#     the worker can write to is avoided on purpose: the worker could race it
#     with symlinks. A healthy worker-owned tree is never touched.
#     After a purge a RELOADED edge still indexes the deleted files in its
#     keys_zone; as those entries age out nginx logs harmless
#     `[crit] unlink() ... failed (2: No such file or directory)` lines (never
#     a 5xx). A RESTART of the edge rebuilds the index from disk and ends them.
#     Not detected (accepted): a root-owned cache FILE inside healthy dirs
#     (only if workers once ran as root after cfm created the dirs); it ages
#     out under the zone's inactive= eviction.
#   * a zone dir or /var/cache/nginx that is a symlink (moved to a bigger
#     disk) is followed for the owner/mode checks, but a symlinked zone's
#     tree is not probed or purged.
#
# The list below must match the proxy_cache_path dirs in configs/openresty.conf
# and configs/angie.conf and siteCacheDirNames in cmd/cfm/site_cache_dirs.go —
# scripts/tests/check_site_cache_config.sh enforces that.
#
# Usage: cfm-cache-dirs.sh [ROOT]   (ROOT defaults to /var/cache/nginx; the
# argument is for local testing against a scratch tree).
# Exit status: 0 when every dir exists with the expected owner/mode and no
# unusable cache tree is left at the end, 1 otherwise (callers in package
# scripts only warn; installers report it).

ROOT=${1:-/var/cache/nginx}
CFM_CACHE_DIRS="cfm_static cfm_micro_1s cfm_micro_2s cfm_micro_5s cfm_micro_10s cfm_micro_30s cfm_micro_60s"

# Without the cfm group (a manual run before the package created it; both
# installers create the account first) the dirs are still created, so `-t`
# passes; ownership and the purge wait for the next run (the daemon also
# re-applies the zone-dir ownership on start).
have_group=1
getent group cfm >/dev/null 2>&1 || have_group=0

if [ -d "$ROOT" ]; then
    chmod a+x "$ROOT" 2>/dev/null || true
else
    install -d -m 0755 -o root -g root "$ROOT" 2>/dev/null || mkdir -p "$ROOT"
    chmod 0755 "$ROOT" 2>/dev/null || true
fi

# unusable: a level dir (depth 1 or 2) the cfm workers cannot use.
unusable() {
    find "$1" -mindepth 1 -maxdepth 2 -type d \
        \( ! -group cfm -o \( ! -user cfm ! -perm -g=rwx \) \) \
        -print -quit 2>/dev/null | grep -q .
}

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
    if [ -d "$d" ] && [ ! -L "$d" ] && unusable "$d"; then
        # find exits non-zero whenever an entry vanishes mid-walk (a live
        # edge evicts and renames temp files constantly), so its status says
        # nothing about the result: re-probe instead.
        find "$d" -mindepth 1 -delete 2>/dev/null || true
        if unusable "$d"; then
            echo "cfm-cache-dirs: purge of $d is incomplete — a level dir the cfm workers cannot use is still there; the next run probes again." >&2
            rc=1
        else
            echo "cfm-cache-dirs: purged an unhealthy cache tree under $d (a level dir the cfm workers cannot use; nginx refills it). Restart (not reload) the edge to drop the stale cache index, or expect harmless [crit] unlink() ENOENT lines as old entries age out."
        fi
    fi
    if [ ! -d "$d" ] || [ "$(stat -L -c '%U:%G %a' "$d" 2>/dev/null)" != "root:cfm 770" ]; then
        echo "cfm-cache-dirs: $d is not root:cfm 0770" >&2
        rc=1
    fi
done
if [ "$have_group" = 0 ]; then
    echo "cfm-cache-dirs: group 'cfm' does not exist yet; dirs created, ownership not applied" >&2
    rc=1
fi
case "$(stat -L -c '%A' "$ROOT" 2>/dev/null)" in
    d??[xst]??[xst]??[xst]*) ;;
    *) echo "cfm-cache-dirs: $ROOT is not traversable (a+x) by the edge workers" >&2; rc=1 ;;
esac
exit "$rc"
