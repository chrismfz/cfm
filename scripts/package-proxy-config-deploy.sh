#!/bin/sh
# Validate and deploy packaged CFM proxy configs for already-installed engines.
# This hook intentionally does not install Angie/OpenResty or bootstrap their
# repositories/certificates; it only refreshes packaged config files when the
# engine's own config test succeeds.

CFM_CONFIG_DIR=${CFM_CONFIG_DIR:-/usr/share/cfm/configs}
CFM_FALLBACK_CERT_DIR=${CFM_FALLBACK_CERT_DIR:-/var/lib/cfm/certs/selfsigned}

ANGIE_DETECTED=0
ANGIE_DEPLOYED=0
ANGIE_ACTIVE=0
OPENRESTY_DETECTED=0
OPENRESTY_DEPLOYED=0
OPENRESTY_ACTIVE=0

find_first_executable() {
    ffe_cmd_name=$1
    shift

    ffe_found=$(command -v "$ffe_cmd_name" 2>/dev/null || true)
    if [ -n "$ffe_found" ] && [ -x "$ffe_found" ]; then
        printf '%s\n' "$ffe_found"
        return 0
    fi

    for ffe_candidate do
        if [ -x "$ffe_candidate" ]; then
            printf '%s\n' "$ffe_candidate"
            return 0
        fi
    done

    return 1
}

service_is_installed() {
    sii_unit=$1

    if ! command -v systemctl >/dev/null 2>&1; then
        return 1
    fi

    systemctl list-unit-files "$sii_unit" --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$sii_unit"
}

service_is_active() {
    sia_unit=$1

    if ! command -v systemctl >/dev/null 2>&1; then
        return 1
    fi

    systemctl is-active --quiet "$sia_unit" 2>/dev/null
}

report_service_status() {
    rss_engine=$1
    rss_unit=$2

    if ! command -v systemctl >/dev/null 2>&1; then
        echo "CFM proxy config: $rss_engine service status unavailable (systemctl not found)"
        return 0
    fi

    if service_is_active "$rss_unit"; then
        echo "CFM proxy config: $rss_engine service is active: $rss_unit"
    elif service_is_installed "$rss_unit"; then
        echo "CFM proxy config: $rss_engine service is installed but not active: $rss_unit"
    else
        echo "CFM proxy config: $rss_engine service unit not installed: $rss_unit"
    fi
}

set_engine_state() {
    ses_engine=$1
    ses_detected=$2
    ses_active=$3
    ses_deployed=$4

    case "$ses_engine" in
        Angie)
            ANGIE_DETECTED=$ses_detected
            ANGIE_ACTIVE=$ses_active
            ANGIE_DEPLOYED=$ses_deployed
            ;;
        OpenResty)
            OPENRESTY_DETECTED=$ses_detected
            OPENRESTY_ACTIVE=$ses_active
            OPENRESTY_DEPLOYED=$ses_deployed
            ;;
    esac
}

print_engine_summary_line() {
    pesl_engine=$1
    pesl_detected=$2
    pesl_active=$3
    pesl_deployed=$4

    if [ "$pesl_detected" -ne 1 ]; then
        echo "  $pesl_engine: not detected"
        return 0
    fi

    if [ "$pesl_active" -eq 1 ]; then
        pesl_active_text=active
    else
        pesl_active_text=inactive
    fi

    if [ "$pesl_deployed" -eq 1 ]; then
        pesl_deployed_text='config deployed'
    else
        pesl_deployed_text='config deploy failed'
    fi

    echo "  $pesl_engine: detected, $pesl_active_text, $pesl_deployed_text"
}

print_proxy_config_summary() {
    echo
    echo
    echo "CFM proxy config summary:"
    print_engine_summary_line Angie "$ANGIE_DETECTED" "$ANGIE_ACTIVE" "$ANGIE_DEPLOYED"
    print_engine_summary_line OpenResty "$OPENRESTY_DETECTED" "$OPENRESTY_ACTIVE" "$OPENRESTY_DEPLOYED"

    if [ "$ANGIE_ACTIVE" -eq 1 ] && [ "$OPENRESTY_ACTIVE" -eq 1 ]; then
        echo "  Active edge: ambiguous; both Angie and OpenResty services are active"
        echo "  Reload active edges with:"
        echo "    systemctl reload angie"
        echo "    systemctl reload openresty"
	echo
	echo
    elif [ "$ANGIE_ACTIVE" -eq 1 ]; then
        echo "  Active edge: Angie"
        echo "  Reload active edge with: systemctl reload angie"
	echo
	echo
    elif [ "$OPENRESTY_ACTIVE" -eq 1 ]; then
        echo "  Active edge: OpenResty"
        echo "  Reload active edge with: systemctl reload openresty"
	echo
	echo
    else
	echo
        echo "  Active edge: none detected"
        echo "  No active edge reload needed. Configs are ready if you later switch engines."
	echo
    fi
}

# render_listener_config ENGINE DST [LIVE_DEST]: render the listener template
# to DST. LIVE_DEST (default DST) is the install path written into its header,
# so a staged copy renders byte-identical to the one that goes live.
render_listener_config() {
    rlc_engine=$1
    rlc_dst=$2
    rlc_live_dest=${3:-$2}
    rlc_template=$CFM_CONFIG_DIR/cfm-panel-listeners.conf.in

    if [ ! -f "$rlc_template" ]; then
        echo "WARNING: CFM proxy config: packaged listener template missing: $rlc_template"
        return 1
    fi

    rlc_dst_dir=$(dirname "$rlc_dst")
    rlc_tmp=$rlc_dst.tmp.$$
    if ! mkdir -p "$rlc_dst_dir"; then
        echo "WARNING: CFM proxy config: failed to create directory: $rlc_dst_dir"
        return 1
    fi

    if ! sed \
        -e "s|@ENGINE@|$rlc_engine|g" \
        -e "s|@LISTENER_DEST@|$rlc_live_dest|g" \
        "$rlc_template" > "$rlc_tmp"; then
        rm -f "$rlc_tmp"
        echo "WARNING: CFM proxy config: failed to render $rlc_dst"
        return 1
    fi

    if ! install -m 0644 -o root -g root "$rlc_tmp" "$rlc_dst"; then
        rm -f "$rlc_tmp"
        echo "WARNING: CFM proxy config: failed to install $rlc_dst"
        return 1
    fi

    rm -f "$rlc_tmp"
    return 0
}

# The sidecars the main config includes from the engine's live config dir.
CFM_SIDECARS="trusted_proxies.conf challenge_waf_bypass.conf cfm-panel-listeners.conf"

# The live dir is never changed until the engine has tested the NEW main config
# with the NEW sidecars. They used to be written into it first, so a failed
# test (or a failed main-config deploy) left untested sidecars live next to the
# OLD main config, and the edge's next restart could fail on them.
#
# stage_sidecars ENGINE STAGE LIVE_DIR: build every new sidecar in STAGE.
stage_sidecars() {
    ss_engine=$1
    ss_stage=$2
    ss_live=$3

    for ss_name in $CFM_SIDECARS; do
        if [ "$ss_name" = cfm-panel-listeners.conf ]; then
            # Rendered, not shipped; its header names the LIVE path so the
            # staged copy is byte-identical to the one that goes live.
            render_listener_config "$ss_engine" "$ss_stage/$ss_name" "$ss_live/$ss_name" || return 1
            continue
        fi
        if [ ! -f "$CFM_CONFIG_DIR/$ss_name" ]; then
            echo "WARNING: CFM proxy config: packaged file missing: $CFM_CONFIG_DIR/$ss_name"
            return 1
        fi
        cp "$CFM_CONFIG_DIR/$ss_name" "$ss_stage/$ss_name" || return 1
    done
    return 0
}

# include_targets FILE: the path of every `include` directive, one per line,
# wherever it sits on the line (`server { include X; }` included).
include_targets() {
    grep -oE '(^|[[:space:];{}])include[[:space:]]+[^;]+;' "$1" \
        | sed 's/^.*include[[:space:]]*//; s/[[:space:]]*;$//'
}

# stage_main_config SRC STAGE LIVE_DIR: copy the packaged main config to
# STAGE/main.conf with each `include LIVE_DIR/<sidecar>;` pointed at STAGE, so
# `-t` reads the new sidecars without them being live. Fails if any include of
# a sidecar still points elsewhere afterwards (a path form this helper does not
# rewrite), because testing would then read the OLD file.
stage_main_config() {
    smc_src=$1
    smc_stage=$2
    smc_live=$3

    smc_live_re=$(printf '%s\n' "$smc_live" | sed 's/[][\.*^$|]/\\&/g')
    smc_sed=""
    for smc_name in $CFM_SIDECARS; do
        smc_name_re=$(printf '%s\n' "$smc_name" | sed 's/[.]/\\./g')
        smc_sed="$smc_sed -e s|$smc_live_re/$smc_name_re;|$smc_stage/$smc_name;|g"
    done
    # shellcheck disable=SC2086 # word-split on purpose: one -e per sidecar
    if ! sed $smc_sed "$smc_src" > "$smc_stage/main.conf"; then
        echo "WARNING: CFM proxy config: failed to stage $smc_src"
        return 1
    fi
    # Every include of a sidecar (by any path) must now read the staged copy:
    # the rewritten absolute path, or a bare relative name (a relative include
    # resolves against the -c file's dir, i.e. the stage).
    for smc_name in $CFM_SIDECARS; do
        if include_targets "$smc_stage/main.conf" | grep -F "$smc_name" \
            | grep -vxF -e "$smc_stage/$smc_name" -e "$smc_name" | grep -q .; then
            echo "WARNING: CFM proxy config: $smc_src includes $smc_name in a form this helper cannot redirect; not deploying untested sidecars"
            return 1
        fi
    done
    return 0
}

# The tested files go live in one step, commit_files. Each is first written
# next to its live one as .NAME.cfm-new.PID (and each live sidecar copied to
# .NAME.cfm-old.PID, or marked .NAME.cfm-absent.PID); a failure there leaves
# the live dir untouched. Then they are renamed in (sidecars, then the main
# config: same directory, so each swap is atomic), and if a rename fails, or
# the run is killed during them, the sidecars already renamed are put back.
# The temp names start with a dot and don't end in .conf, so an
# `include *.conf` glob never sees them.
CFM_COMMIT_LIVE=""   # live sidecar dir of the commit in progress
CFM_COMMIT_MAIN=""   # live main config of the commit in progress
CFM_COMMIT_BACKUP="" # the .cfm-prepkg backup this commit made (removed on rollback)
CFM_COMMITTING=0     # 1 while renames are under way (the trap rolls back)
CFM_RESTORE_FAILED=0 # 1 if a rollback could not put a sidecar back
CFM_KEEP_OLD=""      # sidecars whose .cfm-old copy cleanup must NOT remove

commit_files() {
    cf_stage=$1
    cf_live=$2
    cf_src=$3
    cf_dst=$4

    CFM_COMMIT_LIVE=$cf_live
    CFM_COMMIT_MAIN=$cf_dst
    cf_dst_dir=$(dirname "$cf_dst")
    if ! mkdir -p "$cf_live" "$cf_dst_dir"; then
        echo "WARNING: CFM proxy config: failed to create $cf_live / $cf_dst_dir"
        return 1
    fi

    for cf_name in $CFM_SIDECARS; do
        if ! install -m 0644 -o root -g root "$cf_stage/$cf_name" "$cf_live/.$cf_name.cfm-new.$$"; then
            echo "WARNING: CFM proxy config: failed to write $cf_live/.$cf_name.cfm-new.$$"
            commit_cleanup
            return 1
        fi
        if [ -e "$cf_live/$cf_name" ] || [ -L "$cf_live/$cf_name" ]; then
            cp -pP "$cf_live/$cf_name" "$cf_live/.$cf_name.cfm-old.$$" || { commit_cleanup; return 1; }
        else
            : > "$cf_live/.$cf_name.cfm-absent.$$" || { commit_cleanup; return 1; }
        fi
    done
    if ! install -m 0644 -o root -g root "$cf_src" "$(main_temp "$cf_dst")"; then
        echo "WARNING: CFM proxy config: failed to write the new config next to $cf_dst"
        commit_cleanup
        return 1
    fi
    if [ -f "$cf_dst" ]; then
        cf_backup=$cf_dst.cfm-prepkg.$(date +%Y%m%d%H%M%S)
        if ! cp -a "$cf_dst" "$cf_backup"; then
            echo "WARNING: CFM proxy config: failed to back up $cf_dst"
            commit_cleanup
            return 1
        fi
        CFM_COMMIT_BACKUP=$cf_backup
        echo "CFM proxy config: backed up $cf_dst to $cf_backup"
    fi

    CFM_COMMITTING=1
    for cf_name in $CFM_SIDECARS; do
        if ! mv -f "$cf_live/.$cf_name.cfm-new.$$" "$cf_live/$cf_name"; then
            echo "WARNING: CFM proxy config: failed to install $cf_live/$cf_name; restoring the previous sidecars"
            commit_rollback
            return 1
        fi
    done
    if ! mv -f "$(main_temp "$cf_dst")" "$cf_dst"; then
        echo "WARNING: CFM proxy config: failed to deploy $cf_dst; restoring the previous sidecars"
        commit_rollback
        return 1
    fi
    CFM_COMMITTING=0
    CFM_COMMIT_BACKUP=""   # a real deploy keeps its backup, as before
    commit_cleanup
    echo "CFM proxy config: deployed $cf_dst"
    return 0
}

main_temp() {
    printf '%s/.%s.cfm-new.%s\n' "$(dirname "$1")" "$(basename "$1")" "$$"
}

# commit_rollback: put back each sidecar this commit actually renamed in (its
# .cfm-new temp is gone), or remove one that did not exist before; then clean
# up. If the main config was already renamed in too (a signal between that
# rename and the end of commit_files), the commit is complete: keep it.
commit_rollback() {
    if [ -n "$CFM_COMMIT_MAIN" ] && [ ! -e "$(main_temp "$CFM_COMMIT_MAIN")" ]; then
        CFM_COMMITTING=0
        CFM_COMMIT_BACKUP=""
        commit_cleanup
        return 0
    fi
    for cr_name in $CFM_SIDECARS; do
        cr_live=$CFM_COMMIT_LIVE/$cr_name
        [ -e "$CFM_COMMIT_LIVE/.$cr_name.cfm-new.$$" ] && continue   # never renamed in
        if [ -e "$CFM_COMMIT_LIVE/.$cr_name.cfm-old.$$" ] || [ -L "$CFM_COMMIT_LIVE/.$cr_name.cfm-old.$$" ]; then
            if ! mv -f "$CFM_COMMIT_LIVE/.$cr_name.cfm-old.$$" "$cr_live"; then
                # Keep the only good copy under a name cleanup never removes;
                # if even that rename fails, leave it where it is and exempt it.
                cr_kept=$cr_live.cfm-restore-failed.$$
                if ! mv -f "$CFM_COMMIT_LIVE/.$cr_name.cfm-old.$$" "$cr_kept" 2>/dev/null; then
                    cr_kept=$CFM_COMMIT_LIVE/.$cr_name.cfm-old.$$
                    CFM_KEEP_OLD="$CFM_KEEP_OLD $cr_name"
                fi
                CFM_RESTORE_FAILED=1
                echo "WARNING: CFM proxy config: could not restore $cr_live; the previous copy is $cr_kept - put it back before reloading the edge"
            fi
        elif [ -e "$CFM_COMMIT_LIVE/.$cr_name.cfm-absent.$$" ]; then
            rm -f "$cr_live"
        fi
    done
    [ -n "$CFM_COMMIT_BACKUP" ] && rm -f "$CFM_COMMIT_BACKUP"
    CFM_COMMIT_BACKUP=""
    CFM_COMMITTING=0
    commit_cleanup
}

# commit_cleanup: remove this run's temp, marker and backup files. (A backup
# that could not be restored was already moved to a kept name.)
commit_cleanup() {
    [ -n "$CFM_COMMIT_LIVE" ] || return 0
    for cc_name in $CFM_SIDECARS; do
        rm -f "$CFM_COMMIT_LIVE/.$cc_name.cfm-new.$$" "$CFM_COMMIT_LIVE/.$cc_name.cfm-absent.$$"
        case " $CFM_KEEP_OLD " in
            *" $cc_name "*) ;;   # the only good copy of a sidecar: keep it
            *) rm -f "$CFM_COMMIT_LIVE/.$cc_name.cfm-old.$$" ;;
        esac
    done
    [ -n "$CFM_COMMIT_MAIN" ] && rm -f "$(main_temp "$CFM_COMMIT_MAIN")"
    CFM_COMMIT_LIVE=""
    CFM_COMMIT_MAIN=""
}

# Exit trap: roll back a commit cut short, and remove the staging dir.
cleanup_proxy_deploy() {
    if [ "$CFM_COMMITTING" -eq 1 ]; then
        commit_rollback
    else
        commit_cleanup
    fi
    [ -n "$CFM_STAGE_DIR" ] && rm -rf "$CFM_STAGE_DIR"
    CFM_STAGE_DIR=""
}

ensure_fallback_cert_if_missing() {
    efc_cert_dir=$CFM_FALLBACK_CERT_DIR
    efc_cert_file=$efc_cert_dir/fullchain.pem
    efc_key_file=$efc_cert_dir/privkey.pem

    if [ -s "$efc_cert_file" ] && [ -s "$efc_key_file" ]; then
        chown root:cfm "$efc_cert_file" "$efc_key_file" 2>/dev/null || true
        chmod 0640 "$efc_cert_file" "$efc_key_file" 2>/dev/null || true
        echo "CFM proxy config: fallback certs already present: $efc_cert_file $efc_key_file"
        return 0
    fi

    if ! mkdir -p "$efc_cert_dir"; then
        return 1
    fi

    if ! openssl req \
        -x509 \
        -nodes \
        -days 3650 \
        -newkey rsa:2048 \
        -keyout "$efc_key_file" \
        -out "$efc_cert_file" \
        -subj "/C=US/ST=State/L=City/O=CFM/CN=localhost"; then
        return 1
    fi

    if ! chown root:cfm "$efc_cert_file" "$efc_key_file" 2>/dev/null; then
        return 1
    fi

    if ! chmod 0640 "$efc_cert_file" "$efc_key_file"; then
        return 1
    fi

    echo "CFM proxy config: created self-signed fallback cert: $efc_cert_file"
    return 0
}

process_engine() {
    pe_engine=$1
    pe_bin=$2
    pe_main_src=$3
    pe_main_dst=$4
    pe_sidecar_dir=$5
    pe_unit=$6

    pe_active=0
    if service_is_active "$pe_unit"; then
        pe_active=1
    fi
    set_engine_state "$pe_engine" 1 "$pe_active" 0

    echo "CFM proxy config: $pe_engine detected at $pe_bin"
    report_service_status "$pe_engine" "$pe_unit"

    pe_unchanged="leaving existing sidecars and $(basename "$pe_main_dst") unchanged"
    if [ ! -f "$pe_main_src" ]; then
        echo "WARNING: CFM proxy config: packaged $pe_engine config missing: $pe_main_src; $pe_unchanged"
        return 0
    fi
    # Stage inside the live dir itself (a dot-dir, so an `include *.conf` glob
    # never reaches it): no dependency on /tmp or TMPDIR, which may be full or
    # missing on the host, and nothing is written outside the engine's own dir.
    if ! mkdir -p "$pe_sidecar_dir" \
        || ! CFM_STAGE_DIR=$(mktemp -d "$pe_sidecar_dir/.cfm-proxy-stage.XXXXXX"); then
        CFM_STAGE_DIR=""
        echo "WARNING: CFM proxy config: $pe_engine: cannot create a staging dir; $pe_unchanged"
        return 0
    fi
    pe_stage=$CFM_STAGE_DIR

    if ! stage_sidecars "$pe_engine" "$pe_stage" "$pe_sidecar_dir" \
        || ! stage_main_config "$pe_main_src" "$pe_stage" "$pe_sidecar_dir"; then
        echo "WARNING: CFM proxy config: $pe_engine sidecar staging failed; $pe_unchanged"
        cleanup_proxy_deploy
        return 0
    fi

    # Test the packaged main config, staged so its sidecar includes read the
    # NEW sidecars. Sidecars are never tested with -c on their own: they are
    # not valid standalone nginx/OpenResty/Angie configs.
    echo "CFM proxy config: testing $pe_engine config with: $pe_bin -t -c $pe_stage/main.conf (packaged $pe_main_src + new sidecars)"
    if ! "$pe_bin" -t -c "$pe_stage/main.conf"; then
        echo "WARNING: CFM proxy config: $pe_engine config test failed; command failed: $pe_bin -t -c $pe_stage/main.conf"
        echo "WARNING: CFM proxy config: $pe_engine config test failed; $pe_unchanged"
        cleanup_proxy_deploy
        return 0
    fi
    echo "CFM proxy config: $pe_engine config test passed"

    if commit_files "$pe_stage" "$pe_sidecar_dir" "$pe_main_src" "$pe_main_dst"; then
        set_engine_state "$pe_engine" 1 "$pe_active" 1
    elif [ "$CFM_RESTORE_FAILED" -eq 1 ]; then
        echo "WARNING: CFM proxy config: $pe_engine: deploy failed and a sidecar could not be restored (see above); fix it before reloading $pe_engine"
    else
        echo "WARNING: CFM proxy config: $pe_engine: $pe_unchanged"
    fi
    cleanup_proxy_deploy

    return 0
}

# Install /etc/logrotate.d/logrotate-cfm and the hourly runner that lets its
# `maxsize` caps fire between the distro's once-a-day logrotate pass.
#
# This runs from the package postinst rather than only from
# install-{openresty,angie}.sh on purpose: the installers are run once by hand,
# so a host that has only ever been package-upgraded had no rotation at all for
# the OpenResty edge logs (/usr/local/openresty/nginx/logs/access.log reaching
# hundreds of GB) and none for /var/log/cfm/.
#
# Any failure is a warning, never fatal — an unrotated log must not abort an
# upgrade.
deploy_logrotate_config() {
    dlc_src="$CFM_CONFIG_DIR/logrotate-cfm"
    dlc_dst=${CFM_LOGROTATE_DST:-/etc/logrotate.d/logrotate-cfm}

    if [ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]; then
        echo "CFM logrotate: not running as root; skipping"
        return 0
    fi

    if [ ! -f "$dlc_src" ]; then
        echo "WARNING: CFM logrotate: packaged config missing: $dlc_src"
        return 0
    fi

    # A stray .bak beside the config is read as a SECOND config by any
    # logrotate whose taboo-extension list predates ".bak" — every path then
    # appears twice, logrotate reports "duplicate log entry" and the run
    # aborts. Older installers left exactly that file behind.
    if [ -e "$dlc_dst.bak" ]; then
        rm -f "$dlc_dst.bak" &&
            echo "CFM logrotate: removed stale $dlc_dst.bak (read as a duplicate config)"
    fi

    mkdir -p "$(dirname "$dlc_dst")" 2>/dev/null || true

    # Refresh policy: a fleet-wide rotation fix is worthless if it does not
    # land on upgrade, but an operator who retuned `rotate` must not lose it
    # silently — so stamp what we shipped and only overwrite a file still
    # matching that stamp. (This used to say "same policy as the Lua runtime
    # sync in the postinst"; that loop was removed 2026-09-22 because Lua is
    # package-owned and the loop's own protection could never fire. THIS stamp
    # logic is live and unrelated: different directory — /var/lib/cfm/.packaged,
    # not /var/lib/cfm/lua/.packaged — and it guards a file the package does
    # NOT own, which is exactly why it is still needed here.)
    #
    #   missing                      -> install
    #   identical to packaged        -> nothing to do
    #   unchanged since we last      -> force refresh (the normal upgrade path)
    #     deployed (stamp matches)
    #   locally modified             -> back up, then force refresh, and say so
    #
    # The stamp is what separates the last two: without it every version bump
    # would look like a local edit and spam backups.
    dlc_stamp_dir=/var/lib/cfm/.packaged
    dlc_stamp="$dlc_stamp_dir/logrotate-cfm.sha256"
    dlc_new_hash=$(sha256sum "$dlc_src" 2>/dev/null | awk '{print $1}')

    if [ -e "$dlc_dst" ]; then
        dlc_cur_hash=$(sha256sum "$dlc_dst" 2>/dev/null | awk '{print $1}')
        dlc_old_hash=""
        [ -f "$dlc_stamp" ] && dlc_old_hash=$(cat "$dlc_stamp" 2>/dev/null || true)

        if [ -n "$dlc_cur_hash" ] && [ "$dlc_cur_hash" = "$dlc_new_hash" ]; then
            echo "CFM logrotate: already current $dlc_dst"
            mkdir -p "$dlc_stamp_dir" 2>/dev/null || true
            printf '%s\n' "$dlc_new_hash" > "$dlc_stamp" 2>/dev/null || true
            deploy_logrotate_cron
            validate_logrotate_config "$dlc_dst"
            return 0
        fi

        if [ -z "$dlc_old_hash" ] || [ "$dlc_cur_hash" != "$dlc_old_hash" ]; then
            dlc_backup="/var/lib/cfm/backups/logrotate-cfm.local-prepkg.$(date +%s)"
            mkdir -p /var/lib/cfm/backups 2>/dev/null || true
            if cp -a "$dlc_dst" "$dlc_backup" 2>/dev/null; then
                echo "WARNING: CFM logrotate: $dlc_dst was modified locally; backup saved to $dlc_backup"
            else
                echo "WARNING: CFM logrotate: $dlc_dst was modified locally and could not be backed up; overwriting"
            fi
        fi
    fi

    if cp -f "$dlc_src" "$dlc_dst" 2>/dev/null; then
        chmod 0644 "$dlc_dst" 2>/dev/null || true
        mkdir -p "$dlc_stamp_dir" 2>/dev/null || true
        printf '%s\n' "$dlc_new_hash" > "$dlc_stamp" 2>/dev/null || true
        echo "CFM logrotate: deployed $dlc_dst"
    else
        echo "WARNING: CFM logrotate: failed to deploy $dlc_dst"
        return 0
    fi

    deploy_logrotate_cron
    validate_logrotate_config "$dlc_dst"

    return 0
}

# The hourly runner is a script, not an operator knob, so it is refreshed
# unconditionally. No dot in the basename: run-parts skips /etc/cron.hourly
# entries that contain one.
deploy_logrotate_cron() {
    dlcr_src="$CFM_CONFIG_DIR/cfm-logrotate.cron"
    dlcr_dst=${CFM_LOGROTATE_CRON_DST:-/etc/cron.hourly/cfm-logrotate}

    if [ ! -f "$dlcr_src" ]; then
        echo "WARNING: CFM logrotate: hourly runner missing: $dlcr_src"
        return 0
    fi

    mkdir -p "$(dirname "$dlcr_dst")" 2>/dev/null || true
    if cp -f "$dlcr_src" "$dlcr_dst" 2>/dev/null; then
        chmod 0755 "$dlcr_dst" 2>/dev/null || true
        echo "CFM logrotate: deployed hourly pass $dlcr_dst"
    else
        echo "WARNING: CFM logrotate: failed to deploy $dlcr_dst"
    fi

    return 0
}

validate_logrotate_config() {
    vlc_dst=$1

    command -v logrotate >/dev/null 2>&1 || return 0

    if logrotate -d "$vlc_dst" >/dev/null 2>&1; then
        echo "CFM logrotate: config validates"
    else
        echo "WARNING: CFM logrotate: logrotate rejected $vlc_dst; rotation may not run"
    fi

    return 0
}

deploy_logrotate_config
if ! ensure_fallback_cert_if_missing; then
    echo "WARNING: CFM proxy config: failed to create fallback self-signed certs; config tests may fail"
fi

# (After the line above: check_package_proxy_config_deploy.sh loads only what
# precedes it, and must not inherit these traps.)
CFM_STAGE_DIR=""
trap cleanup_proxy_deploy EXIT
trap 'exit 1' HUP INT TERM

ANGIE_BIN=$(find_first_executable angie /usr/sbin/angie /sbin/angie || true)
if [ -n "$ANGIE_BIN" ]; then
    process_engine \
        Angie \
        "$ANGIE_BIN" \
        "$CFM_CONFIG_DIR/angie.conf" \
        /etc/angie/angie.conf \
        /etc/angie \
        angie.service \
        angie\ -s\ reload
else
    echo "CFM proxy config: Angie not detected; skipping"
fi

OPENRESTY_BIN=$(find_first_executable openresty /usr/bin/openresty /usr/local/openresty/nginx/sbin/openresty || true)
if [ -n "$OPENRESTY_BIN" ]; then
    process_engine \
        OpenResty \
        "$OPENRESTY_BIN" \
        "$CFM_CONFIG_DIR/openresty.conf" \
        /usr/local/openresty/nginx/conf/nginx.conf \
        /usr/local/openresty/nginx/conf \
        openresty.service \
        /usr/local/openresty/sbin/nginx\ -s\ reload
else
    echo "CFM proxy config: OpenResty not detected; skipping"
fi

print_proxy_config_summary

exit 0
