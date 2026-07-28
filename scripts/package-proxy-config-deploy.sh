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

install_file() {
    if_src=$1
    if_dst=$2

    if [ ! -f "$if_src" ]; then
        echo "WARNING: CFM proxy config: packaged file missing: $if_src"
        return 1
    fi

    if_dst_dir=$(dirname "$if_dst")
    if ! mkdir -p "$if_dst_dir"; then
        echo "WARNING: CFM proxy config: failed to create directory: $if_dst_dir"
        return 1
    fi

    if ! install -m 0644 -o root -g root "$if_src" "$if_dst"; then
        echo "WARNING: CFM proxy config: failed to install $if_dst"
        return 1
    fi

    return 0
}

render_listener_config() {
    rlc_engine=$1
    rlc_dst=$2
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
        -e "s|@LISTENER_DEST@|$rlc_dst|g" \
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

prepare_sidecars() {
    ps_engine=$1
    ps_conf_dir=$2

    ps_sidecar_src=$CFM_CONFIG_DIR/trusted_proxies.conf
    ps_sidecar_dst=$ps_conf_dir/trusted_proxies.conf
    install_file "$ps_sidecar_src" "$ps_sidecar_dst" || return 1

    ps_sidecar_src=$CFM_CONFIG_DIR/challenge_waf_bypass.conf
    ps_sidecar_dst=$ps_conf_dir/challenge_waf_bypass.conf
    install_file "$ps_sidecar_src" "$ps_sidecar_dst" || return 1

    ps_sidecar_dst=$ps_conf_dir/cfm-panel-listeners.conf
    render_listener_config "$ps_engine" "$ps_sidecar_dst" || return 1

    return 0
}

deploy_main_config() {
    dmc_engine=$1
    dmc_src=$2
    dmc_dst=$3

    if [ ! -f "$dmc_src" ]; then
        echo "WARNING: CFM proxy config: packaged $dmc_engine config missing: $dmc_src"
        return 1
    fi

    dmc_dst_dir=$(dirname "$dmc_dst")
    if ! mkdir -p "$dmc_dst_dir"; then
        echo "WARNING: CFM proxy config: failed to create directory: $dmc_dst_dir"
        return 1
    fi

    if [ -f "$dmc_dst" ]; then
        dmc_backup=$dmc_dst.cfm-prepkg.$(date +%Y%m%d%H%M%S)
        if cp -a "$dmc_dst" "$dmc_backup"; then
            echo "CFM proxy config: backed up $dmc_dst to $dmc_backup"
        else
            echo "WARNING: CFM proxy config: failed to back up $dmc_dst; leaving existing $(basename "$dmc_dst") unchanged"
            return 1
        fi
    fi

    if install -m 0644 -o root -g root "$dmc_src" "$dmc_dst"; then
        echo "CFM proxy config: deployed $dmc_dst"
        return 0
    fi

    echo "WARNING: CFM proxy config: failed to deploy $dmc_dst"
    return 1
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

    if ! prepare_sidecars "$pe_engine" "$pe_sidecar_dir"; then
        echo "WARNING: CFM proxy config: $pe_engine sidecar deployment failed; leaving existing $(basename "$pe_main_dst") unchanged"
        return 0
    fi

    # Only test the engine's packaged main config with -c. Sidecar includes are
    # validated transitively through that main config; they are not valid
    # standalone nginx/OpenResty/Angie configs.
    echo "CFM proxy config: testing $pe_engine config with: $pe_bin -t -c $pe_main_src"
    if "$pe_bin" -t -c "$pe_main_src"; then
        echo "CFM proxy config: $pe_engine config test passed"
        if deploy_main_config "$pe_engine" "$pe_main_src" "$pe_main_dst"; then
            set_engine_state "$pe_engine" 1 "$pe_active" 1
        fi
    else
        echo "WARNING: CFM proxy config: $pe_engine config test failed; command failed: $pe_bin -t -c $pe_main_src"
        echo "WARNING: CFM proxy config: $pe_engine config test failed; leaving existing $(basename "$pe_main_dst") unchanged"
    fi

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

    # Same refresh policy as the Lua runtime sync in the postinst, and for the
    # same reason: a fleet-wide rotation fix is worthless if it does not land
    # on upgrade, but an operator who retuned `rotate` must not lose it
    # silently.
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
