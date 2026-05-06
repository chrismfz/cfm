#!/bin/sh
# Validate and deploy packaged CFM proxy configs for already-installed engines.
# This hook intentionally does not install Angie/OpenResty or bootstrap their
# repositories/certificates; it only refreshes packaged config files when the
# engine's own config test succeeds.

CFM_CONFIG_DIR=${CFM_CONFIG_DIR:-/usr/share/cfm/configs}

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

reload_command_for_engine() {
    rcfe_unit=$1
    rcfe_fallback=$2

    if service_is_active "$rcfe_unit" || service_is_installed "$rcfe_unit"; then
        printf 'systemctl reload %s\n' "${rcfe_unit%.service}"
        return 0
    fi

    printf '%s\n' "$rcfe_fallback"
}

report_reload_command() {
    rrc_engine=$1
    rrc_unit=$2
    rrc_fallback=$3

    rrc_command=$(reload_command_for_engine "$rrc_unit" "$rrc_fallback")
    echo "CFM proxy config: deployed $rrc_engine config; reload with: $rrc_command"
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

process_engine() {
    pe_engine=$1
    pe_bin=$2
    pe_main_src=$3
    pe_main_dst=$4
    pe_sidecar_dir=$5
    pe_unit=$6
    pe_reload_fallback=$7

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
            report_reload_command "$pe_engine" "$pe_unit" "$pe_reload_fallback"
        fi
    else
        echo "WARNING: CFM proxy config: $pe_engine config test failed; command failed: $pe_bin -t -c $pe_main_src"
        echo "WARNING: CFM proxy config: $pe_engine config test failed; leaving existing $(basename "$pe_main_dst") unchanged"
    fi

    return 0
}

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

exit 0
