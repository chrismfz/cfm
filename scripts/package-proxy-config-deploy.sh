#!/bin/sh
# Validate and deploy packaged CFM proxy configs for already-installed engines.
# This hook intentionally does not install Angie/OpenResty or bootstrap their
# repositories/certificates; it only refreshes packaged config files when the
# engine's own config test succeeds.

CFM_CONFIG_DIR=/usr/share/cfm/configs

find_first_executable() {
    _cmd_name=$1
    shift

    _found=$(command -v "$_cmd_name" 2>/dev/null || true)
    if [ -n "$_found" ] && [ -x "$_found" ]; then
        printf '%s\n' "$_found"
        return 0
    fi

    for _candidate do
        if [ -x "$_candidate" ]; then
            printf '%s\n' "$_candidate"
            return 0
        fi
    done

    return 1
}

install_file() {
    _src=$1
    _dst=$2

    if [ ! -f "$_src" ]; then
        echo "WARNING: CFM proxy config: packaged file missing: $_src"
        return 1
    fi

    _dst_dir=$(dirname "$_dst")
    if ! mkdir -p "$_dst_dir"; then
        echo "WARNING: CFM proxy config: failed to create directory: $_dst_dir"
        return 1
    fi

    if ! install -m 0644 -o root -g root "$_src" "$_dst"; then
        echo "WARNING: CFM proxy config: failed to install $_dst"
        return 1
    fi

    return 0
}

render_listener_config() {
    _engine=$1
    _dst=$2
    _template=$CFM_CONFIG_DIR/cfm-panel-listeners.conf.in

    if [ ! -f "$_template" ]; then
        echo "WARNING: CFM proxy config: packaged listener template missing: $_template"
        return 1
    fi

    _dst_dir=$(dirname "$_dst")
    _tmp=$_dst.tmp.$$
    if ! mkdir -p "$_dst_dir"; then
        echo "WARNING: CFM proxy config: failed to create directory: $_dst_dir"
        return 1
    fi

    if ! sed \
        -e "s|@ENGINE@|$_engine|g" \
        -e "s|@LISTENER_DEST@|$_dst|g" \
        "$_template" > "$_tmp"; then
        rm -f "$_tmp"
        echo "WARNING: CFM proxy config: failed to render $_dst"
        return 1
    fi

    if ! install -m 0644 -o root -g root "$_tmp" "$_dst"; then
        rm -f "$_tmp"
        echo "WARNING: CFM proxy config: failed to install $_dst"
        return 1
    fi

    rm -f "$_tmp"
    return 0
}

prepare_sidecars() {
    _engine=$1
    _conf_dir=$2

    install_file "$CFM_CONFIG_DIR/trusted_proxies.conf" "$_conf_dir/trusted_proxies.conf" || return 1
    install_file "$CFM_CONFIG_DIR/challenge_waf_bypass.conf" "$_conf_dir/challenge_waf_bypass.conf" || return 1
    render_listener_config "$_engine" "$_conf_dir/cfm-panel-listeners.conf" || return 1

    return 0
}

deploy_main_config() {
    _engine=$1
    _src=$2
    _dst=$3

    if [ ! -f "$_src" ]; then
        echo "WARNING: CFM proxy config: packaged $_engine config missing: $_src"
        return 1
    fi

    _dst_dir=$(dirname "$_dst")
    if ! mkdir -p "$_dst_dir"; then
        echo "WARNING: CFM proxy config: failed to create directory: $_dst_dir"
        return 1
    fi

    if [ -f "$_dst" ]; then
        _backup=$_dst.cfm-prepkg.$(date +%Y%m%d%H%M%S)
        if cp -a "$_dst" "$_backup"; then
            echo "CFM proxy config: backed up $_dst to $_backup"
        else
            echo "WARNING: CFM proxy config: failed to back up $_dst; leaving existing $(basename "$_dst") unchanged"
            return 1
        fi
    fi

    if install -m 0644 -o root -g root "$_src" "$_dst"; then
        echo "CFM proxy config: deployed $_dst"
        return 0
    fi

    echo "WARNING: CFM proxy config: failed to deploy $_dst"
    return 1
}

process_engine() {
    _engine=$1
    _bin=$2
    _src=$3
    _dst=$4
    _sidecar_dir=$5

    echo "CFM proxy config: $_engine detected at $_bin"

    if ! prepare_sidecars "$_engine" "$_sidecar_dir"; then
        echo "WARNING: CFM proxy config: $_engine sidecar deployment failed; leaving existing $(basename "$_dst") unchanged"
        return 0
    fi

    echo "CFM proxy config: testing $_engine config with: $_bin -t -c $_src"
    if "$_bin" -t -c "$_src"; then
        echo "CFM proxy config: $_engine config test passed"
        deploy_main_config "$_engine" "$_src" "$_dst" || true
    else
        echo "WARNING: CFM proxy config: $_engine config test failed; command failed: $_bin -t -c $_src"
        echo "WARNING: CFM proxy config: $_engine config test failed; leaving existing $(basename "$_dst") unchanged"
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
        /etc/angie
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
        /usr/local/openresty/nginx/conf
else
    echo "CFM proxy config: OpenResty not detected; skipping"
fi

exit 0
