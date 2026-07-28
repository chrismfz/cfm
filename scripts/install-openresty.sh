#!/usr/bin/env bash
set -euo pipefail

readonly CFM_SHARED_LUA_DIR="/var/lib/cfm/lua"
readonly CFM_LUA_MANIFEST=(
    cfm.lua cfm_panel.lua cfm_panel_tunnel.lua cfm_rules.lua cfm_stats.lua
    cfm_waf.lua cfm_waf_util.lua cfm_waf_detectors.lua cfm_waf_excl.lua
    cfm_clamav.lua cfm_cache_log.lua cfm_clearance.lua cfm_geo.lua cfm_purge.lua
    cfm_filecache.lua cfm_origin_ka.lua cfm_bridge_cfg.lua
    log-cfm.lua sslcollector.lua
)

log() {
    echo "[+] $*"
}

warn() {
    echo "[!] $*" >&2
}

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

need_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        die "Please run as root"
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

detect_os() {
    [ -f /etc/os-release ] || die "/etc/os-release not found"
    # shellcheck disable=SC1091
    . /etc/os-release

    OS_ID="${ID:-}"
    OS_VERSION_ID="${VERSION_ID:-}"
    OS_FAMILY=""

    case "$OS_ID" in
        debian|ubuntu)
            OS_FAMILY="debian"
            ;;
        almalinux|rocky|rhel|centos|cloudlinux)
            OS_FAMILY="el"
            ;;
        *)
            case "${ID_LIKE:-}" in
                *debian*)
                    OS_FAMILY="debian"
                    ;;
                *rhel*|*fedora*|*centos*)
                    OS_FAMILY="el"
                    ;;
                *)
                    die "Unsupported OS: ID=${OS_ID:-unknown}, ID_LIKE=${ID_LIKE:-unknown}"
                    ;;
            esac
            ;;
    esac
}

install_prereqs_debian() {
    local pkgs=()

    dpkg -s wget >/dev/null 2>&1 || pkgs+=(wget)
    dpkg -s gnupg >/dev/null 2>&1 || pkgs+=(gnupg)
    dpkg -s ca-certificates >/dev/null 2>&1 || pkgs+=(ca-certificates)
    dpkg -s lsb-release >/dev/null 2>&1 || pkgs+=(lsb-release)
    dpkg -s openssl >/dev/null 2>&1 || pkgs+=(openssl)
    dpkg -s ripgrep >/dev/null 2>&1 || pkgs+=(ripgrep)
    # lua-resty-maxminddb uses ffi.load('libmaxminddb') which needs the
    # unversioned .so symlink provided by the -dev package, not the runtime lib
    dpkg -s libmaxminddb-dev >/dev/null 2>&1 || pkgs+=(libmaxminddb-dev)

    if [ "${#pkgs[@]}" -gt 0 ]; then
        log "Installing Debian prerequisites: ${pkgs[*]}"
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
    fi
}

install_prereqs_el() {
    local pkgs=()

    rpm -q wget >/dev/null 2>&1 || pkgs+=(wget)
    rpm -q ca-certificates >/dev/null 2>&1 || pkgs+=(ca-certificates)
    rpm -q openssl >/dev/null 2>&1 || pkgs+=(openssl)
    rpm -q ripgrep >/dev/null 2>&1 || pkgs+=(ripgrep)
    # lua-resty-maxminddb uses ffi.load('libmaxminddb') which needs the
    # unversioned .so symlink provided by the -devel package, not the runtime lib
    rpm -q libmaxminddb-devel >/dev/null 2>&1 || pkgs+=(libmaxminddb-devel)

    if [ "${#pkgs[@]}" -gt 0 ]; then
        log "Installing EL prerequisites: ${pkgs[*]}"
        if command_exists dnf; then
            dnf install -y "${pkgs[@]}"
        else
            yum install -y "${pkgs[@]}"
        fi
    fi
}

get_debian_codename() {
    local codename=""

    if command_exists lsb_release; then
        codename="$(lsb_release -sc 2>/dev/null || true)"
    fi

    if [ -z "$codename" ] && [ -n "${VERSION_CODENAME:-}" ]; then
        codename="$VERSION_CODENAME"
    fi

    if [ -z "$codename" ]; then
        codename="$(grep -Po '^VERSION="?[0-9]+ \(\K[^)]+' /etc/os-release 2>/dev/null || true)"
    fi

    [ -n "$codename" ] || die "Could not determine Debian/Ubuntu codename"
    printf '%s\n' "$codename"
}

setup_openresty_repo_debian() {
    local key_file="/etc/apt/trusted.gpg.d/openresty.gpg"
    local repo_file="/etc/apt/sources.list.d/openresty.list"
    local codename

    codename="$(get_debian_codename)"

    if [ ! -f "$key_file" ]; then
        log "Adding OpenResty GPG key"
        wget -qO - https://openresty.org/package/pubkey.gpg | gpg --dearmor -o "$key_file"
    fi

    if [ ! -f "$repo_file" ] || ! grep -q "openresty.org/package/debian" "$repo_file"; then
        log "Adding OpenResty APT repository for codename: $codename"
        echo "deb http://openresty.org/package/debian $codename openresty" > "$repo_file"
        apt-get update
    fi
}

setup_openresty_repo_el() {
    local major
    local repo_url
    local repo_file="/etc/yum.repos.d/openresty.repo"

    major="$(printf '%s' "$OS_VERSION_ID" | cut -d. -f1)"
    [ -n "$major" ] || die "Could not determine EL major version"

    case "$major" in
        8)
            repo_url="https://openresty.org/package/centos/openresty.repo"
            ;;
        9|10)
            repo_url="https://openresty.org/package/centos/openresty2.repo"
            ;;
        *)
            die "Unsupported EL major version: $major"
            ;;
    esac

    if [ ! -f "$repo_file" ] || ! grep -q "openresty.org/package/centos" "$repo_file"; then
        log "Adding OpenResty YUM/DNF repository for EL$major"
        wget -qO "$repo_file" "$repo_url"
    fi
}

is_pkg_installed_debian() {
    dpkg -s "$1" >/dev/null 2>&1
}

is_pkg_installed_el() {
    rpm -q "$1" >/dev/null 2>&1
}

install_openresty_packages() {
    local pkgs=(
        openresty-openssl3
        openresty-opm
        openresty
    )
    local to_install=()
    local pkg

    if [ "$OS_FAMILY" = "debian" ]; then
        for pkg in "${pkgs[@]}"; do
            if ! is_pkg_installed_debian "$pkg"; then
                to_install+=("$pkg")
            fi
        done

        if [ "${#to_install[@]}" -gt 0 ]; then
            log "Installing OpenResty packages: ${to_install[*]}"
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${to_install[@]}"
        else
            log "All OpenResty packages already installed"
        fi
    else
        for pkg in "${pkgs[@]}"; do
            if ! is_pkg_installed_el "$pkg"; then
                to_install+=("$pkg")
            fi
        done

        if [ "${#to_install[@]}" -gt 0 ]; then
            log "Installing OpenResty packages: ${to_install[*]}"
            if command_exists dnf; then
                dnf install -y "${to_install[@]}"
            else
                yum install -y "${to_install[@]}"
            fi
        else
            log "All OpenResty packages already installed"
        fi
    fi
}

find_opm_bin() {
    local candidates=(
        /usr/bin/opm
        /usr/local/openresty/bin/opm
        /opt/openresty/bin/opm
        "$(command -v opm 2>/dev/null || true)"
    )
    local c

    for c in "${candidates[@]}"; do
        if [ -n "$c" ] && [ -x "$c" ]; then
            printf '%s\n' "$c"
            return 0
        fi
    done

    return 1
}

opm_package_installed() {
    local opm_bin="$1"
    local pkg="$2"

    "$opm_bin" list 2>/dev/null | awk '{print $1}' | grep -Fxq "$pkg"
}

install_opm_packages() {
    local opm_bin
    local pkgs=(
        ledgetech/lua-resty-http
        openresty/lua-resty-string
	anjia0532/lua-resty-maxminddb
    )
    local pkg

    opm_bin="$(find_opm_bin)" || die "Could not find opm binary after installation"

    for pkg in "${pkgs[@]}"; do
        if opm_package_installed "$opm_bin" "$pkg"; then
            log "OPM package already installed: $pkg"
        else
            log "Installing OPM package: $pkg"
            "$opm_bin" get "$pkg"
        fi
    done
}

detect_cert_dir() {
    printf '%s\n' "/var/lib/cfm/certs/selfsigned"
}

create_default_certs_if_missing() {
    local cert_dir
    local cert_file
    local key_file

    cert_dir="$(detect_cert_dir)"

    cert_file="$cert_dir/fullchain.pem"
    key_file="$cert_dir/privkey.pem"

    if [ -s "$cert_file" ] && [ -s "$key_file" ]; then
        log "Default certs already present: $cert_file and $key_file"
        chown root:cfm "$cert_file" "$key_file"
        chmod 0640 "$cert_file" "$key_file"
        return 0
    fi

    log "Creating self-signed cert in: $cert_dir"
    mkdir -p "$cert_dir"

    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$key_file" \
        -out "$cert_file" \
        -subj "/C=GR/ST=State/L=City/O=OpenResty/CN=localhost"

    log "Created: $cert_file and $key_file"
    chown root:cfm "$cert_file" "$key_file"
    chmod 0640 "$cert_file"
    chmod 0640 "$key_file"
}

validate_fallback_cert_preflight() {
    local cert_dir cert_file key_file
    cert_dir="$(detect_cert_dir)"
    cert_file="$cert_dir/fullchain.pem"
    key_file="$cert_dir/privkey.pem"

    [ -r "$cert_file" ] || die "Fallback cert missing/unreadable: $cert_file"
    [ -r "$key_file" ] || die "Fallback key missing/unreadable: $key_file"
    su -s /bin/sh -c "test -r '$cert_file' && test -r '$key_file'" cfm >/dev/null 2>&1 || \
        die "Fallback cert/key are not readable by cfm group: $cert_dir"

    local key_mode
    key_mode="$(stat -c '%a' "$key_file")"
    if [ $(( key_mode % 10 )) -ne 0 ]; then
        die "Fallback key is world-readable; expected mode 0640/0600: $key_file ($key_mode)"
    fi
    log "Fallback cert preflight passed: $cert_file / $key_file"
}

ensure_cfm_account() {
    # Create the cfm group and system user if they do not already exist.
    #
    # The cfm group is used to grant OpenResty read access to the SSLCollector
    # unix socket (root:cfm 0660) and cfm_token.lua (root:cfm 0640) without
    # giving it broader privileges.  The cfm system user owns the OpenResty
    # worker processes; it has no home directory and no login shell.

    if ! getent group cfm >/dev/null 2>&1; then
        log "Creating group: cfm"
        groupadd --system cfm
    else
        log "Group already present: cfm"
    fi

    if ! getent passwd cfm >/dev/null 2>&1; then
        log "Creating system user: cfm"
        useradd \
            --system \
            --gid cfm \
            --no-create-home \
            --home-dir /var/lib/cfm \
            --shell /sbin/nologin \
            --comment "CFM service account" \
            cfm
    else
        log "User already present: cfm"
    fi
}

ensure_lua_dir() {
    local lua_dir="$CFM_SHARED_LUA_DIR"

    if [ -d "$lua_dir" ]; then
        log "Lua directory already present: $lua_dir"
        return 0
    fi

    mkdir -p "$lua_dir"
    log "Created Lua directory: $lua_dir"
}

ensure_nginx_temp_dirs() {
    # nginx worker processes (running as cfm) write temp files for buffered
    # request bodies and proxy responses.  openresty.conf points these to
    # /var/lib/cfm/nginx/ so the cfm user owns them outright.
    #
    # Dirs covered:
    #   client_body_temp  — proxy_request_buffering on  (request body spill)
    #   proxy_temp        — proxy_buffering on           (response body spill)
    local dirs=(
        /var/lib/cfm/nginx/client_body_temp
        /var/lib/cfm/nginx/proxy_temp
    )
    local d

    for d in "${dirs[@]}"; do
        mkdir -p "$d"
        chown cfm:cfm "$d"
        chmod 0700 "$d"
        log "nginx temp dir ready (cfm:cfm 0700): $d"
    done
}

ensure_cache_dirs() {
    local dirs=(
        /var/cache/nginx/cfm_static
        /var/cache/nginx/cfm_micro
    )
    local d

    for d in "${dirs[@]}"; do
        if [ ! -d "$d" ]; then
            mkdir -p "$d"
            log "Created cache directory: $d"
        else
            log "Cache directory already present: $d"
        fi
        # root:cfm 0770 — OpenResty workers (cfm group) can write cache files.
        chown root:cfm "$d"
        chmod 0770 "$d"
    done
}

backup_and_copy_file() {
    local src="$1"
    local dst="$2"

    if [ ! -f "$src" ]; then
        warn "Source file not found, skipping: $src"
        return 0
    fi

    local dst_dir
    dst_dir="$(dirname "$dst")"
    mkdir -p "$dst_dir"

    if [ -e "$dst" ]; then
        mv -f "$dst" "${dst}.bak"
        log "Backed up existing file: $dst -> ${dst}.bak"
    fi

    cp -f "$src" "$dst"
    log "Copied: $src -> $dst"
}

# Install the CFM logrotate config plus the hourly runner that gives its
# `maxsize` caps a chance to fire (configs/logrotate-cfm explains why a
# once-a-day pass is not enough on a busy edge).
#
# Deliberately NOT backup_and_copy_file: that helper leaves the old copy next
# to the original, and /etc/logrotate.d/logrotate-cfm.bak is read as a second
# config by any logrotate old enough to lack ".bak" in its taboo extension
# list. Every path would then be declared twice -> "duplicate log entry" ->
# the run aborts and nothing rotates. So back up outside the directory, and
# clear any .bak an earlier version of this installer left behind.
install_logrotate_config() {
    local src="/usr/share/cfm/configs/logrotate-cfm"
    local dst="/etc/logrotate.d/logrotate-cfm"
    local backup_dir="/var/lib/cfm/backups"

    if [ ! -f "$src" ]; then
        warn "Source file not found, skipping: $src"
        return 0
    fi

    mkdir -p /etc/logrotate.d

    if [ -e "${dst}.bak" ]; then
        rm -f "${dst}.bak"
        log "Removed stale ${dst}.bak (logrotate can read it as a duplicate config)"
    fi

    if [ -e "$dst" ]; then
        mkdir -p "$backup_dir"
        mv -f "$dst" "$backup_dir/logrotate-cfm.bak"
        log "Backed up existing file: $dst -> $backup_dir/logrotate-cfm.bak"
    fi

    cp -f "$src" "$dst"
    chmod 0644 "$dst"
    log "Copied: $src -> $dst"

    # No dot in the basename: run-parts skips /etc/cron.hourly entries whose
    # name contains one.
    local cron_src="/usr/share/cfm/configs/cfm-logrotate.cron"
    local cron_dst="/etc/cron.hourly/cfm-logrotate"
    if [ -f "$cron_src" ]; then
        mkdir -p /etc/cron.hourly
        cp -f "$cron_src" "$cron_dst"
        chmod 0755 "$cron_dst"
        log "Installed hourly logrotate pass: $cron_dst"
    else
        warn "Hourly logrotate runner not found, skipping: $cron_src"
    fi

    if command -v logrotate >/dev/null 2>&1; then
        if logrotate -d "$dst" >/dev/null 2>&1; then
            log "logrotate config validates: $dst"
        else
            warn "logrotate rejected $dst — rotation may not run:"
            logrotate -d "$dst" >&2 || true
        fi
    fi
}

render_panel_listener_template() {
    local engine_name="$1"
    local listener_dest="$2"
    local src="/usr/share/cfm/configs/cfm-panel-listeners.conf.in"
    local tmp
    [ -f "$src" ] || die "panel listener template not found: $src"
    tmp="$(mktemp)"
    sed -e "s|@ENGINE@|${engine_name}|g" -e "s|@LISTENER_DEST@|${listener_dest}|g" "$src" > "$tmp"
    printf '%s\n' "$tmp"
}

deploy_cfm_files() {
    local conf_dir

    conf_dir="/usr/local/openresty/nginx/conf"

    mkdir -p "$conf_dir"
    mkdir -p /etc/logrotate.d

    backup_and_copy_file "/usr/share/cfm/configs/trusted_proxies.conf" \
        "$conf_dir/trusted_proxies.conf"
    local listener_tpl
    listener_tpl="$(render_panel_listener_template "OpenResty" "$conf_dir/cfm-panel-listeners.conf")"
    backup_and_copy_file "$listener_tpl" "$conf_dir/cfm-panel-listeners.conf"
    rm -f "$listener_tpl"

    backup_and_copy_file "/usr/share/cfm/configs/challenge_waf_bypass.conf" \
                         "$conf_dir/challenge_waf_bypass.conf"


    install_logrotate_config
}

deploy_nginx_conf() {
    local src="/usr/share/cfm/configs/openresty.conf"
    local dst="/usr/local/openresty/nginx/conf/nginx.conf"
    local prefix="/usr/local/openresty/nginx"

    if [ ! -f "$src" ]; then
        warn "nginx conf source not found, skipping: $src"
        return 0
    fi

    validate_panel_lua_guard_preflight "$src" "$prefix" || return 1
    if ! check_legacy_lua_paths_in_runtime_configs "$prefix" "$src"; then
        die "Detected legacy OpenResty Lua path references in candidate config bundle"
    fi
    log "Testing nginx config: $src"
    if openresty -t -p "$prefix" -c "$src" >/dev/null 2>&1; then
        log "Config test passed"
        backup_and_copy_file "$src" "$dst"
        log "nginx.conf deployed successfully"
    else
        warn "Config test FAILED — nginx.conf NOT deployed. Output:"
        openresty -t -p "$prefix" -c "$src" >&2 || true
    fi
}

validate_panel_lua_guard_preflight() {
    local nginx_src="$1"
    local prefix="$2"
    local listener_conf="$prefix/conf/cfm-panel-listeners.conf"

    if ! grep -Eq '^[[:space:]]*include[[:space:]]+cfm-panel-listeners\.conf;' "$nginx_src"; then
        return 0
    fi
    if [ ! -f "$listener_conf" ]; then
        warn "Panel listener include enabled but listener file missing: $listener_conf"
        return 1
    fi
    local lua_path
    lua_path="$(awk '/access_by_lua_file/ && /cfm_panel\.lua/ {gsub(/;/,"",$2); print $2; exit}' "$listener_conf")"
    if [ -z "$lua_path" ]; then
        warn "Panel listener include enabled but cfm_panel.lua path is not configured in $listener_conf"
        return 1
    fi
    if [ ! -r "$lua_path" ]; then
        warn "Panel listener include enabled but Lua guard file missing/unreadable: $lua_path"
        return 1
    fi
    if ! su -s /bin/sh -c "test -r '$lua_path'" cfm >/dev/null 2>&1; then
        warn "Panel Lua guard file is not readable by worker user cfm: $lua_path"
        return 1
    fi
    local selftest="package.path='/var/lib/cfm/lua/?.lua;'..package.path; ngx={log=function() end,ERR=3,WARN=4,NOTICE=5,INFO=6,HTTP_FORBIDDEN=403,HTTP_INTERNAL_SERVER_ERROR=500,HTTP_NOT_FOUND=404,time=os.time,now=os.time,escape_uri=function(s) return tostring(s or '') end,unescape_uri=function(s) return tostring(s or '') end,var={},header={},ctx={},req={get_method=function() return 'GET' end,is_internal=function() return true end},exit=function(code) return code end}; local ok,a,b=pcall(dofile,arg[1]); if not ok then error(a) end; if a==false then error(b or 'selftest failed') end; if a==true then return end; if type(cfm_panel_selftest)=='function' then local ok2,err=cfm_panel_selftest(); assert(ok2, err or 'selftest failed'); return end; error('missing cfm_panel_selftest')"
    local interp=""
    for cand in resty luajit lua lua5.1 lua5.4 lua5.3 lua5.2; do
        if command -v "$cand" >/dev/null 2>&1; then
            interp="$cand"
            break
        fi
    done
    if [ -n "$interp" ]; then
        if ! CFM_PANEL_SELFTEST_ONLY=1 "$interp" -e "$selftest" "$lua_path" >/dev/null 2>&1; then
            warn "Panel Lua guard syntax/module selftest failed with $interp: $lua_path"
            CFM_PANEL_SELFTEST_ONLY=1 "$interp" -e "$selftest" "$lua_path" >&2 || true
            return 1
        fi
        log "Panel Lua guard preflight passed with $interp: $lua_path"
        return 0
    fi
    for cand in luac luac5.1 luac5.4 luac5.3 luac5.2; do
        if command -v "$cand" >/dev/null 2>&1; then
            if "$cand" -p "$lua_path" >/dev/null 2>&1; then
                warn "Panel Lua guard selftest interpreter unavailable; $cand syntax check passed only: $lua_path"
                return 0
            fi
            warn "Panel Lua guard syntax check failed with $cand: $lua_path"
            "$cand" -p "$lua_path" >&2 || true
            return 1
        fi
    done
    warn "Panel Lua guard selftest skipped: no resty/lua/luajit/luac interpreter found"
    return 0
}

check_lua_token_files() {
    local token_files=(
        "$CFM_SHARED_LUA_DIR/cfm_token.lua"
        "$CFM_SHARED_LUA_DIR/cfm_bridge_token.lua"
    )
    local token_file
    local ready_count=0
    local missing_count=0

    for token_file in "${token_files[@]}"; do
        if [ -f "$token_file" ]; then
            chown root:cfm "$token_file"
            chmod 0640 "$token_file"
            ready_count=$((ready_count + 1))
            log "Token file permissions ready (root:cfm 0640): $token_file"
        else
            missing_count=$((missing_count + 1))
            warn "Token file missing: $token_file (run cfm daemon first to generate it)"
        fi
    done

    log "Token file readiness: ready=$ready_count missing=$missing_count expected=2"
}

validate_shared_lua_runtime() {
    local missing=()
    local name
    for name in "${CFM_LUA_MANIFEST[@]}"; do
        [ -r "$CFM_SHARED_LUA_DIR/$name" ] || missing+=("$CFM_SHARED_LUA_DIR/$name")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        die "Missing required CFM Lua files in shared runtime: ${missing[*]}"
    fi
}

check_legacy_lua_paths_in_runtime_configs() {
    local conf_root="$1"
    local entrypoint="$2"
    local pattern='^[[:space:]]*(access_by_lua_file|content_by_lua_file|rewrite_by_lua_file|log_by_lua_file|init_by_lua_file|init_worker_by_lua_file|lua_package_path)([[:space:]]|;|$)'
    local legacy='/(etc/angie|usr/local/openresty/nginx)/lua/(cfm(_panel)?|cfm_rules|cfm_stats|cfm_waf|cfm_clamav|cfm_cache_log|log-cfm|sslcollector)\.lua'
    local -a queue=()
    local -a files=()
    local -A seen=()
    local current
    local include_path
    local f
    local hit=0

    [ -f "$entrypoint" ] || return 0
    queue+=("$entrypoint")

    while [ "${#queue[@]}" -gt 0 ]; do
        current="${queue[0]}"
        queue=("${queue[@]:1}")

        if [ -n "${seen["$current"]+x}" ]; then
            continue
        fi
        seen["$current"]=1

        [ -f "$current" ] || continue
        files+=("$current")

        while IFS= read -r include_path; do
            include_path="${include_path%;}"
            include_path="${include_path#\"}"
            include_path="${include_path%\"}"
            case "$include_path" in
                /*) ;;
                *) include_path="$conf_root/conf/$include_path" ;;
            esac
            while IFS= read -r f; do
                [ -f "$f" ] || continue
                if [ -z "${seen["$f"]+x}" ]; then
                    queue+=("$f")
                fi
            done < <(compgen -G "$include_path" || true)
        done < <(awk '($0 !~ /^[[:space:]]*#/) {if (match($0, /^[[:space:]]*include[[:space:]]+[^;]+;/)) {line=substr($0, RSTART, RLENGTH); sub(/^[[:space:]]*include[[:space:]]+/, "", line); print line}}' "$current")
    done

    for f in "${files[@]}"; do
        while IFS= read -r match; do
            warn "legacy Lua path in active directive: $match"
            hit=1
        done < <(awk -v p="$pattern" '($0 !~ /^[[:space:]]*#/ && $0 ~ p) {print FILENAME ":" FNR ":" $0}' "$f" | rg -n "$legacy")
    done

    [ "$hit" -eq 0 ]
}



main() {
    need_root
    detect_os

    log "Detected OS family: $OS_FAMILY (${OS_ID:-unknown} ${OS_VERSION_ID:-unknown})"

    if [ "$OS_FAMILY" = "debian" ]; then
        install_prereqs_debian
        setup_openresty_repo_debian
    else
        install_prereqs_el
        setup_openresty_repo_el
    fi

    install_openresty_packages
    install_opm_packages
    ensure_cfm_account
    create_default_certs_if_missing
    validate_fallback_cert_preflight
    ensure_lua_dir
    ensure_nginx_temp_dirs
    ensure_cache_dirs
    deploy_cfm_files
    validate_shared_lua_runtime
    deploy_nginx_conf
    check_lua_token_files
    log "Shared fallback cert path: /var/lib/cfm/certs/selfsigned/{fullchain,privkey}.pem"
    log "Done"
}

main "$@"
