#!/usr/bin/env bash
set -euo pipefail

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
    if [ -d "/opt/openresty/nginx/conf" ]; then
        printf '%s\n' "/opt/openresty/nginx/conf/selfsigned"
    elif [ -d "/usr/local/openresty/nginx/conf" ]; then
        printf '%s\n' "/usr/local/openresty/nginx/conf/selfsigned"
    else
        return 1
    fi
}

create_default_certs_if_missing() {
    local cert_dir
    local cert_file
    local key_file

    cert_dir="$(detect_cert_dir)" || die "Could not find OpenResty conf directory"

    cert_file="$cert_dir/fullchain.pem"
    key_file="$cert_dir/privkey.pem"

    if [ -s "$cert_file" ] && [ -s "$key_file" ]; then
        log "Default certs already present: $cert_file and $key_file"
        return 0
    fi

    log "Creating self-signed cert in: $cert_dir"
    mkdir -p "$cert_dir"

    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$key_file" \
        -out "$cert_file" \
        -subj "/C=GR/ST=State/L=City/O=OpenResty/CN=localhost"

    log "Created: $cert_file and $key_file"
}

ensure_lua_dir() {
    local lua_dir="/usr/local/openresty/nginx/lua"

    if [ -d "$lua_dir" ]; then
        log "Lua directory already present: $lua_dir"
        return 0
    fi

    mkdir -p "$lua_dir"
    log "Created Lua directory: $lua_dir"
}

ensure_cache_dirs() {
    local dirs=(
        /var/cache/nginx/cfm_static
        /var/cache/nginx/cfm_micro
    )
    local d

    for d in "${dirs[@]}"; do
        if [ -d "$d" ]; then
            log "Cache directory already present: $d"
        else
            mkdir -p "$d"
            log "Created cache directory: $d"
        fi
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

deploy_cfm_files() {
    local lua_dir
    local conf_dir

    lua_dir="/usr/local/openresty/nginx/lua"
    conf_dir="/usr/local/openresty/nginx/conf"

    mkdir -p "$lua_dir"
    mkdir -p "$conf_dir"
    mkdir -p /etc/logrotate.d

    backup_and_copy_file "/usr/share/cfm/configs/cfm.lua"            "$lua_dir/cfm.lua"
    backup_and_copy_file "/usr/share/cfm/configs/cfm_rules.lua"      "$lua_dir/cfm_rules.lua"
    backup_and_copy_file "/usr/share/cfm/configs/cfm_stats.lua"      "$lua_dir/cfm_stats.lua"
    backup_and_copy_file "/usr/share/cfm/configs/cfm_waf.lua"        "$lua_dir/cfm_waf.lua"
    backup_and_copy_file "/usr/share/cfm/configs/cfm_clamav.lua"        "$lua_dir/cfm_clamav.lua"
    backup_and_copy_file "/usr/share/cfm/configs/cfm_cache_log.lua"        "$lua_dir/cfm_cache_log.lua"

    backup_and_copy_file "/usr/share/cfm/configs/sslcollector.lua"   "$lua_dir/sslcollector.lua"

    backup_and_copy_file "/usr/share/cfm/configs/trusted_proxies.conf" \
                         "$conf_dir/trusted_proxies.conf"

    backup_and_copy_file "/usr/share/cfm/configs/challenge_waf_bypass.conf" \
                         "$conf_dir/challenge_waf_bypass.conf"


    backup_and_copy_file "/usr/share/cfm/configs/logrotate-cfm" \
                         "/etc/logrotate.d/logrotate-cfm"
}

deploy_nginx_conf() {
    local src="/usr/share/cfm/configs/openresty.conf"
    local dst="/usr/local/openresty/nginx/conf/nginx.conf"
    local prefix="/usr/local/openresty/nginx"

    if [ ! -f "$src" ]; then
        warn "nginx conf source not found, skipping: $src"
        return 0
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
    create_default_certs_if_missing
    ensure_lua_dir
    ensure_cache_dirs
    deploy_cfm_files
    deploy_nginx_conf
    log "Done"
}

main "$@"
