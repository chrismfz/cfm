#!/usr/bin/env bash
#
# install-angie.sh — TESTBED installer for CFM on Angie (nginx fork)
#
# WARNING: Experimental. Installs Angie + angie-module-lua. Does NOT touch
# an existing OpenResty install, and does NOT auto-deploy nginx.conf — the
# OpenResty config needs manual adaptation for Angie (see print_next_steps).
#
# Layout (differs from OpenResty):
#   Angie configs: /etc/angie/
#   CFM lua:       /etc/angie/lua/
#   Extra resty:   /etc/angie/lualib/         (lua-resty-maxminddb here)
#   Dyn modules:   /usr/lib/angie/modules/
#   Logs:          /var/log/angie/
#   Caches:        /var/cache/angie/
#   Binary:        /usr/sbin/angie
#
# This script mirrors the structure of install-openresty.sh for side-by-side
# comparison.

set -euo pipefail

log()  { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

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
        almalinux|rocky|rhel|centos|cloudlinux|oracle)
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

    dpkg -s curl           >/dev/null 2>&1 || pkgs+=(curl)
    dpkg -s ca-certificates >/dev/null 2>&1 || pkgs+=(ca-certificates)
    dpkg -s lsb-release    >/dev/null 2>&1 || pkgs+=(lsb-release)
    dpkg -s openssl        >/dev/null 2>&1 || pkgs+=(openssl)
    dpkg -s git            >/dev/null 2>&1 || pkgs+=(git)
    dpkg -s libmaxminddb0  >/dev/null 2>&1 || pkgs+=(libmaxminddb0)

    if [ "${#pkgs[@]}" -gt 0 ]; then
        log "Installing Debian prerequisites: ${pkgs[*]}"
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
    fi
}

install_prereqs_el() {
    local pkgs=()

    rpm -q curl            >/dev/null 2>&1 || pkgs+=(curl)
    rpm -q ca-certificates >/dev/null 2>&1 || pkgs+=(ca-certificates)
    rpm -q openssl         >/dev/null 2>&1 || pkgs+=(openssl)
    rpm -q git             >/dev/null 2>&1 || pkgs+=(git)
    rpm -q libmaxminddb    >/dev/null 2>&1 || pkgs+=(libmaxminddb)

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

    [ -n "$codename" ] || die "Could not determine Debian/Ubuntu codename"
    printf '%s\n' "$codename"
}

setup_angie_repo_debian() {
    local key_file="/etc/apt/trusted.gpg.d/angie-signing.gpg"
    local repo_file="/etc/apt/sources.list.d/angie.list"
    local codename
    codename="$(get_debian_codename)"

    if [ ! -f "$key_file" ]; then
        log "Downloading Angie signing key"
        curl -fsSL -o "$key_file" https://angie.software/keys/angie-signing.gpg
    fi

    # Angie repo URL format:
    #   https://download.angie.software/angie/<ID>/<VERSION_ID> <codename> main
    # e.g. debian/13 trixie main, ubuntu/24.04 noble main
    if [ ! -f "$repo_file" ] || ! grep -q "download.angie.software/angie" "$repo_file"; then
        log "Adding Angie APT repo for $OS_ID/$OS_VERSION_ID ($codename)"
        echo "deb https://download.angie.software/angie/$OS_ID/$OS_VERSION_ID $codename main" \
            > "$repo_file"
        apt-get update
    fi
}

setup_angie_repo_el() {
    local repo_file="/etc/yum.repos.d/angie.repo"
    local major
    local distro_path

    major="$(printf '%s' "$OS_VERSION_ID" | cut -d. -f1)"
    [ -n "$major" ] || die "Could not determine EL major version"

    # Angie publishes per-distro repo paths at:
    #   https://download.angie.software/angie/<distro>/<major>/
    # As of this writing, published paths include: almalinux, centos, rocky,
    # oracle, fedora, msvsphere. NOT published: cloudlinux, rhel.
    #
    # CloudLinux is ABI-compatible with AlmaLinux/RHEL (same base packages,
    # same glibc, same OpenSSL). RHEL itself is what Alma rebuilds from.
    # Both safely use the almalinux repo path.
    case "$OS_ID" in
        almalinux)              distro_path="almalinux" ;;
        rocky)                  distro_path="rocky" ;;
        centos)                 distro_path="centos" ;;
        oracle)                 distro_path="oracle" ;;
        cloudlinux|rhel)        distro_path="almalinux" ;;
        *)
            warn "Unknown EL-family distro '$OS_ID' — falling back to almalinux repo"
            distro_path="almalinux"
            ;;
    esac

    if [ ! -f "$repo_file" ] || ! grep -q "download.angie.software" "$repo_file"; then
        log "Adding Angie DNF/YUM repo for $distro_path $major"
        cat > "$repo_file" <<EOF
[angie]
name=Angie repo
baseurl=https://download.angie.software/angie/$distro_path/\$releasever/
gpgcheck=1
enabled=1
gpgkey=https://angie.software/keys/angie-signing.gpg.asc
EOF
    fi
}

is_pkg_installed_debian() {
    dpkg -s "$1" >/dev/null 2>&1
}

is_pkg_installed_el() {
    rpm -q "$1" >/dev/null 2>&1
}

install_angie_packages() {
    # angie-module-lua ships: luajit2, lua_cjson, lua-resty-core,
    # lua-resty-http, lua-resty-string, lua-resty-lrucache, lua-resty-hmac,
    # lua-resty-jwt, lua-resty-openssl, lua-resty-session, and more.
    #
    # The only OPM lib from install-openresty.sh that is NOT bundled is
    # anjia0532/lua-resty-maxminddb — handled by install_extra_resty().
    local pkgs=(
        angie
        angie-module-lua
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
            log "Installing Angie packages: ${to_install[*]}"
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${to_install[@]}"
        else
            log "All Angie packages already installed"
        fi
    else
        for pkg in "${pkgs[@]}"; do
            if ! is_pkg_installed_el "$pkg"; then
                to_install+=("$pkg")
            fi
        done

        if [ "${#to_install[@]}" -gt 0 ]; then
            log "Installing Angie packages: ${to_install[*]}"
            if command_exists dnf; then
                dnf install -y "${to_install[@]}"
            else
                yum install -y "${to_install[@]}"
            fi
        else
            log "All Angie packages already installed"
        fi
    fi
}

install_extra_resty() {
    # lua-resty-maxminddb is NOT in angie-module-lua — install via git clone
    # since it's pure Lua (just needs libmaxminddb at runtime, handled by
    # prereqs). This avoids pulling luarocks + build toolchain.
    local dest="/etc/angie/lualib/resty"
    local repo="https://github.com/anjia0532/lua-resty-maxminddb.git"
    local tmp

    if [ -f "$dest/maxminddb.lua" ]; then
        log "lua-resty-maxminddb already present in $dest"
        return 0
    fi

    mkdir -p "$dest"
    tmp="$(mktemp -d)"

    log "Cloning lua-resty-maxminddb into $tmp"
    if git clone --depth 1 "$repo" "$tmp/lua-resty-maxminddb" >/dev/null 2>&1; then
        if [ -f "$tmp/lua-resty-maxminddb/lib/resty/maxminddb.lua" ]; then
            cp -f "$tmp/lua-resty-maxminddb/lib/resty/maxminddb.lua" "$dest/maxminddb.lua"
            log "Installed: $dest/maxminddb.lua"
        else
            warn "maxminddb.lua not found in cloned repo — upstream layout changed?"
        fi
    else
        warn "Failed to clone lua-resty-maxminddb from $repo — install manually"
    fi

    rm -rf "$tmp"
}

detect_cert_dir() {
    if [ -d "/etc/angie" ]; then
        printf '%s\n' "/etc/angie/selfsigned"
    else
        return 1
    fi
}

create_default_certs_if_missing() {
    local cert_dir
    cert_dir="$(detect_cert_dir)" || die "Angie conf directory not found"

    local cert_file="$cert_dir/fullchain.pem"
    local key_file="$cert_dir/privkey.pem"

    if [ -s "$cert_file" ] && [ -s "$key_file" ]; then
        log "Default certs already present: $cert_file and $key_file"
        return 0
    fi

    log "Creating self-signed cert in: $cert_dir"
    mkdir -p "$cert_dir"

    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$key_file" \
        -out "$cert_file" \
        -subj "/C=GR/ST=State/L=City/O=Angie/CN=localhost"

    log "Created: $cert_file and $key_file"
}

ensure_lua_dir() {
    local lua_dir="/etc/angie/lua"

    if [ -d "$lua_dir" ]; then
        log "Lua directory already present: $lua_dir"
        return 0
    fi

    mkdir -p "$lua_dir"
    log "Created Lua directory: $lua_dir"
}

ensure_cache_dirs() {
    local dirs=(
        /var/cache/angie/cfm_static
        /var/cache/angie/cfm_micro
    )
    local d

    for d in "${dirs[@]}"; do
        if [ -d "$d" ]; then
            log "Cache directory already present: $d"
        else
            mkdir -p "$d"
            # angie user is created by the package; fail-soft if not yet present
            chown -R angie:angie "$d" 2>/dev/null || true
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
    local lua_dir="/etc/angie/lua"
    local conf_dir="/etc/angie"

    mkdir -p "$lua_dir"
    mkdir -p "$conf_dir"
    mkdir -p /etc/logrotate.d

    backup_and_copy_file "/usr/share/cfm/configs/cfm.lua"            "$lua_dir/cfm.lua"
    backup_and_copy_file "/usr/share/cfm/configs/cfm_rules.lua"      "$lua_dir/cfm_rules.lua"
    backup_and_copy_file "/usr/share/cfm/configs/cfm_stats.lua"      "$lua_dir/cfm_stats.lua"
    backup_and_copy_file "/usr/share/cfm/configs/cfm_waf.lua"        "$lua_dir/cfm_waf.lua"
    backup_and_copy_file "/usr/share/cfm/configs/cfm_clamav.lua"     "$lua_dir/cfm_clamav.lua"
    backup_and_copy_file "/usr/share/cfm/configs/cfm_cache_log.lua"  "$lua_dir/cfm_cache_log.lua"
    backup_and_copy_file "/usr/share/cfm/configs/sslcollector.lua"   "$lua_dir/sslcollector.lua"

    backup_and_copy_file "/usr/share/cfm/configs/trusted_proxies.conf" \
                         "$conf_dir/trusted_proxies.conf"

    backup_and_copy_file "/usr/share/cfm/configs/challenge_waf_bypass.conf" \
                         "$conf_dir/challenge_waf_bypass.conf"

    backup_and_copy_file "/usr/share/cfm/configs/logrotate-cfm" \
                         "/etc/logrotate.d/logrotate-cfm"
}

print_next_steps() {
    cat <<'EOF'

===========================================================================
  TESTBED INSTALL COMPLETE — Angie is installed but NOT YET SERVING CFM
===========================================================================

This script intentionally did NOT overwrite /etc/angie/angie.conf, because
configs/openresty.conf needs manual adaptation for Angie. Key items:

  1. load_module directives (top-level, before the `events` block):
       load_module modules/ndk_http_module.so;
       load_module modules/ngx_http_lua_module.so;

     NOTE: Angie's angie-module-lua package may auto-load these via a
     drop-in under /etc/angie/module.d/ (or similar). Check before adding
     manually — double-loading is an error.

  2. Path substitutions in your adapted config:
       /usr/local/openresty/nginx/conf  ->  /etc/angie
       /usr/local/openresty/nginx/lua   ->  /etc/angie/lua
       /usr/local/openresty/nginx/logs  ->  /var/log/angie
       /var/cache/nginx                 ->  /var/cache/angie

  3. lua_package_path (in the http {} block) must cover both dirs:
       lua_package_path '/etc/angie/lua/?.lua;/etc/angie/lualib/?.lua;;';

  4. ssl_certificate paths for the fallback self-signed:
       /etc/angie/selfsigned/fullchain.pem
       /etc/angie/selfsigned/privkey.pem

  5. nftables DNAT targets stay :9080 / :9043 (unchanged).

SUGGESTED FLOW:
    cp /usr/share/cfm/configs/openresty.conf /etc/angie/angie.conf.cfm
    # edit /etc/angie/angie.conf.cfm per notes above
    angie -t -c /etc/angie/angie.conf.cfm
    # once clean:
    mv /etc/angie/angie.conf     /etc/angie/angie.conf.dist
    mv /etc/angie/angie.conf.cfm /etc/angie/angie.conf
    systemctl restart angie

WHILE TESTING: OpenResty is untouched. If this box currently has OpenResty
listening on :9080 / :9043 you MUST stop it before starting Angie, or they
will fight over the port:
    systemctl stop openresty
    systemctl start angie

EOF
}

main() {
    need_root
    detect_os

    log "Detected OS family: $OS_FAMILY (${OS_ID:-unknown} ${OS_VERSION_ID:-unknown})"
    log "*** TESTBED INSTALLER — experimental. Does not touch OpenResty. ***"

    if [ "$OS_FAMILY" = "debian" ]; then
        install_prereqs_debian
        setup_angie_repo_debian
    else
        install_prereqs_el
        setup_angie_repo_el
    fi

    install_angie_packages
    install_extra_resty
    create_default_certs_if_missing
    ensure_lua_dir
    ensure_cache_dirs
    deploy_cfm_files
    print_next_steps
    log "Done"
}

main "$@"
