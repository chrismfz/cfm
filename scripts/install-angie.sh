#!/usr/bin/env bash
#
# install-angie.sh — TESTBED installer for CFM on Angie (nginx fork)
#
# Installs Angie + angie-module-lua, runs CFM-specific pre-flight checks,
# and (if configs/angie.conf is shipped in /usr/share/cfm/configs/) auto-
# deploys it with `angie -t` validation.
#
# DOES NOT touch an existing OpenResty install. Both can be present side by
# side; only one may be running at a time (they fight for :9080 / :9043).
#
# Layout (differs from OpenResty):
#   Angie configs: /etc/angie/
#   CFM lua:       /var/lib/cfm/lua/ (provided by package)
#   Extra resty:   /etc/angie/lualib/         (lua-resty-maxminddb here)
#   Dyn modules:   /usr/lib/angie/modules/
#   Logs:          /var/log/angie/            (chowned to cfm:cfm)
#   Caches:        /var/cache/angie/          (chowned to cfm:cfm)
#   Temp dirs:     /var/lib/cfm/nginx/*       (created & owned by cfm:cfm)
#   Binary:        /usr/sbin/angie
#
# This script mirrors the structure of install-openresty.sh for side-by-side
# comparison.

set -euo pipefail

readonly CFM_SHARED_LUA_DIR="/var/lib/cfm/lua"
readonly CFM_LUA_MANIFEST=(
    cfm.lua cfm_panel.lua cfm_panel_tunnel.lua cfm_rules.lua cfm_stats.lua
    cfm_waf.lua cfm_waf_util.lua cfm_waf_detectors.lua cfm_waf_excl.lua
    cfm_clamav.lua cfm_cache_log.lua cfm_clearance.lua cfm_geo.lua cfm_purge.lua
    cfm_filecache.lua cfm_origin_ka.lua cfm_bridge_cfg.lua cfm_tlsfp.lua
    cfm_decision.lua
    log-cfm.lua sslcollector.lua
)

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
    dpkg -s ripgrep        >/dev/null 2>&1 || pkgs+=(ripgrep)
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
    rpm -q ripgrep         >/dev/null 2>&1 || pkgs+=(ripgrep)
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

# ─────────────────────────────────────────────────────────────────────────────
# CFM pre-flight checks (angie.conf uses "user cfm;")
# ─────────────────────────────────────────────────────────────────────────────

ensure_cfm_user_exists() {
    if id -u cfm >/dev/null 2>&1; then
        log "cfm user exists"
        return 0
    fi
    warn "cfm user does NOT exist — angie.conf uses 'user cfm;' and will fail."
    warn "The cfm user is normally created by the CFM RPM/DEB postinst."
    warn "If CFM is installed, check: getent passwd cfm"
    warn "If not, install CFM first, OR edit angie.conf to use a different user."
}

ensure_cfm_temp_dirs() {
    # angie.conf sets:
    #   client_body_temp_path /var/lib/cfm/nginx/client_body_temp;
    #   proxy_temp_path       /var/lib/cfm/nginx/proxy_temp;
    # Workers run as cfm — these must exist and be cfm:cfm-owned.
    local dirs=(
        /var/lib/cfm/nginx/client_body_temp
        /var/lib/cfm/nginx/proxy_temp
    )
    local d

    for d in "${dirs[@]}"; do
        if [ -d "$d" ]; then
            log "CFM temp dir already present: $d"
        else
            mkdir -p "$d"
            log "Created CFM temp dir: $d"
        fi
        # Always (re)chown — safe no-op if already cfm:cfm.
        if id -u cfm >/dev/null 2>&1; then
            chown -R cfm:cfm "$d"
        fi
    done
}

ensure_log_dir_ownership() {
    # Angie's package creates /var/log/angie/ as angie:angie. Since workers
    # run as cfm, pre-existing log files owned by angie cannot be appended
    # to. Chown the whole dir recursively.
    local log_dir="/var/log/angie"

    if [ ! -d "$log_dir" ]; then
        log "Creating $log_dir"
        mkdir -p "$log_dir"
    fi

    if id -u cfm >/dev/null 2>&1; then
        chown -R cfm:cfm "$log_dir"
        log "Ensured $log_dir is owned by cfm:cfm"
    else
        warn "cfm user missing — skipping chown of $log_dir"
    fi
}

detect_cert_dir() {
    printf '%s\n' "/var/lib/cfm/certs/selfsigned"
}

create_default_certs_if_missing() {
    local cert_dir
    cert_dir="$(detect_cert_dir)"

    local cert_file="$cert_dir/fullchain.pem"
    local key_file="$cert_dir/privkey.pem"

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
        -subj "/C=GR/ST=State/L=City/O=Angie/CN=localhost"

    log "Created: $cert_file and $key_file"
    chown root:cfm "$cert_file" "$key_file"
    chmod 0640 "$cert_file"
    chmod 0640 "$key_file"
}

validate_fallback_cert_preflight() {
    local cert_dir cert_file key_file key_mode
    cert_dir="$(detect_cert_dir)"
    cert_file="$cert_dir/fullchain.pem"
    key_file="$cert_dir/privkey.pem"

    [ -r "$cert_file" ] || die "Fallback cert missing/unreadable: $cert_file"
    [ -r "$key_file" ] || die "Fallback key missing/unreadable: $key_file"
    su -s /bin/sh -c "test -r '$cert_file' && test -r '$key_file'" cfm >/dev/null 2>&1 || \
        die "Fallback cert/key are not readable by cfm group: $cert_dir"

    key_mode="$(stat -c '%a' "$key_file")"
    if [ $(( key_mode % 10 )) -ne 0 ]; then
        die "Fallback key is world-readable; expected mode 0640/0600: $key_file ($key_mode)"
    fi
    log "Fallback cert preflight passed: $cert_file / $key_file"
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

ensure_cache_dirs() {
    # Cache dirs owned by cfm (the angie worker user per angie.conf), not angie.
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
            log "Created cache directory: $d"
        fi
        # Chown to cfm (worker user) so proxy cache writes succeed.
        if id -u cfm >/dev/null 2>&1; then
            chown -R cfm:cfm "$d"
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

    # Record the packaged fingerprint the postinst compares against
    # (deploy_logrotate_config in package-proxy-config-deploy.sh). Without it,
    # a config this installer just deployed looks locally modified to the next
    # package upgrade, which then backs it up and warns for no reason.
    local stamp_dir="/var/lib/cfm/.packaged"
    mkdir -p "$stamp_dir"
    sha256sum "$dst" | awk '{print $1}' > "$stamp_dir/logrotate-cfm.sha256"

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
    local conf_dir="/etc/angie"

    mkdir -p "$conf_dir"
    mkdir -p /etc/logrotate.d

    backup_and_copy_file "/usr/share/cfm/configs/trusted_proxies.conf" \
        "$conf_dir/trusted_proxies.conf"
    # Panel listener scaffold includes HTTPS fallback certificates in :12083/:12087/:12096 blocks.
    local listener_tpl
    listener_tpl="$(render_panel_listener_template "Angie" "$conf_dir/cfm-panel-listeners.conf")"
    backup_and_copy_file "$listener_tpl" "$conf_dir/cfm-panel-listeners.conf"
    rm -f "$listener_tpl"

    backup_and_copy_file "/usr/share/cfm/configs/challenge_waf_bypass.conf" \
                         "$conf_dir/challenge_waf_bypass.conf"

    install_logrotate_config
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
                /*)
                    ;;
                *)
                    include_path="$conf_root/$include_path"
                    ;;
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
deploy_angie_conf() {
    # Mirrors install-openresty.sh's deploy_nginx_conf:
    # validate with `angie -t` against the staged config before swapping.
    local src="/usr/share/cfm/configs/angie.conf"
    local dst="/etc/angie/angie.conf"
    local prefix="/etc/angie"

    if [ ! -f "$src" ]; then
        warn "angie.conf source not found, skipping: $src"
        warn "(Ship configs/angie.conf in the CFM package to enable auto-deploy.)"
        return 0
    fi

    if ! command_exists angie; then
        warn "angie binary not found in PATH — skipping config test/deploy"
        return 0
    fi

    validate_panel_lua_guard_preflight "$src" "$prefix" || return 1
    if ! check_legacy_lua_paths_in_runtime_configs "$prefix" "$src"; then
        die "Detected legacy Angie Lua path references in candidate Angie config bundle"
    fi

    log "Testing angie config: $src"
    if angie -t -p "$prefix" -c "$src" >/dev/null 2>&1; then
        log "Config test passed"
        backup_and_copy_file "$src" "$dst"
        log "angie.conf deployed successfully"
    else
        warn "Config test FAILED — angie.conf NOT deployed. Output:"
        angie -t -p "$prefix" -c "$src" >&2 || true
        warn "Fix the errors above, then re-run this script or copy manually:"
        warn "  cp $src $dst && angie -t && systemctl restart angie"
    fi
}

validate_panel_lua_guard_preflight() {
    local angie_src="$1"
    local prefix="$2"
    local listener_conf="$prefix/cfm-panel-listeners.conf"

    if ! grep -Eq '^[[:space:]]*include[[:space:]]+cfm-panel-listeners\.conf;' "$angie_src"; then
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

print_next_steps() {
    local deployed=0
    if [ -f /etc/angie/angie.conf ] && grep -q "CFM testbed" /etc/angie/angie.conf 2>/dev/null; then
        deployed=1
    fi

    cat <<EOF

===========================================================================
  TESTBED INSTALL COMPLETE
===========================================================================

Pre-flight status:
  cfm user present:         $(id -u cfm >/dev/null 2>&1 && echo yes || echo "NO — angie will fail to start")
  Temp dirs (cfm:cfm):      /var/lib/cfm/nginx/{client_body_temp,proxy_temp}
  Log dir (cfm:cfm):        /var/log/angie/
  Cache dirs (cfm:cfm):     /var/cache/angie/cfm_{static,micro}
  Self-signed fallback:     /var/lib/cfm/certs/selfsigned/{fullchain,privkey}.pem
  CFM lua runtime checked:  /var/lib/cfm/lua/
  Extra resty (maxminddb):  /etc/angie/lualib/resty/
  angie.conf deployed:      $([ $deployed -eq 1 ] && echo yes || echo "NO — see below")

EOF

    if [ $deployed -eq 1 ]; then
        cat <<'EOF'
READY TO TEST — bring up Angie in place of OpenResty:

    systemctl stop openresty      # release :9080 and :9043
    systemctl start angie
    systemctl status angie
    tail -f /var/log/angie/error.log

Smoke tests:
    curl -sk http://127.0.0.1:9080/__ssl_debug
    curl -vk https://virgo.myip.gr/ 2>&1 | head
    tail -f /var/log/angie/access.cfm.log

ROLLBACK:
    systemctl stop angie && systemctl start openresty

EOF
    else
        cat <<'EOF'
MANUAL DEPLOY — configs/angie.conf was not found in the CFM package.

Stage and validate:
    cp <your>/angie.conf  /etc/angie/angie.conf.cfm
    angie -t -p /etc/angie -c /etc/angie/angie.conf.cfm

If clean:
    mv /etc/angie/angie.conf     /etc/angie/angie.conf.dist
    mv /etc/angie/angie.conf.cfm /etc/angie/angie.conf
    systemctl stop openresty
    systemctl start angie

EOF
    fi
}

main() {
    need_root
    detect_os

    log "Detected OS family: $OS_FAMILY (${OS_ID:-unknown} ${OS_VERSION_ID:-unknown})"
    log "*** TESTBED INSTALLER — experimental. Does not touch OpenResty. ***"

    # 1. Install packages
    if [ "$OS_FAMILY" = "debian" ]; then
        install_prereqs_debian
        setup_angie_repo_debian
    else
        install_prereqs_el
        setup_angie_repo_el
    fi
    install_angie_packages
    install_extra_resty

    # 2. CFM-specific pre-flight (user, temp dirs, log dir ownership)
    ensure_cfm_user_exists
    ensure_cfm_temp_dirs
    ensure_log_dir_ownership

    # 3. Angie-specific setup
    create_default_certs_if_missing
    validate_fallback_cert_preflight
    ensure_lua_dir
    ensure_cache_dirs
    deploy_cfm_files
    validate_shared_lua_runtime

    # 4. Auto-deploy angie.conf if shipped (with `angie -t` validation)
    deploy_angie_conf

    # 5. Next-steps report
    print_next_steps
    log "Done"
}

main "$@"
