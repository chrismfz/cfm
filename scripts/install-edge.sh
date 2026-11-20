#!/usr/bin/env bash
#
# install-edge.sh — prepare cfm-edge (chrismfz/cfm-edge) as this node's edge
#
# cfm-edge is CFM's own edge package: nginx.org nginx + the OpenResty Lua set,
# laid out like a distro package. This script installs it (EL, from the same
# repo as cfm), ADOPTS it (CFM's edge config in /etc/cfm-edge, tested with
# `cfm-edge -t` before it goes in place) and makes the node ready to switch.
#
# It NEVER touches the live edge or the DNAT: no systemctl start / stop /
# restart / enable / disable, no `cfm dnat` (scripts/tests/check_install_edge.sh
# pins it). The switch and the way back are printed at the end, for the engine
# that runs now: `cfm dnat off` first (the origin serves directly), then the
# systemctl swap at leisure (both edges bind :9080 / :9043 and the panel
# listener ports, so only one runs at a time), then `cfm dnat on`.
#
# Adoption is what makes every later CFM upgrade keep cfm-edge's config and
# sidecars current (package-proxy-config-deploy.sh deploys only to an adopted
# cfm-edge: its live nginx.conf carries the line `# cfm-edge-adopted-by: cfm`).
#
# Layout:
#   Binary:        /usr/sbin/cfm-edge             (cfm-edge rpm)
#   Config:        /etc/cfm-edge/nginx.conf       (= /usr/share/cfm/configs/cfm-edge.conf,
#                                                   rendered from openresty.conf)
#   Sidecars:      /etc/cfm-edge/{trusted_proxies,challenge_waf_bypass,cfm-panel-listeners}.conf
#   CFM Lua:       /var/lib/cfm/lua/              (cfm package)
#   Logs:          /var/log/cfm-edge/             (rotated by the cfm-edge rpm)
#   Caches:        /var/cache/nginx/              (cfm_static + cfm_micro_<ttl>s)
#   Temp dirs:     /var/lib/cfm/nginx/*           (cfm:cfm)
#   PID:           /run/cfm-edge.pid              (the unit's PIDFile)
#
# Usage: bash scripts/install-edge.sh
#   CFM_EDGE_SKIP_INSTALL=1   do not install the rpm (it must already be there)
#   CFM_SKIP_REALIP=1         skip `cfm realip fix`

set -euo pipefail

readonly CFM_SHARED_LUA_DIR="/var/lib/cfm/lua"
# Every Lua module the package ships to $CFM_SHARED_LUA_DIR. Kept equal to
# configs/lua/*.lua by scripts/tests/check_shared_lua_layout.sh, as in the
# other two installers: a missing module either takes the edge down or
# silently disables an armed security control, so the pre-flight dies on it.
readonly CFM_LUA_MANIFEST=(
    cfm.lua cfm_bridge_cfg.lua cfm_cache.lua cfm_cache_log.lua cfm_cfg.lua
    cfm_clamav.lua cfm_clearance.lua cfm_decision.lua cfm_edgeban.lua cfm_filecache.lua
    cfm_fppolicy.lua cfm_geo.lua cfm_h3_config.lua cfm_hostmatch.lua cfm_ipkey.lua cfm_lockdown.lua
    cfm_origin_ka.lua cfm_panel.lua cfm_panel_hosts.lua cfm_panel_tunnel.lua
    cfm_pcw.lua cfm_purge.lua cfm_rules.lua cfm_selfip.lua cfm_shdict.lua cfm_stats.lua
    cfm_tlsfp.lua cfm_ua_emergency.lua cfm_waf.lua cfm_waf_detectors.lua
    cfm_waf_excl.lua cfm_waf_util.lua log-cfm.lua sslcollector.lua
)

readonly EDGE_BIN="/usr/sbin/cfm-edge"
readonly EDGE_CONF_DIR="/etc/cfm-edge"
readonly EDGE_MAIN_CONF="$EDGE_CONF_DIR/nginx.conf"
readonly CFM_CONFIGS="/usr/share/cfm/configs"
readonly EDGE_SRC_CONF="$CFM_CONFIGS/cfm-edge.conf"
# Must stay equal to CFMEDGE_ADOPT_MARKER in package-proxy-config-deploy.sh
# (check_install_edge.sh pins it).
readonly EDGE_ADOPT_MARKER="# cfm-edge-adopted-by: cfm"

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

# cfm-edge ships as one rpm for EL8/9/10 today; the .deb is a later step.
require_el() {
    [ -r /etc/os-release ] || die "cannot read /etc/os-release"
    # shellcheck disable=SC1091
    . /etc/os-release
    case " ${ID:-} ${ID_LIKE:-} " in
        *" rhel "*|*" centos "*|*" fedora "*|*" almalinux "*|*" rocky "*|*" cloudlinux "*) ;;
        *) die "cfm-edge is packaged for EL (AlmaLinux / Rocky / RHEL / CloudLinux 8, 9, 10) only so far; this is ${ID:-unknown}" ;;
    esac
    command_exists rpm || die "rpm not found"
}

# CFM must be installed and new enough to ship the cfm-edge config.
require_cfm() {
    [ -f "$EDGE_SRC_CONF" ] || die "$EDGE_SRC_CONF missing: install or upgrade the cfm package first (cfm-edge support arrived with configs/cfm-edge.conf)"
    grep -qxF "$EDGE_ADOPT_MARKER" "$EDGE_SRC_CONF" \
        || die "$EDGE_SRC_CONF has no adoption line ($EDGE_ADOPT_MARKER): upgrade the cfm package"
}

install_cfm_edge_package() {
    if rpm -q cfm-edge >/dev/null 2>&1; then
        log "cfm-edge already installed: $(rpm -q cfm-edge)"
        return 0
    fi
    if [ "${CFM_EDGE_SKIP_INSTALL:-0}" = "1" ]; then
        die "cfm-edge is not installed and CFM_EDGE_SKIP_INSTALL=1"
    fi
    local pm
    if command_exists dnf; then pm=dnf; elif command_exists yum; then pm=yum; else die "neither dnf nor yum found"; fi
    log "Installing cfm-edge ($pm, from the repo cfm comes from)"
    "$pm" -y install cfm-edge || die "could not install cfm-edge: is the nixpal repo (the one cfm is installed from) configured on this node?"
    log "Installed: $(rpm -q cfm-edge)"
}

# ─────────────────────────────────────────────────────────────────────────────
# CFM pre-flight (cfm-edge.conf uses "user cfm;")
# ─────────────────────────────────────────────────────────────────────────────

ensure_cfm_user_exists() {
    id -u cfm >/dev/null 2>&1 || die "the cfm user does not exist: cfm-edge.conf runs its workers as 'user cfm;' (the cfm package creates it)"
    log "cfm user exists"
}

ensure_cfm_temp_dirs() {
    # cfm-edge.conf sets client_body_temp_path / proxy_temp_path under
    # /var/lib/cfm/nginx, shared with the other engines; workers run as cfm.
    local d
    for d in /var/lib/cfm/nginx/client_body_temp /var/lib/cfm/nginx/proxy_temp; do
        [ -d "$d" ] || { mkdir -p "$d"; log "Created CFM temp dir: $d"; }
        chown -R cfm:cfm "$d"
    done
}

create_default_certs_if_missing() {
    local cert_dir=/var/lib/cfm/certs/selfsigned
    local cert_file="$cert_dir/fullchain.pem" key_file="$cert_dir/privkey.pem"

    if [ -s "$cert_file" ] && [ -s "$key_file" ]; then
        log "Default certs already present: $cert_file and $key_file"
    else
        log "Creating self-signed fallback cert in: $cert_dir"
        mkdir -p "$cert_dir"
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$key_file" -out "$cert_file" \
            -subj "/C=GR/ST=State/L=City/O=CFM/CN=localhost"
    fi
    chown root:cfm "$cert_file" "$key_file"
    chmod 0640 "$cert_file" "$key_file"

    su -s /bin/sh -c "test -r '$cert_file' && test -r '$key_file'" cfm >/dev/null 2>&1 \
        || die "Fallback cert/key are not readable by the cfm group: $cert_dir"
    log "Fallback cert preflight passed"
}

validate_shared_lua_runtime() {
    local missing=() name
    for name in "${CFM_LUA_MANIFEST[@]}"; do
        [ -r "$CFM_SHARED_LUA_DIR/$name" ] || missing+=("$CFM_SHARED_LUA_DIR/$name")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        die "Missing required CFM Lua files in shared runtime: ${missing[*]}"
    fi
    log "CFM Lua runtime complete: $CFM_SHARED_LUA_DIR"
}

ensure_cache_dirs() {
    # Every proxy_cache_path dir must exist before `-t` below. ONE helper,
    # shared with the packages and the other installers.
    local here helper
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    for helper in "$here/cfm-cache-dirs.sh" /usr/share/cfm/scripts/cfm-cache-dirs.sh; do
        [ -f "$helper" ] && break
        helper=""
    done
    [ -n "$helper" ] || die "cfm-cache-dirs.sh not found next to this installer or in /usr/share/cfm/scripts"
    if sh "$helper"; then
        log "Site Cache dirs ready under /var/cache/nginx"
    else
        warn "Site Cache dir provisioning reported a problem (see above)"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Adoption: sidecars, then the main config, each tested before it goes live
# ─────────────────────────────────────────────────────────────────────────────

backup_once() {
    # Keep the file the package or an operator put there, once: a re-run must
    # not overwrite the first backup with CFM's own copy.
    local f="$1"
    if [ -e "$f" ] && [ ! -e "$f.pre-cfm" ]; then
        cp -p "$f" "$f.pre-cfm"
        log "Backed up $f -> $f.pre-cfm"
    fi
}

render_panel_listener_template() {
    local listener_dest="$1"
    local src="$CFM_CONFIGS/cfm-panel-listeners.conf.in"
    [ -f "$src" ] || die "panel listener template not found: $src"
    sed -e "s|@ENGINE@|cfm-edge|g" -e "s|@LISTENER_DEST@|${listener_dest}|g" "$src"
}

deploy_sidecars() {
    mkdir -p "$EDGE_CONF_DIR"
    local f
    for f in trusted_proxies.conf challenge_waf_bypass.conf; do
        [ -f "$CFM_CONFIGS/$f" ] || die "packaged sidecar missing: $CFM_CONFIGS/$f"
        install -m 0644 -o root -g root "$CFM_CONFIGS/$f" "$EDGE_CONF_DIR/$f"
        log "Installed $EDGE_CONF_DIR/$f"
    done
    local tmp
    tmp="$(mktemp)"
    render_panel_listener_template "$EDGE_CONF_DIR/cfm-panel-listeners.conf" >"$tmp"
    install -m 0644 -o root -g root "$tmp" "$EDGE_CONF_DIR/cfm-panel-listeners.conf"
    rm -f "$tmp"
    log "Installed $EDGE_CONF_DIR/cfm-panel-listeners.conf"
}

deploy_main_conf() {
    [ -x "$EDGE_BIN" ] || die "$EDGE_BIN not found"
    log "Testing CFM's cfm-edge config: $EDGE_BIN -t -c $EDGE_SRC_CONF"
    if ! "$EDGE_BIN" -t -c "$EDGE_SRC_CONF"; then
        die "config test FAILED (above): $EDGE_MAIN_CONF left unchanged, cfm-edge NOT adopted"
    fi
    backup_once "$EDGE_MAIN_CONF"
    install -m 0644 -o root -g root "$EDGE_SRC_CONF" "$EDGE_MAIN_CONF"
    "$EDGE_BIN" -t -q || die "the installed $EDGE_MAIN_CONF fails its config test; restore $EDGE_MAIN_CONF.pre-cfm"
    log "Adopted: $EDGE_MAIN_CONF is CFM's config (CFM upgrades keep it current from now on)"
}

# The edge proxies every web request to the origin from 127.0.0.1; `cfm realip
# fix` makes the origin trust it (docs/origin-real-ip.md). Never fatal.
ensure_origin_realip() {
    if [ "${CFM_SKIP_REALIP:-0}" = "1" ]; then
        log "Origin real-IP: skipped (CFM_SKIP_REALIP=1); run 'cfm realip fix' later"
        return 0
    fi
    if ! command_exists cfm; then
        warn "Origin real-IP: cfm is not on PATH; run 'cfm realip fix' later"
        return 0
    fi
    local rc=0
    cfm realip fix || rc=$?
    [ "$rc" -eq 0 ] || warn "Origin real-IP: not set automatically (see above); check with 'cfm realip'"
    return 0
}

# The IPv6 listen decision (EDGE_LISTEN_V6, off by default; docs/edge-ipv6.md),
# for cfm-edge's conf dir too. Runs after the realip fix, as in the other
# installers. Never fails the install: on any doubt the edge stays IPv4 only.
ensure_edge_listen_v6() {
    local script=/usr/share/cfm/scripts/cfm-edge-listen-v6.sh
    if [ ! -f "$script" ]; then
        warn "Edge IPv6 listen: $script missing; IPv4 only until the cfm package runs it"
        return 0
    fi
    sh "$script" render || true
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Report: the switch and the way back, for the engine running now
# ─────────────────────────────────────────────────────────────────────────────

active_edge() {
    local u
    for u in angie openresty cfm-edge; do
        if systemctl is-active --quiet "$u.service" 2>/dev/null; then
            printf '%s\n' "$u"
            return 0
        fi
    done
    printf '%s\n' ""
}

print_next_steps() {
    local old
    old="$(active_edge)"

    cat <<EOF

===========================================================================
  cfm-edge PREPARED (the live edge was not touched)
===========================================================================
  Package:      $(rpm -q cfm-edge 2>/dev/null || echo "?")
  Config:       $EDGE_MAIN_CONF (CFM's; previous copy: $EDGE_MAIN_CONF.pre-cfm)
  Config test:  $("$EDGE_BIN" -t -q >/dev/null 2>&1 && echo passed || echo "FAILED: run $EDGE_BIN -t")
  Live edge:    ${old:-none running}

EOF

    if [ "$old" = "cfm-edge" ]; then
        cat <<'EOF'
cfm-edge is already the live edge; reload it to apply the new config:

    systemctl reload cfm-edge
EOF
        return 0
    fi

    cat <<'EOF'
Nothing below has been run: every step is yours.

1) Take the edge out of the path first (the sites are served by the origin
   directly meanwhile, without WAF/challenge):

    cfm dnat                    # note what is on: web, and panel ports
    cfm dnat off
    cfm dnat cpanel off         # only if panel DNAT was on

EOF
    if [ -n "$old" ]; then
        cat <<EOF
2) Switch ${old} -> cfm-edge (both bind :9080/:9043 and the panel ports):

    systemctl stop ${old}
    systemctl start cfm-edge
    systemctl status cfm-edge --no-pager
    ss -ltnp | grep -E ':(9080|9043)\b'           # owner "cfm-edge"
    curl -skI https://127.0.0.1:9043/ -H 'Host: <a site on this node>'
    tail -f /var/log/cfm-edge/error.log

3) When YOU are satisfied (nothing here runs it), put the edge back in the path:

    cfm dnat on
    cfm dnat cpanel on          # only if it was on in step 1

4) Once it serves well, make it survive a reboot:

    systemctl disable ${old} && systemctl enable cfm-edge

ROLLBACK (back to ${old}), at any point:

    cfm dnat off                # (and cfm dnat cpanel off)
    systemctl stop cfm-edge && systemctl start ${old}
    systemctl disable cfm-edge && systemctl enable ${old}   # if step 4 ran
    cfm dnat on                 # (and cfm dnat cpanel on)
EOF
    else
        cat <<'EOF'
2) No edge is running. Start cfm-edge, check it, then step 3:

    systemctl enable --now cfm-edge
    systemctl status cfm-edge --no-pager

3) When YOU are satisfied (nothing here runs it), put the edge in the path:

    cfm dnat on
    cfm dnat cpanel on          # if the panel ports go through the edge
EOF
    fi
}

main() {
    need_root
    require_el
    require_cfm
    install_cfm_edge_package

    ensure_cfm_user_exists
    ensure_cfm_temp_dirs
    create_default_certs_if_missing
    validate_shared_lua_runtime
    ensure_cache_dirs

    deploy_sidecars
    deploy_main_conf
    ensure_origin_realip
    ensure_edge_listen_v6

    print_next_steps
    log "Done"
}

main "$@"
