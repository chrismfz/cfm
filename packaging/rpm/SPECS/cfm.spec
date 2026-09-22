Name:           cfm
Version:        2026.05.14
Release:        1.201438%{?dist}
Summary:        Local nftables manager (block/allow with TTL), plus simple list/unlist/flush
License:        MIT
URL:            https://nixpal.com
BuildArch:      x86_64
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires(pre): shadow-utils
Requires: libmaxminddb-devel

%description
cfm: local nftables manager (block/allow with optional TTL), plus simple list/unlist/flush.

%pre
# ---------------------------------------------------------------------------
# cfm system user and group
#
# The cfm group is used by OpenResty (SSLCollector unix socket, cfm_token.lua).
# The cfm user is the identity OpenResty workers run under.
# getent guards make the calls idempotent across installs and upgrades.
# ---------------------------------------------------------------------------
if ! getent group cfm >/dev/null 2>&1; then
    groupadd --system cfm
fi

if ! getent passwd cfm >/dev/null 2>&1; then
    useradd \
        --system \
        --gid cfm \
        --no-create-home \
        --home-dir /var/lib/cfm \
        --shell /sbin/nologin \
        -c "CFM service account" \
        cfm
fi

%prep
# nothing

%build
# nothing

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}

if [ -d "%{pkgroot}/usr" ]; then
  cp -a "%{pkgroot}/usr" "%{buildroot}/"
fi
if [ -d "%{pkgroot}/etc" ]; then
  cp -a "%{pkgroot}/etc" "%{buildroot}/"
fi
if [ -d "%{pkgroot}/var" ]; then
  cp -a "%{pkgroot}/var" "%{buildroot}/"
fi

# detectors.conf overlay directory: shipped EMPTY (package never installs
# files into it) so per-host overrides in it survive upgrades while the base
# detectors.conf conffile stays pristine and updateable.
mkdir -p %{buildroot}/etc/cfm/detectors.d


# ensure canonical shared assets are always shipped, even if %%{pkgroot} staging omitted them
mkdir -p "%{buildroot}%{_datadir}/cfm"
if [ -d "%{projectroot}/configs" ]; then
  rm -rf "%{buildroot}%{_datadir}/cfm/configs"
  cp -a "%{projectroot}/configs" "%{buildroot}%{_datadir}/cfm/configs"
  # Lua modules belong in /var/lib/cfm/lua/ ONLY. This cp is unfiltered, so it
  # would otherwise ship ~900 KB of every module a second time here - and
  # resurrect the source tree the removed post-scriptlet sync loop copied from.
  # The Makefile's own PKGROOT staging already excludes lua/; match it.
  rm -rf "%{buildroot}%{_datadir}/cfm/configs/lua"
fi
if [ -d "%{projectroot}/scripts" ]; then
  rm -rf "%{buildroot}%{_datadir}/cfm/scripts"
  cp -a "%{projectroot}/scripts" "%{buildroot}%{_datadir}/cfm/scripts"
fi
# canonicalize Lua runtime payload permissions in the package payload itself
if [ -d "%{buildroot}/var/lib/cfm/lua" ]; then
  chmod 0750 "%{buildroot}/var/lib/cfm/lua"
  find "%{buildroot}/var/lib/cfm/lua" -type f -exec chmod 0640 {} +
fi

if [ -f "%{buildroot}/lib/systemd/system/cfm.service" ]; then
  mkdir -p "%{buildroot}%{_unitdir}"
  mv "%{buildroot}/lib/systemd/system/cfm.service" "%{buildroot}%{_unitdir}/"
  rm -rf "%{buildroot}/lib/systemd"
fi

install -Dm644 %{projectroot}/LICENSE %{buildroot}/usr/share/licenses/cfm/LICENSE



%files
%license /usr/share/licenses/cfm/LICENSE
%{_bindir}/cfm
%{_unitdir}/cfm.service
%attr(0700,root,root) %dir /etc/cfm
%attr(0700,root,root) %dir /etc/cfm/detectors.d
%config(noreplace) /etc/cfm/cfm.conf
%config(noreplace) /etc/cfm/detectors.conf
%attr(0600,root,root) %config(noreplace) /etc/cfm/kernsec.conf
%attr(0600,root,root) %config(noreplace) /etc/cfm/lsm.conf
%config(noreplace) /etc/cfm/webdetector_malpaths.txt
%config(noreplace) /etc/cfm/webdetector_challenge_paths.txt
%config(noreplace) /etc/cfm/webdetector_challenge_exclude.txt
%config(noreplace) /etc/cfm/notify.conf
%config(noreplace) /etc/cfm/cfm.allow
%config(noreplace) /etc/cfm/cfm.deny
%config(noreplace) /etc/cfm/cfm.blocklists
%config(noreplace) /etc/cfm/cfm.ignore
%attr(0600,root,root) %config(noreplace) /etc/cfm/cfm.dnat_bypass
%attr(0600,root,root) %config(noreplace) /etc/cfm/cfm.dnat_cpanel_bypass
%config(noreplace) /etc/cfm/cfm.dyndns
%config(noreplace) /etc/cfm/cfm-admin.htpasswd

%dir /var/lib/cfm
%dir %attr(0750,root,cfm) /var/lib/cfm/lua
%attr(0640,root,cfm) /var/lib/cfm/lua/*

# shared examples (always overwritten on upgrade)
%dir %{_datadir}/cfm
%dir %{_datadir}/cfm/configs
%{_datadir}/cfm/configs/*
%dir %{_datadir}/cfm/scripts
%{_datadir}/cfm/scripts/*
%dir %{_datadir}/cfm/plugins
%{_datadir}/cfm/plugins/*


%post

# /etc/cfm holds bypass lists, kernsec.conf, lsm.conf and other root-only
# config. Force 0700 on upgrade so existing 0755 installs get tightened.
# Files needing non-root read access live in /var/lib/cfm/ instead.
[ -d /etc/cfm ] && chmod 0700 /etc/cfm || true

# kernsec.conf may reveal host hardening exceptions. Tighten only by
# removing group/other bits so upgrades do not loosen operator-chosen owner
# bits (for example 0400 stays 0400).
[ -f /etc/cfm/kernsec.conf ] && chmod go-rwx /etc/cfm/kernsec.conf || true

# lsm.conf discloses which BPF LSM policies are active on the host;
# same lock-down as kernsec.conf.
[ -f /etc/cfm/lsm.conf ] && chmod go-rwx /etc/cfm/lsm.conf || true

# Per-server API/MaxMind secrets overlay. Seed an editable 0600 template on
# first install only; never overwrite an operator's existing file. It is not
# tracked by rpm (created here, not in the file manifest), so upgrades leave it.
if [ ! -e /etc/cfm/cfm.api.conf ] && [ -f /usr/share/cfm/configs/cfm.api.conf.example ]; then
    # Seeding is a convenience, never fatal — keep the scriptlet going regardless
    # (parity with the deb postinst, which runs under set -e).
    cp -p /usr/share/cfm/configs/cfm.api.conf.example /etc/cfm/cfm.api.conf 2>/dev/null || true
    chmod 0600 /etc/cfm/cfm.api.conf 2>/dev/null || true
fi

# shared Lua runtime dir (root writable, cfm readable)
mkdir -p /var/lib/cfm/lua
chown root:cfm /var/lib/cfm/lua
chmod 0750 /var/lib/cfm/lua
find /var/lib/cfm/lua -type f -exec chown root:cfm {} + || true
find /var/lib/cfm/lua -type f -exec chmod 0640 {} + || true


# NOTE: Lua modules are delivered by the PACKAGE MANAGER, not by this script.
# The package installs them straight to /var/lib/cfm/lua/ and owns every one,
# so an upgrade installs new modules, refreshes changed ones and REMOVES
# modules the new version dropped - all of it before this script runs.
#
# A hand-rolled "seed/refresh" loop used to live here, copying from
# /usr/share/cfm/configs/lua over the files the package had just installed. It
# behaved differently per packaging, and was useless in both:
#   - deb: that source was never shipped, so the loop only ever fell through to
#     "WARNING: packaged lua source path missing" on every install and upgrade,
#     about a path that is not supposed to exist.
#   - rpm: the source WAS shipped (this spec's install section copied the whole
#     configs/ tree unfiltered, so every module rode along a second time), and
#     the loop re-copied ~900 KB over byte-identical files and rewrote a stamp
#     each run. Its headline policy - "locally modified -> backup and
#     force-refresh" - could never fire on an upgrade anyway: rpm replaces
#     /var/lib/cfm/lua/* BEFORE this scriptlet runs, so by the time it compares
#     hashes the operator edit is already gone and the hashes already match.
# Removed 2026-09-22; the rpm no longer ships the duplicate source tree either.
#
# A hand-edit under /var/lib/cfm/lua/ IS overwritten on upgrade with no backup.
# That was always true - the loop never actually changed it. These are code
# files, deliberately NOT config-marked (a .rpmnew would freeze security code
# at the operator version). `rpm -V cfm` / `dpkg --verify cfm` report such
# edits. Edit /etc/cfm/*, never /var/lib/cfm/lua/*.

# Retire the stamp directory the removed loop wrote into. The stamps are ours
# and nothing reads them now; on rpm hosts the directory is NOT empty (one
# .sha256 per module), so a bare rmdir would fail and orphan them forever.
rm -f /var/lib/cfm/lua/.packaged/*.sha256 2>/dev/null || true
rmdir /var/lib/cfm/lua/.packaged 2>/dev/null || true

# cPanel/WHM plugin: refresh the live plugin CODE on upgrade (non-disruptive;
# no register_appconfig / install_plugin / cpsrvd restart). Acts only when cPanel
# is present and the plugin is already installed. Shared with the deb postinst via
# scripts/cpanel-plugin-refresh.sh so the two packaging scripts can't drift.
if [ -x /usr/share/cfm/scripts/cpanel-plugin-refresh.sh ]; then
    /usr/share/cfm/scripts/cpanel-plugin-refresh.sh || true
fi

# nginx temp dirs — must be owned by the cfm worker user
# (default OpenResty paths are root-owned; workers running as cfm can't write them)
for d in /var/lib/cfm/nginx/client_body_temp /var/lib/cfm/nginx/proxy_temp; do
    mkdir -p "$d"
    chown cfm:cfm "$d"
    chmod 700 "$d"
done

# Validate and deploy packaged Angie/OpenResty configs for installed engines.
if [ -x /usr/share/cfm/scripts/package-proxy-config-deploy.sh ]; then
    /usr/share/cfm/scripts/package-proxy-config-deploy.sh || true
else
    echo "WARNING: CFM proxy config deploy helper missing: /usr/share/cfm/scripts/package-proxy-config-deploy.sh"
fi

# Reload edge proxies if they are currently active. We do this AFTER
# the cfm restart cycle below, not before — that way fresh angie/openresty
# workers run init_worker_by_lua against a cfm that is already up and
# has its socket + snapshot ready, instead of racing the restart and
# falling back through soft-start retries. We never enable or start a
# service here: hosts may run neither, only one, or both.

# Ensure correct SELinux context in case older versions used /lib path
[ -f /lib/systemd/system/cfm.service ] && \
  chcon -h system_u:object_r:systemd_unit_file_t:s0 /lib/systemd/system/cfm.service || true

systemctl daemon-reload || true

# Step 1: check if running
was_active=0
if systemctl is-active --quiet cfm.service; then
    echo "CFM is currently running — stopping..."
    was_active=1
    systemctl stop cfm.service || true
fi

# Step 2: always disable (flush nftables)
if [ -x "%{_bindir}/cfm" ]; then
    echo "Flushing tables with: cfm disable"
    "%{_bindir}/cfm" disable || true
fi

# Step 3: if it was running, start again
if [ "$was_active" -eq 1 ]; then
    echo "CFM was active — starting it again..."
    systemctl start cfm.service || true
else
    echo "CFM was not running — leaving stopped."
fi

# Step 4: now that cfm is back up (or staying down deliberately), reload
# the edge proxies so their workers re-init against the ready state.
# Short sleep gives cfm a moment to create /var/run/sslcollector.sock and
# rewrite /var/lib/cfm/sslcollector/dump.json with the correct 0640
# perms — both prerequisites for a clean init_worker_by_lua run.
if command -v systemctl >/dev/null 2>&1; then
    sleep 2
    for svc in angie.service openresty.service; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo "CFM: reloading $svc to apply updated config..."
            systemctl reload "$svc" || true
        fi
    done
fi


%preun
%systemd_preun cfm.service

%postun
%systemd_postun_with_restart cfm.service

%changelog
* Mon May 04 2026 CFM Maintainers <maintainers@cfm.local> - 0.0.0-1
- Fix cfm_clearance normalize_host trailing-dot pattern ("%.+$") to avoid invalid escape syntax.
- Add CI preflight check that requires cfm_clearance so Lua parse errors fail before deployment.
- Note: this regression could abort OpenResty/Angie require loading and surface as HTTP 500 responses.

* Tue Sep 02 2025 Chris <chris@nixpal.com> - 0.0.0-1
- Initial RPM packaging
