Name:           cfm
Version:        2026.04.30
Release:        1.105909%{?dist}
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
%config(noreplace) /etc/cfm/cfm.conf
%config(noreplace) /etc/cfm/detectors.conf
%config(noreplace) /etc/cfm/webdetector_malpaths.txt
%config(noreplace) /etc/cfm/webdetector_challenge_paths.txt
%config(noreplace) /etc/cfm/webdetector_challenge_exclude.txt
%config(noreplace) /etc/cfm/notify.conf
%config(noreplace) /etc/cfm/cfm.allow
%config(noreplace) /etc/cfm/cfm.deny
%config(noreplace) /etc/cfm/cfm.blocklists
%config(noreplace) /etc/cfm/cfm.ignore
%config(noreplace) /etc/cfm/cfm.dyndns
%config(noreplace) /etc/cfm/cfm-admin.htpasswd

# shared examples (always overwritten on upgrade)
%dir %{_datadir}/cfm
%dir %{_datadir}/cfm/configs
%{_datadir}/cfm/configs/*
%dir %{_datadir}/cfm/scripts
%{_datadir}/cfm/scripts/*
%dir %{_datadir}/cfm/plugins
%{_datadir}/cfm/plugins/*


%post
# shared Lua token dir (root writable, cfm readable)
mkdir -p /var/lib/cfm/lua
chown root:cfm /var/lib/cfm/lua
chmod 750 /var/lib/cfm/lua

# nginx temp dirs — must be owned by the cfm worker user
# (default OpenResty paths are root-owned; workers running as cfm can't write them)
for d in /var/lib/cfm/nginx/client_body_temp /var/lib/cfm/nginx/proxy_temp; do
    mkdir -p "$d"
    chown cfm:cfm "$d"
    chmod 700 "$d"
done

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


%preun
%systemd_preun cfm.service

%postun
%systemd_postun_with_restart cfm.service

%changelog
* Tue Sep 02 2025 Chris <chris@nixpal.com> - 0.0.0-1
- Initial RPM packaging
