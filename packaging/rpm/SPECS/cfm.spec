Name:           cfm
Version:        2025.10.09
Release:        1.115555%{?dist}
Summary:        Local nftables manager (block/allow with TTL), plus simple list/unlist/flush
License:        MIT
URL:            https://nixpal.com
BuildArch:      x86_64
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
cfm: local nftables manager (block/allow with optional TTL), plus simple list/unlist/flush.

%prep
# nothing

%build
# nothing

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}

# Αντέγραψε ΜΟΝΟ ό,τι θες από το pkgroot (και όχι ολόκληρο το pkgroot)
if [ -d "%{pkgroot}/usr" ]; then
  cp -a "%{pkgroot}/usr" "%{buildroot}/"
fi
if [ -d "%{pkgroot}/etc" ]; then
  cp -a "%{pkgroot}/etc" "%{buildroot}/"
fi

# Αν για οποιονδήποτε λόγο υπάρχει service κάτω από /lib/systemd/system, μετακίνησέ το στο _unitdir
if [ -f "%{buildroot}/lib/systemd/system/cfm.service" ]; then
  mkdir -p "%{buildroot}%{_unitdir}"
  mv "%{buildroot}/lib/systemd/system/cfm.service" "%{buildroot}%{_unitdir}/"
  rm -rf "%{buildroot}/lib/systemd"
fi

# Βάλε το LICENSE στη σωστή θέση (και ΜΟΝΟ εκεί)
install -Dm644 %{projectroot}/LICENSE %{buildroot}/usr/share/licenses/cfm/LICENSE



%files
%license /usr/share/licenses/cfm/LICENSE
%{_bindir}/cfm
%{_unitdir}/cfm.service
%config(noreplace) /etc/cfm/cfm.conf
%config(noreplace) /etc/cfm/detectors.conf
%config(noreplace) /etc/cfm/notify.conf
%config(noreplace) /etc/cfm/cfm.allow
%config(noreplace) /etc/cfm/cfm.deny
%config(noreplace) /etc/cfm/cfm.blocklists
%config(noreplace) /etc/cfm/cfm.dyndns


%post
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
