Name:           cfm
Version:        2025.09.28
Release:        1.203537%{?dist}
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
%systemd_post cfm.service

%preun
%systemd_preun cfm.service

%postun
%systemd_postun_with_restart cfm.service

%changelog
* Tue Sep 02 2025 Chris <chris@nixpal.com> - 0.0.0-1
- Initial RPM packaging
