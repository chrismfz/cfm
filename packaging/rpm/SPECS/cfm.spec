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


# ensure canonical shared assets are always shipped, even if %{pkgroot} staging omitted them
mkdir -p "%{buildroot}%{_datadir}/cfm"
if [ -d "%{projectroot}/configs" ]; then
  rm -rf "%{buildroot}%{_datadir}/cfm/configs"
  cp -a "%{projectroot}/configs" "%{buildroot}%{_datadir}/cfm/configs"
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

# kernsec.conf may reveal host hardening exceptions. Tighten only by
# removing group/other bits so upgrades do not loosen operator-chosen owner
# bits (for example 0400 stays 0400).
[ -f /etc/cfm/kernsec.conf ] && chmod go-rwx /etc/cfm/kernsec.conf || true

# lsm.conf discloses which BPF LSM policies are active on the host;
# same lock-down as kernsec.conf.
[ -f /etc/cfm/lsm.conf ] && chmod go-rwx /etc/cfm/lsm.conf || true

# shared Lua runtime dir (root writable, cfm readable)
mkdir -p /var/lib/cfm/lua
chown root:cfm /var/lib/cfm/lua
chmod 0750 /var/lib/cfm/lua
find /var/lib/cfm/lua -type f -exec chown root:cfm {} + || true
find /var/lib/cfm/lua -type f -exec chmod 0640 {} + || true


# seed/refresh runtime Lua files from packaged canonical source.
# policy:
#  - missing runtime file -> install packaged file
#  - existing file unchanged from last packaged fingerprint -> refresh to new packaged file
#  - existing file locally modified -> backup and force-refresh with packaged file
stamp_dir=/var/lib/cfm/lua/.packaged
mkdir -p "$stamp_dir"

lua_src_dir=""
for cand in /usr/share/cfm/configs/lua /usr/share/cfm/lua; do
    if [ -d "$cand" ]; then
        lua_src_dir="$cand"
        break
    fi
done

if [ -n "$lua_src_dir" ]; then
    find "$lua_src_dir" -maxdepth 1 -type f -name "*.lua" | while read -r src; do
        base="$(basename "$src")"
        dst="/var/lib/cfm/lua/$base"
        stamp="$stamp_dir/$base.sha256"
        new_hash="$(sha256sum "$src" | awk '{print $1}')"

        if [ ! -f "$dst" ]; then
            if install -m 0640 -o root -g cfm "$src" "$dst"; then
                echo "CFM Lua sync: copied new file $dst"
                printf '%s\n' "$new_hash" > "$stamp"
            else
                echo "WARNING: failed to copy new Lua file: $dst"
            fi
            continue
        fi

        old_hash=""
        [ -f "$stamp" ] && old_hash="$(cat "$stamp" 2>/dev/null || true)"
        cur_hash="$(sha256sum "$dst" | awk '{print $1}')"

        if [ -n "$old_hash" ] && [ "$cur_hash" = "$old_hash" ]; then
            if install -m 0640 -o root -g cfm "$src" "$dst"; then
                echo "CFM Lua sync: updated file $dst"
                printf '%s\n' "$new_hash" > "$stamp"
            else
                echo "WARNING: failed to update Lua file: $dst"
            fi
        elif [ "$cur_hash" = "$new_hash" ]; then
            echo "CFM Lua sync: already current $dst"
            printf '%s\n' "$new_hash" > "$stamp"
            # Refresh dst mtime even though the content didn't change, so
            # `ls -la /var/lib/cfm/lua/` is a useful at-a-glance check:
            # every .lua file's mtime reflects "processed in this install"
            # rather than "last time the content happened to change",
            # which could be weeks ago. The other branches already get
            # current mtime implicitly because `install` (no -p) writes
            # the file; this branch is the only no-op path where we'd
            # otherwise leave stale mtimes that look alarming on a fresh
            # deploy ("why are these files 10 days old?").
            touch "$dst" 2>/dev/null || true
        else
            backup="$dst.local-prepkg.$(date +%s)"
            cp -a "$dst" "$backup" || true
            echo "WARNING: local Lua runtime file differed; backup saved to $backup"
            if install -m 0640 -o root -g cfm "$src" "$dst"; then
                echo "CFM Lua sync: forced update applied $dst"
                printf '%s\n' "$new_hash" > "$stamp"
            else
                echo "WARNING: failed forced update for Lua file: $dst"
            fi
        fi
    done
else
    echo "WARNING: packaged lua source path missing: /usr/share/cfm/configs/lua (and /usr/share/cfm/lua)"
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
