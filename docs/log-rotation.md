# Log rotation

CFM writes to a lot of files. This is which of them rotate, who rotates them,
and how to verify it on a live server.

## Verify (start here)

```bash
# On a server: what exists, how big, and which logrotate config covers it
scripts/tests/check_logrotate_coverage.sh --host

# What logrotate would actually do with the CFM config
logrotate -d /etc/logrotate.d/logrotate-cfm
```

In the repo (and in CI) the same script with no arguments asserts that every
log path CFM configures is covered by something.

## Who rotates what

| Directory | Rotated by |
|---|---|
| `/var/log/cfm/` | `/etc/logrotate.d/logrotate-cfm` (CFM) |
| `/usr/local/openresty/nginx/logs/` | `/etc/logrotate.d/logrotate-cfm` (CFM) |
| `/var/log/angie/` | vendor `/etc/logrotate.d/angie` |
| `/var/log/nginx/` | distro `/etc/logrotate.d/nginx` |
| `/var/log/apache2/`, `/var/log/httpd/` | distro `/etc/logrotate.d/{apache2,httpd}` |
| `/usr/local/apache/logs/` | cPanel EA4 |

CFM owns exactly the two directories nobody else does. The OpenResty
tarball/package ships no logrotate config at all, which is why an OpenResty
edge is the one that grows a 200 GB `access.log`; Angie and the distro nginx
packages ship their own, and CFM must stay out of their way.

**Do not add a vendor-rotated path to `configs/logrotate-cfm`.** logrotate
refuses a path declared by two configs:

```
error: /etc/logrotate.d/logrotate-cfm:12 duplicate log entry for /var/log/nginx/access_cfm_tsv.log
```

That is a config error, not a warning — it does not add rotation, it stops the
run. If a vendor directory turns out not to be covered on some host, fix it
there (or ship a host-specific drop-in), don't duplicate the entry.

## Why the config looks the way it does

`configs/logrotate-cfm` → `/etc/logrotate.d/logrotate-cfm`.

- **Globs, not filenames.** `*.log` per directory. The previous enumerated
  list silently missed every log added after it was written
  (`access.bad_request.log`, `cfm.clam.log`, `cfm.socket.log`,
  `ua_emergency.log`). `*.log` never re-matches an already-rotated
  `.log.1`/`.log.2.gz`.
- **`copytruncate`.** No postrotate signal, so no pid-file path assumptions —
  the same file works for OpenResty, Angie, Debian, RHEL, cPanel and
  DirectAdmin. The cost is that rotation copies the whole file, which is what
  makes the size caps load-bearing.
- **`maxsize`, not just `daily`.** A busy edge writes tens of GB/day. With
  `daily` alone `access.log` grows unbounded until the nightly run, and once it
  is bigger than the free space `copytruncate` + `compress` can no longer
  complete — so it never rotates again and the disk fills. Caps are 200M for
  `/var/log/cfm/`, 2G for the edge.
- **No `delaycompress` on the edge block.** An uncompressed `.1` of a 2 GB
  access log costs as much disk as the live file.
- **`/etc/cron.hourly/cfm-logrotate`** (`configs/cfm-logrotate.cron`).
  `maxsize` only fires when logrotate runs, and the distro timer runs it once a
  day — too coarse for a log growing at tens of GB/day. The hourly pass uses
  logrotate's default state file, the same one the daily run uses, so the
  time-based directives are not applied twice.

## Deployment

Installed by **both**:

- `scripts/install-{openresty,angie}.sh` → `install_logrotate_config()`
- the package postinst, via `scripts/package-proxy-config-deploy.sh` →
  `deploy_logrotate_config()`

The postinst path matters: the installers are run once by hand, so hosts that
have only ever been package-upgraded previously had no CFM rotation at all.

Neither path leaves a `.bak` inside `/etc/logrotate.d/`. A
`logrotate-cfm.bak` there is read as a second config by any logrotate whose
taboo-extension list predates `.bak` (older EL builds), which reintroduces the
duplicate-entry abort above. Existing backups are removed on deploy; the
previous config is kept at `/var/lib/cfm/backups/logrotate-cfm.bak`.

## Recovering a host that already filled up

`copytruncate` on a 200 GB file needs 200 GB free, so rotation cannot dig you
out. Truncate in place instead — this keeps the fd valid, so no reload is
needed:

```bash
cd /usr/local/openresty/nginx/logs
: > access.log            # or `truncate -s 0 access.log`
```

Never `rm` a live log: the process keeps writing to the unlinked inode and the
space is not returned until it is restarted. After truncating, deploy the
current config and confirm:

```bash
scripts/tests/check_logrotate_coverage.sh --host
logrotate -d /etc/logrotate.d/logrotate-cfm
```
