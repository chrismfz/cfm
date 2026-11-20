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
| `/var/log/cfm-edge/` | the cfm-edge package's `/etc/logrotate.d/cfm-edge`, run hourly too by CFM's `/etc/cron.hourly/cfm-logrotate` |
| `/var/log/nginx/` | distro `/etc/logrotate.d/nginx` |
| `/var/log/apache2/`, `/var/log/httpd/` | distro `/etc/logrotate.d/{apache2,httpd}`; on cPanel, cpanellogd (see below) |
| `/usr/local/apache/logs/` | cPanel EA4 |

CFM owns exactly the two directories nobody else does. The OpenResty
tarball/package ships no logrotate config at all, which is why an OpenResty
edge is the one that grows a 200 GB `access.log`; Angie and the distro nginx
packages ship their own, and CFM must stay out of their way.

cfm-edge (CFM's own edge package, `chrismfz/cfm-edge`) also rotates its own
directory, so `logrotate-cfm` must not list it either. A busy edge writes tens
of GB a day, though, and a `maxsize` only fires when logrotate runs: CFM's
hourly pass (`configs/cfm-logrotate.cron`) therefore hands logrotate
`/etc/logrotate.d/cfm-edge` as well whenever the package is installed, as it
does `logrotate-cfm` for the OpenResty logs. The package's file carries the
size cap.

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
- **`dateext` + `dateformat -%Y%m%d-%H%M%S` in every block.** The distro's
  daily run reads `/etc/logrotate.conf` first; EL's sets a global `dateext`
  (`access.log-YYYYMMDD`), Debian's does not. The hourly pass runs
  `logrotate-cfm` without `logrotate.conf`, so before this it numbered
  generations (`access.log.1`, `.2`, …) on the same files. `rotate N` counts
  per naming scheme, so an EL node kept up to 2N generations, and a second
  dated rotation on one day failed with `error: destination … already exists,
  skipping rotation` (logrotate exit 1). Naming them in the block, to the
  second, gives both runs one scheme on every distro and two rotations never
  share a name (logrotate 3.14, EL8's, accepts `%H%M%S`). It must stay
  per-block, never global: the hourly pass hands logrotate `logrotate-cfm` and
  `/etc/logrotate.d/cfm-edge` in ONE invocation, and a global carries across
  files in one invocation (the cfm-edge package sets the same two lines in its
  own block). `check_logrotate_coverage.sh` asserts both lines in every block
  and, where logrotate is installed, runs two forced rotations a second apart
  on a temp tree. The dated names never match `*.log`, and CFM's
  rotated-log readers (`logscan.RotatedSiblings`) take `<name>-…` siblings by
  mtime.

  logrotate only ever expires generations whose name matches the CURRENT
  `dateformat`, so what a node had before the change is never deleted: the
  hourly pass's numbered ones (`access.log.1` … `.7.gz`, `cfm.log.1` …
  `.14.gz`; on Debian both runs made these) and, on EL, the distro run's
  date-only ones (`access.log-YYYYMMDD.gz`). Remove both by hand once they
  are older than the block's old retention (`rotate 7` / `rotate 14` days),
  so nothing the old config would still have kept, and the rotated-log tools
  (`include_rotated`, `rotated=N`) still reach, is lost. Run this a day after
  the upgrade, or again later; it only takes files past that age:

  ```bash
  find /usr/local/openresty/nginx/logs -maxdepth 1 -type f -regextype posix-extended -regex '.*\.log(\.[0-9]+|-[0-9]{8})(\.gz)?' -mtime +7 -print -delete
  ```

  ```bash
  find /var/log/cfm -maxdepth 1 -type f -regextype posix-extended -regex '.*\.log(\.[0-9]+|-[0-9]{8})(\.gz)?' -mtime +14 -print -delete
  ```

  Files younger than that stay until the next run of the command; a
  maxsize-heavy edge rotating several times a day can hold more than seven
  of them for a while.

  (and, on a host that still writes the legacy flat paths, the same
  `/var/log/cfm*.log.N` / `-YYYYMMDD` files under `/var/log` itself, by
  name: that directory is the distro's). The `%H%M%S` dateformat needs a
  logrotate whose `dateformat` knows `%H`/`%M`/`%S` (EL8's 3.14 does).

- **No `delaycompress` on the edge block.** An uncompressed `.1` of a 2 GB
  access log costs as much disk as the live file.
- **`/etc/cron.hourly/cfm-logrotate`** (`configs/cfm-logrotate.cron`).
  `maxsize` only fires when logrotate runs, and the distro timer runs it once a
  day — too coarse for a log growing at tens of GB/day. The hourly pass uses
  logrotate's default state file, the same one the daily run uses, so the
  time-based directives are not applied twice.
- **The Apache TSV fallback log (`access_cfm_tsv.log`, `httpd-cfm.conf`)** is
  capped by the same hourly script, not by a logrotate block. On cPanel
  `/var/log/apache2/` has no distro block: cpanellogd renames a log past 2 GB
  to `<name>.YYYY_MM_DD[.NN]` and never deletes the copies (2026-11-17: 316 GB
  on titan, 207 GB on mars, 175 GB on orion, a 26 GB never-rotated live file
  on virgo). The script deletes those copies after a day (that name form only:
  a distro logrotate generation such as `.1.gz` or an operator's own copy is
  left alone) and, past 512 MB, gzips the live file to `<name>.cfm-prev.gz`
  (one generation, overwritten) and truncates it in place; its only reader
  (the web detector's file source, used when the edge socket is off) follows
  the live file. The same step covers `/usr/local/apache/logs/` and
  `/var/log/nginx/access_cfm_tsv.log` (`nginx-cfm.conf`), and runs before the
  script's exit on a node without `logrotate-cfm`. `check_logrotate_coverage.sh`
  runs it against a temp tree (`CFM_TSV_LOGS`, `CFM_TSV_MAX_BYTES`,
  `CFM_LOGROTATE_CONF`). A
  logrotate block for it would be a `duplicate log entry` on a distro whose
  apache2 config globs `*.log`.
- **`/etc/systemd/system/logrotate.service.d/cfm-openresty.conf`**
  (`configs/cfm-logrotate-systemd.conf`, `ReadWritePaths=-/usr/local/openresty/nginx/logs`).
  EL9 / CloudLinux 9, Debian 11+ and Ubuntu 22.04+ run `logrotate.service`
  with `ProtectSystem=full`, which
  makes `/usr` read-only to it, so the daily run failed on every OpenResty log
  with `Read-only file system` and the unit ended `failed` each night. It
  still recorded those logs as rotated, so only the hourly `maxsize` pass ever
  rotated them (2026-10-10: titan and rigel had `access-panel.log` from July
  and May). The leading `-` lets the unit start on a host without OpenResty;
  EL8 (logrotate from cron) is unaffected. Another `/etc/logrotate.d` entry
  rotating logs under `/usr` (cPanel's, under `/usr/local`) can still leave
  the unit `failed`: read `journalctl -u logrotate`, not just the unit state. `check_logrotate_coverage.sh
  --host` fails a host where the unit has `ProtectSystem` set without it.

## Adding a new log

A new file under `/var/log/cfm/` or `/usr/local/openresty/nginx/logs/` **named
`*.log`** needs no change at all: logrotate expands the glob on every run, so
the file is rotated from the first pass after it appears. No package upgrade,
no installer re-run.

Anything else needs a config change in the same commit, and CI will tell you:
`check_logrotate_coverage.sh` collects every configured log path — including
`*_LOG_FILE` keys and `/var/log/cfm/…` literals in Go, whatever their
extension — and fails on one that nothing rotates. Two cases it catches:

- a log outside the two CFM-owned directories → add a block, unless the
  directory is vendor-rotated (then add it to `VENDOR_DIRS` in the checker and
  to the header comment in `configs/logrotate-cfm`);
- a log inside them that is not named `*.log` (`audit.json`, say) → either
  rename it to `*.log` or add an explicit entry.

## Deployment

Installed by **both**:

- `scripts/install-{openresty,angie}.sh` → `install_logrotate_config()`
- the package postinst, via `scripts/package-proxy-config-deploy.sh` →
  `deploy_logrotate_config()`

The postinst path matters: the installers are run once by hand, so hosts that
have only ever been package-upgraded previously had no CFM rotation at all.

### Refresh policy on upgrade

`/etc/logrotate.d/logrotate-cfm` is **force-refreshed on every package
upgrade** — that is the point, since a fleet-wide rotation fix that waits for
someone to re-run an installer does not fix anything. It follows the same
hash-stamp policy the postinst already uses for the Lua runtime, with the
fingerprint of the last deployed version in
`/var/lib/cfm/.packaged/logrotate-cfm.sha256`:

| Live file | What happens |
|---|---|
| missing | installed |
| identical to the packaged one | nothing, stamp refreshed |
| unchanged since we last deployed it | force-refreshed (normal upgrade) |
| locally modified | backed up to `/var/lib/cfm/backups/logrotate-cfm.local-prepkg.<ts>`, then force-refreshed, with a `WARNING` in the upgrade output |

So operator tuning is never lost silently, but it is also not sticky — if you
retune `rotate` or `maxsize` on a host, expect to reapply it after an upgrade,
or better, raise it so the shipped defaults suit the fleet. The installers
write the same stamp, so a hand-run installer deploy is not mistaken for a
local edit by the next upgrade.

`/etc/cron.hourly/cfm-logrotate` is a script rather than a knob, so it is
overwritten unconditionally. The `logrotate.service` drop-in is refreshed when
it differs, followed by `systemctl daemon-reload`; `install-openresty.sh`
installs it too.

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
