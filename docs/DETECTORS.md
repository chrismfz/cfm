# Detectors Guide

How to configure CFM's log-driven detectors safely in production: start with
`BLOCK = dryrun`, tune, then a short TTL (`10m`, `30m`) before anything permanent.

- Runtime file: `/etc/cfm/detectors.conf`, plus overlays in `/etc/cfm/detectors.d/`
- Reference config: [`../configs/detectors.conf`](../configs/detectors.conf). Its comments document every knob.
- Leniency companion sections: [§6](#6-leniency-companion-sections)

---

## 1) Detector model overview

### Section naming

- `[type]`: one built-in detector (`[ssh_auth]`, `[mysql]`, `[webdetector]`).
- `[type:instance]`: a named instance, used by custom detectors (`[custom:ssh_file]`).
- `[<section>.leniency]`: optional companion with a softer block policy for
  matched countries / ASNs (§6), for exactly that section
  (`[custom:ssh_file.leniency]` for an instance).

An unknown type is logged and skipped (`[detectors] unknown section type: …`).
`[api_abuse]` is a deprecated alias of `cfm_endpoints`.

### Source modes (`MODE`)

- `file`: tail a log file (`LOG_PATH`)
- `journal`: read journald (`JOURNAL_UNIT`, plus `JOURNAL_MATCHES` where supported)
- `docker`: read container logs (`DOCKER_CONTAINER`, optional `DOCKER_ARGS`) where supported
- `auto`: resolve the source automatically.

`ssh_auth`, `dovecot_auth`, `postfix_security` / `postfix_relays` /
`postfix_queues` and `exim_security` / `exim_relays` / `exim_queues` use the
shared resolver (`internal/detectors/srcresolve`). `ftpd`, `modsec` and `mysql`
keep their own older autodetects with different semantics; `proxmox_auth`,
`custom` and `ngm_auth` read only what is configured. More detectors migrate
per `docs/detectors-config-unification.md`.

`modsec` (`resolveModsecLogPath`, `internal/detectors/modsec_register.go`):
`MODE = auto` with `LOG_PATH = auto` (stock) scans the known Apache / nginx
error and audit logs (cPanel, cPanel EA4's `/var/log/apache2/error_log`, EL /
DirectAdmin `/var/log/httpd/error_log`, Debian `/var/log/apache2/error.log`,
nginx) and tails the one with the most ModSecurity denials in its last 2 MiB,
else the first that exists. A concrete `LOG_PATH` that exists is used as
given. In `MODE = auto` a concrete `LOG_PATH` that does NOT exist is logged
and the scan runs instead (the path is kept only if no candidate exists
either). That covers the old stock line `LOG_PATH = /var/log/apache2/error_log`,
which a live `detectors.conf` keeps across upgrades: it is cPanel EA4's real
path, but DirectAdmin, Debian and nginx hosts have no such file, and before
2026-11-18 their `[modsec]` watched nothing. `MODE = file` pins `LOG_PATH`
verbatim. The manager's config signature folds in that resolution, so a log
that appears after the start (Apache installed later) rebuilds the section
onto it. While no candidate has a denial the scan is repeated every 10 minutes,
so the first denials in another log (an audit log) move the section there
once; a pick with denials is then kept, as before. `detectors_srcresolve`
reports the file it would tail; the source probe (`detectors_status`) only
checks that a candidate is readable.

The shared resolver:

- **Explicit values win.** A concrete `DOCKER_CONTAINER`, `JOURNAL_UNIT` or
  `LOG_PATH` (in that precedence) short-circuits auto; postfix
  `JOURNAL_MATCHES` passes through as given. A concrete `MODE` restricts
  resolution to that source kind.
- **Auto order:** journald units with entries → merely-active units → docker
  container discovery by name pattern → known log files. Discovery runs before
  files, so a containerized service beats a stale host log. It never guesses:
  two matching containers resolve to nothing and the log asks for
  `DOCKER_CONTAINER`.
- **Canonical unit names.** An active unit, and an explicit `JOURNAL_UNIT`, is
  resolved to its canonical systemd name: journald indexes only that, so
  `sshd.service` on Debian (an `Alias=` of `ssh.service`) would tail an empty
  stream. The resolution line shows it (`explicit JOURNAL_UNIT sshd.service →
  canonical ssh.service`). `ftpd`, `proxmox_auth` and `custom` use a pinned
  name as given.
- **Nothing confirmed:** the detector tails its historical default
  provisionally (it self-heals when the source appears) and logs `no log
  source confirmed (...); tailing the default provisionally`.
- **Exim has no journal candidates:** it writes its own mainlog, and its unit's
  journal carries only child-process noise. **Postfix journal candidates are
  signature-checked:** recent entries must carry the `postfix/...[pid]:` tag.
- **Mail detectors self-disable** when their MTA is absent (`… detector
  disabled (auto)`), so exim sections go quiet on postfix-only hosts and vice
  versa. Postfix sections probe binary / unit / discovered container / log,
  and stay alive provisionally when the docker CLI exists but no container is
  up yet (the manager re-resolves on a bounded retry). Exim sections probe
  binary / unit (plus the mainlog for `exim_security` / `exim_relays`); exim
  in docker is not probed.
- `postfix_queues` wraps its queue commands in `docker exec` when postfix
  lives only in a discovered container (mailcow).

With `auto` you normally set nothing. Pin explicit keys only for a custom
layout, and then exactly one source per section.

**Preview before trusting it:** `cfm detectors-srcresolve` (alias
`detectors-resolve`), the cfm-admin Detectors page "Source resolution" card,
`GET /api/v1/detectors/source-resolution` and the `detectors_srcresolve` MCP
tool show the dry-run resolution for every section, with the daemon's own
planners and live probes. The CLI also joins daemon coverage
(`/api/v1/detectors/coverage`): a DAEMON column (unit active / stopped /
absent), `<type> (not in config)` rows for a daemon nothing watches, and a
summary count. Check it per node before removing source pins.

### Overlay files (`/etc/cfm/detectors.d/`)

The daemon reads `/etc/cfm/detectors.conf` (the package-owned base) and merges
every `/etc/cfm/detectors.d/*.conf` over it in lexicographic filename order.
Put per-host overrides in overlays, one file per concern (`10-mysql.conf`,
`20-ssh.conf`), so the base stays pristine and upgrades update it in place.
The package ships `detectors.d/` empty and never installs files into it.

- Same section + key: the overlay value **replaces** the earlier one.
- `KEY += value` **appends**: list keys join with `", "`; rule blocks
  (`QUERY_RULES`, `CONN_RULES`, `FAIL_REGEX`, `RULES`, `IGNORE_REGEX`) and
  multi-line values stack line by line. An inline `;`/`#` comment on the
  earlier list value is dropped before joining (the scalar readers cut at the
  first `;`/`#`). With no earlier value, `+=` just sets it.
- A section only in an overlay is added whole.
- Only real, regular `*.conf` files are read. Hidden files, symlinks of any
  kind, directories and special entries are ignored: one stray entry never
  drops the other overlays, and no link is followed. A misnamed file
  (`10-ssh.CONF`, `10-ssh.conf.bak`) is not seen; a typo'd key or section is
  skipped by the lenient parser, as in the base.
- Hot reload watches the base by its mtime (`StampNS`) and the overlay set by
  `LayerSig`, a hash of each overlay's name, mtime and size, so an overlay
  edited, added, removed or renamed reloads, even one installed with an older
  preserved mtime (`cp -p`, `rsync -a`). Neither signal can mask the other.
- An overlay that fails to **read or parse** is a hard error, never applied
  half-merged: a hot reload keeps the running detectors; at start the base
  alone is applied (`overlay read failed on first load: … starting with the
  base config ONLY`). Builtin-only protection is for an unreadable base.

`config_drift` computes `missing_sections` / `missing_keys` against the MERGED
view, while value diffs stay stock-vs-BASE (overlay values are intentional
per-host state, summarized as counts). The cfm-admin config editor edits the
BASE file and shows a notice when overlays exist.

**Per-host tokens are not config.** `CHALLENGE_TOKEN` and `OPENRESTY_TOKEN`
live in `/var/lib/cfm/secrets/` (`challenge_token`, `openresty_token`; root,
`0600`), and that file is the one in use, so the conffile can stay identical
to the packaged one.

- A missing file is created: copied from `detectors.conf` when that has a
  usable token (the **base** `[webdetector]` if it has one, else the merged
  config), otherwise generated. After that `detectors.conf` is not read for it.
- Keep the key lines, set to `placeholder`: an older binary after a rollback
  appends a MISSING line at the end of the file, where it can land in another
  section and loop the daemon through reloads, and an EMPTY line makes its
  regex overwrite the next line. A rollback rotates the token twice if the
  line is `placeholder`; a Debian upgrade that takes the package's
  `detectors.conf` at the prompt rotates it once.
- **To rotate:** set the line to `placeholder`, delete the file, restart.
  **To set a token** (nodes behind one load balancer): write it into the file
  (root, `0600`) and restart.
- A file holding no usable token, a symlink or an unreadable store is never
  overwritten (an empty file is replaced): another token runs, unstored.
  `cfm health` reports a file without a usable token as missing. The store outlives package removal.

### Threshold / window / cooldown semantics

- `EVERY`: poll interval. Many detectors default it to `[global]
  DEFAULT_EVERY` (stock `60s`), else to their own default.
- `WINDOW`: sliding window for the counters.
- threshold keys (`AUTHFAIL_IP`, `DENIED_USER`, `MODSEC_IP`, …): alert when the
  count reaches the threshold (`>=`) inside `WINDOW`.
- `COOLDOWN`: detector-side alert dedupe per key.
- `SAMPLE_LIMIT`: matched lines attached to the alert.

The scalar readers strip an inline `;`/`#` comment but cut at the first one
regardless of quoting. Prefer comments on their own line.

### Block behavior and block cooldown

A detector only emits an alert. Blocking, leniency, the cfm-web report and the
notification are the section sink's job (`internal/detectors/autoblock_sink.go`),
per the section's `BLOCK`:

```ini
BLOCK = no          ; aliases: off, 0, empty
# BLOCK = dryrun    ; alias: alert
# BLOCK = permanent ; alias: perm
# BLOCK = 30m       ; any duration, "d" (days) included: 7d, 1d12h
BLOCK_COOLDOWN = 20m
```

- `no`: alert only, no firewall write and no report.
- `dryrun`: runs the policy and logs "would block" without enforcement.
- `permanent`: non-expiring nft block.
- duration: TTL block in the timed sets. It extends, never shortens: a longer
  or permanent block already on the address is kept (`block_kept=longer`).
- `BLOCK_COOLDOWN` (default `15m`): after a real block, the same section does
  not block the same IP again within it; the alert is still published,
  without a notification.
- **Absent `BLOCK` means `no`**, except `ssh_auth` (`permanent`, cooldown
  `30m`) and `login_bruteforce` (`3d`, cooldown `6h`), which default to the
  stock values (`sectionBlockDefaults`). A present but empty `BLOCK` means no.
  A value the parser cannot read is `no`.
- Per alert, a detector can force a dry run (`Extra["enforcement"]="dryrun"`),
  cap the ban (`core.ExtraMaxBlockTTL`: a permanent becomes that TTL; a capped
  ban does not stamp `BLOCK_COOLDOWN`) or mute the mail (`core.ExtraNotify`;
  the alert log records it as `muted`).
- A ban from a web section (`waf_security`, `webdetector`, `challenge_*`,
  `modsec`, `cfm_endpoints`, `cpanel`, `login_bruteforce`) also goes to the
  edge ban store, which stops a client behind a trusted proxy that never meets
  the nft drop.

#### TTL bans across a restart, an upgrade or a reboot

A TTL block lives only as a timed element of `inet cfm block_v4` /
`block_v6`, or of `block_v6_clients` for the /64 an automatic ban of an IPv6
client takes. `cfm.deny` holds only permanent bans (it has no expiry, so a TTL
ban there would become permanent). A restart's `EnsureBase` keeps the table,
its sets and their elements on both engines (`LiveNFTTTLBansSurviveRestart`).
Nothing on an upgrade may empty the table: the rpm `%post` once ran `cfm
disable` on every upgrade and freed every TTL-banned attacker.

For what still empties it (a reboot, `cfm reset`, `cfm disable`) the daemon
persists TTL host bans, and the IPv6 client /64s of `block_v6_clients`, in
`/var/lib/cfm/ttlbans.json`
(`internal/ttlban`):

- **Saved** from nft every ~2 minutes (the edge ban reconcile's read of the
  block sets, which must cover both or saves nothing) and on SIGTERM / SIGINT /
  SIGHUP. A snapshot replaces the file with what nft holds. Exception: a read
  that lost at least three stored live bans, and more than half of them, is a
  table recreated empty under the daemon (`cfm disable` then any CLI command
  that runs EnsureBase; a `flush ruleset`): those bans stay in the file and
  the log says to restart the daemon to re-apply them. Permanent elements are
  not saved (cfm.deny re-applies them), nor are TTL'd CIDR blocks.
  Two elements with one key keep the longer ban.
- **Restored** after `EnsureBase`, in the background (the first edge ban
  reconcile waits up to 30 seconds for it, and nothing is saved before it
  ends): each ban for its remaining time, through `AddBlockBatch` (a /64
  through `firewall.ExtendBlockNet`), which adds or extends but never shortens
  a ban or makes a permanent one temporary. An
  expired entry is dropped, and so is one covered by an nft allow / ignore
  set, `cfm.allow`, `cfm.ignore` or `[global] IGNORE_IPS` / `IGNORE_NETS`. The
  startup log has one `[ttlban] restore:` line with the counts.
- **Unblocks** in the daemon (`/unblock`, `cfm unblock` through its
  force-unblock, cfm-web pending unblocks) drop the entry at once, and a
  snapshot whose read began earlier cannot put it back. `cfm unblock` also
  edits the file, so an unblock while the daemon is stopped holds too. A new
  unblock path calls `ttlban.ForgetClient` (the address and its client's
  /64; unblocking an IPv6 address frees its /64, `firewall.RemoveClientNet`).
- **An allow** does not remove the block element (nft accepts before it
  drops): the restore skips the entry while the allow is in place, and a ban
  that outlives a `cfm allow --ttl` comes back, as in nft.
- **`cfm flush`** removes the file and leaves a `ttlbans.json.flushed`
  marker: the daemon's next read begun after it is the truth, and a start that
  finds it restores nothing. `cfm reset` and `cfm disable` keep the file. To
  drop every TTL ban for good, use `cfm flush`, or delete the file with the
  daemon stopped.

Limits: a crash loses the bans added since the last snapshot. A restore batch
that fails three times leaves the bans in the file for the next start. The
time left is capped at what the ban had when saved (the file is rewritten at
every stop and at least every 10 minutes); a clock *ahead* at boot expires
bans early. An unblock and a fresh ban of the same address both landing
during the restore lose the fresh ban; the detector bans again on the next hit.

Because upgrades keep the table, a release that changes `NFT_INPUT_PRIORITY`'s
default applies only after `cfm reset` (EnsureBase keeps an existing input
chain and logs the mismatch).

> **Duration units.** Every duration in `detectors.conf` (`BLOCK`, `EVERY`,
> `WINDOW`, `COOLDOWN`, `TIMEOUT`, mysql `QUERY_RULES` max-time, …) uses Go's
> syntax (`s`, `m`, `h`) plus a lowercase **`d`** (`1d == 24h`), composable
> (`1d12h`) and fractional (`1.5d`). There is no `w` or `y`. A value the
> parser cannot read (`7days`, `7D`) silently falls back to the built-in
> default, and for `BLOCK` to no blocking.

---

## 2) Built-in detector catalog

Defaults are the stock `configs/detectors.conf` values. A section that omits a
key runs the code default, which can differ (notably `BLOCK`: see §1).

| Detector key | What it detects | Key knobs | Stock defaults |
|---|---|---|---|
| `cfm_endpoints` | CFM login / token / API abuse, in three stages; runs even with no section | `STAGE1/2/3_THRESHOLD`, `STAGE2_CHALLENGE_TTL`, `DRY_RUN`, `ALLOW_IPS/NETS`, `PATH_EXCEPTIONS` | `EVERY=2s`, `WINDOW=2m`, stages 10/12/16, `BLOCK=15m` |
| `waf_security` | sources the in-path WAF keeps blocking (edge-`block` hits only), per reason family | one key per family (`SQLI`, `RCE`, `CVE`, …; `1` = armed), `RULE_<id>`, `DRY_RUN`, `ALLOW_IPS/NETS/UA_CONTAINS`, `PATH_EXCEPTIONS` | `EVERY=20s`, `WINDOW=30m`, `BLOCK=6h`; GR/CY `15m`, lenient list. See `docs/waf-autoblock-design.md` |
| `login_bruteforce` | web login brute force from the web detector's login column: one site, or a spray over sites | `SITE_FAILS`, `SITES`, `WINDOW`, `DRY_RUN`, `ALLOW_IPS/NETS/ASNS` | `WINDOW=1h`, `SITE_FAILS=4`, `SITES=3`, `BLOCK=3d`, armed; GR/CY `10m`, not reported. Runs even with no section |
| `challenge_solver_farm` | distributed challenge-solving farms, by solver spread per vhost and by fingerprint | `MIN_SUBNETS`, `MIN_SOLVES`, `WINDOW`, `ACTION`, fingerprint tracks, allowlists | `EVERY=30s`, `WINDOW=180s`, `MIN_SUBNETS=30`, `MIN_SOLVES=15`, **alert-only** |
| `challenge_cookie_discard` | clients that re-solve the challenge while holding valid clearance | `MIN_SOLVES`, `WINDOW`, `MAX_TRACKED_IPS`, allowlists, `BLOCK` | `EVERY=30s`, `WINDOW=10m`, `MIN_SOLVES=8`, **alert-only unless `BLOCK` is set** |
| `webdetector` | L7 abuse behaviour, challenge integration | `MODE`, path files, scoring and challenge knobs | `EVERY=5s`, `WINDOW=120s`, `BLOCK=12h`; GR/CY `15m`, not reported |
| `ssh_auth` | SSH auth failures | `MODE`, `AUTHFAIL_IP`, `AUTHFAIL_USER`, `DDOS_IP` | `MODE=auto`, `WINDOW=15m`, thresholds `8`, `BLOCK=permanent`, `BLOCK_COOLDOWN=30m` (also without those keys) |
| `dovecot_auth` | Dovecot auth abuse, and logins refused as `user_disabled` | `MODE`, `AUTHFAIL_IP`, `AUTHFAIL_USER`, `USER_DISABLED_*` | `MODE=auto`, `WINDOW=15m`, thresholds `10`, `BLOCK=permanent`; GR/CY `15m`, lenient list; user_disabled: 2 in 24h, a 24h ban, no mail |
| `ftpd` | FTP auth failures | `MODE`, `AUTHFAIL_IP`, `AUTHFAIL_USER` | `MODE=auto`, `WINDOW=15m`, thresholds `8`, `BLOCK=permanent` |
| `proxmox_auth` | Proxmox VE auth failures (pvedaemon) | `MODE` (`journal` / `file`), `JOURNAL_UNIT`, `LOG_PATH`, `AUTHFAIL_IP/USER` | no stock section; code: `MODE=journal`, `pvedaemon.service`, thresholds 20 / 10 |
| `cpanel` | cPanel login failures, root logins | `AUTHFAIL_IP`, `AUTHFAIL_USER`, `ROOT_IP` | `WINDOW=10m`, `5`/`5`/`3`, `BLOCK=1h` |
| `ngm_auth` | NGM control-panel login abuse (`/var/log/ngm/auth.log`) | `AUTHFAIL_IP`, `AUTHFAIL_USER`, `ADMIN_IP`, `TOKEN_IP` | `WINDOW=10m`, `25`/`15`/`5`/`10`, `BLOCK=dryrun`. See `docs/ngm-auth-detector.md` |
| `mysql` | MySQL/MariaDB auth failures / scans | `LOG_PATH`, `DENIED_IP`, `DENIED_USER`, `ROOT_IP`, `SCAN_IP` | `LOG_PATH=auto`, `WINDOW=10m`, `BLOCK=permanent` |
| `mysql_governor` | processlist pressure, long queries, connection caps | `MODE`, `POLL_EVERY`, `QUERY_RULES`, `CONN_RULES`, kill limits | `MODE=monitor` (set `enforce` per host), `POLL_EVERY=5s`. See `docs/mysql-governor.md` |
| `exim_security` | Exim auth / reject patterns | `LOG_PATH` (auto), `REJECT_LOG_PATH`, per-rule thresholds | `WINDOW=30m`, `BLOCK=12h`; GR/CY `10m`, lenient list |
| `exim_relays` | Exim relay / throughput abuse | `LOG_PATH` (auto), `LOCAL_USER_MAX`, `AUTH_*`, `UNAUTH_IP_MAX` | `WINDOW=15m`, `BLOCK=dryrun` |
| `exim_queues` | Exim queue growth, frozen messages | `QUEUE_TOTAL_MAX`, `QUEUE_FROZEN_MAX` | `EVERY=60s`, alert-only; publishes the queue count to `cfm health` / the dashboard (`internal/mailq`) |
| `postfix_security` | Postfix auth / reject / RBL / TLS anomalies | `MODE` (auto), thresholds | `MODE=auto`, `WINDOW=30m`, `BLOCK=permanent` |
| `postfix_relays` | Postfix relay-style abuse | `MODE` (auto), thresholds like exim relays | `MODE=auto`, `WINDOW=15m`, no `BLOCK` (alert-only) |
| `postfix_queues` | Postfix queue saturation | `TOTAL_CMD`, `LIST_CMD` (auto), thresholds | `EVERY=60s`, alert-only; publishes the queue count like `exim_queues` |
| `modsec` | ModSecurity denial bursts per IP | `MODE`, `LOG_PATH`, `MODSEC_IP` | `MODE=auto`, `LOG_PATH=auto` (see Source modes), `WINDOW=15m`, `MODSEC_IP=20`, `BLOCK=permanent` |
| `health` | host health: CPU / RAM / disk / temperature / connection spikes, RAID / SMART / ZFS / ECC, backups, `/tmp` | `%` thresholds, spike multipliers, `*_ALERT`, `BACKUP_*`, `TMP_PCT`, `TMP_CLEAN_OLDER` | `EVERY=20s`, alert-only; `/tmp` at `TMP_PCT=85`% alerts and deletes regular files older than `TMP_CLEAN_OLDER=12h` (`TMP_PCT=0` turns it off). Backups: `docs/backup-check.md` |
| `custom` | your own regex rules (§3) | `FAIL_REGEX`, `MATCH_TARGET`, thresholds | none shipped |

The outbound abuse sentinel is not a detector section: `OUTBOUND_*` in
`cfm.conf` configures it (`docs/outbound-sentinel.md`).

### `cfm_endpoints` — protecting CFM's own API

Built in and on even with no `[cfm_endpoints]` section; a section only
overrides the built-in values, and `ENABLED = 0` is the explicit opt-out.
`[api_abuse]` is a deprecated alias. It counts apiserver auth and probe
anomalies per source IP and escalates in three stages.

- **Defaults:** 10 direct invalid-token events in 2 minutes → stage 1
  (observe), 12 → stage 2 (a challenge for `STAGE2_CHALLENGE_TTL`, 10m), 16 →
  stage 3 (a `BLOCK` candidate, 15m). A stale automation token reaches those
  numbers quickly. `DRY_RUN = 1` forces stage 3 to dryrun.
- **Before arming:** find uptime monitors and trusted automation in the
  control-plane traffic and add only their stable addresses to `[global]
  IGNORE_IPS` / `IGNORE_NETS` or the section's `ALLOW_IPS` / `ALLOW_NETS`
  (avoid broad shared-cloud ranges); allowed sources are dropped before
  counting. Run the first week with `BLOCK = dryrun` (covers stages 2 and 3)
  or `BLOCK = no`.
- `ALLOW_UA_CONTAINS` is attacker-controlled. The old shipped
  `uptime,healthcheck,prometheus` list is removed on load unless
  `ALLOW_UA_CONTAINS_EXPLICIT = 1` acknowledges it. `PATH_EXCEPTIONS` only
  mutes generic unauthorized-burst noise on an exact path; direct auth
  failures, fuzz and method probes still count.
- Stage 2 needs the webdetector bridge: with no readable `detectors.conf`,
  stage 1 and the stage-3 policy work, but a challenge is recorded as failed.
- The edge replaces control-plane `X-Forwarded-For` with one normalized
  client address. If another reverse proxy sits in front, add only that proxy
  to the edge's real-IP trust; the multi-hop chain is not kept.
- An API rate-limit trip (`docs/security/control-plane.md` §6) is a `429`,
  never fed into this detector.

### `dovecot_auth` — logins refused as `user_disabled`

On a cPanel node with Imunify360, `pam_imunify` refuses a mail login from an
address on Imunify's global RBL before any password is checked. Imunify logs
`[IM360_RBL] The IP … has been locked` to `/var/log/messages`, and dovecot
logs `Login aborted: … (user disabled, 1 attempts in 2 secs)
(user_disabled)`, a line with none of the password-failure markers. So no
detector banned these sources and none reached the fleet list, though on an
Imunify node they are all RBL locks. On a node without Imunify,
`user_disabled` is also a suspended mailbox whose owner's phone retries. The
detector keeps them apart from password failures:

- **Counting:** per IP only (the mailbox is the victim), `USER_DISABLED_IP`
  (2) in `USER_DISABLED_WINDOW` (24h): Imunify's locks repeat over hours.
- **Alert:** `DOVECOT/USER_DISABLED`.
- **Ban:** at most `USER_DISABLED_BLOCK_TTL` (24h), whatever the section's
  `BLOCK` says (`core.ExtraMaxBlockTTL`), and reported to cfm-web, so the
  fleet gets the address. GR/CY addresses take the section leniency.
- **Mail:** none per ban (`core.ExtraNotify`) unless `USER_DISABLED_NOTIFY =
  1`: hundreds a day on an Imunify node. The ban, the report and the detector
  log still happen; the alert log records each as `muted`, whatever the
  section's `BLOCK`.
- **Cooldown:** a capped ban does not stamp `BLOCK_COOLDOWN`, so the same
  address's password failures still get their permanent ban right after.
- **Client-chosen text:** the verdict and the source address are read only
  from the server's text, so a username such as `x(user_disabled)@…` or
  `rip=203.0.113.50,…` cannot turn a password failure into a capped ban or
  name another address. On a login service's line the reason must appear
  before `user=<` and the address is the last `rip=`. An auth-worker /
  passwd-file / pam line (only with `auth_verbose`) never counts as
  user_disabled; its address is the IP of the last `(USER,IP[,<session>])`
  tuple, else a single `rhost=`, else none.
- **Off switch:** `USER_DISABLED_IP = 0`.

### `challenge_solver_farm` — why it exists

Bots that solve the challenge *correctly* defeat every per-IP threshold by
construction: they solve about once per address from a residential-proxy pool
of tens of thousands of `/24`s. A per-IP counter only ever sees a first and
only request, so this detector keys on the **vhost**. A finding names the
track(s) that fired:

- `subnet_spread`: distinct client subnets (`PREFIX_V4` `/24`, `PREFIX_V6`
  `/48`) solving one vhost within `WINDOW` reach `MIN_SUBNETS`. `MIN_SOLVES`
  guards a quiet vhost and only bites when set above `MIN_SUBNETS`.
- `fp_concentration` (`FP_TRACK`): a vhost's solvers collapse onto one TLS
  fingerprint across `MIN_FP_SUBNETS` (8) subnets AND `MIN_FP_COUNTRIES` (6)
  countries within `WINDOW`: the low-and-slow farm the subnet count misses.
  Country is the false-positive guard: a legitimate shared fingerprint
  (corporate fleet, carrier CGNAT) is geographically clustered.
- `cross_host` (`XH_TRACK`): one fingerprint that is at least
  `MIN_XH_HOST_SHARE_PCT` (50%) of each vhost's fingerprinted solves, over
  `MIN_XH_HOSTS` (4) vhosts, `MIN_XH_COUNTRIES` (12) countries and
  `MIN_XH_SUBNETS` (30) subnets node-wide within `XH_WINDOW` (30m). Share is
  the primary guard; solves per IP is deliberately not a gate.

The fingerprint is a group-by key, never a matched value, so a new tool with a
new fingerprint trips the same shape. `ALLOW_FPS` exempts a known shared
fingerprint from both fingerprint tracks.

**Calibration.** Thresholds are measured the way the code measures: a
**sliding** window sampled every `EVERY`, never fixed buckets (their maximum
understates the sliding one, overstating the headroom). The shipped `WINDOW =
180s`, `MIN_SUBNETS = 30`, `MIN_SOLVES = 15` (`solverfarm.DefaultWindow` and
friends; `TestSolverFarmDefaultsAgree` pins the template and reference config
to them) come from a fleet re-measure: at 15 subnets real Greek shop audiences
(paid-ad traffic, 15–25 `/24` per 180s) read as farms, while fingerprint-less
findings on farm-hit vhosts reached 33–77. 30 sits between them with thin
margins, so a single-country farm below it is missed; a fingerprinted farm
over enough countries is caught by the fingerprint tracks whatever
`MIN_SUBNETS` is. The 180s window is for slow farms (60s missed one). A
conffile the operator edited keeps its old `60s` / `40` / `40` lines on
upgrade (the package leaves a `.dpkg-dist` / `.rpmnew`); change them by hand.
A vhost with a genuinely global mobile audience could spread wider:
`MIN_SUBNETS` is a knob, and `ALLOW_HOSTS` / `ALLOW_UA_CONTAINS` / `ALLOW_NETS`
/ `ALLOW_IPS` exempt known-good sources.

`EVERY` is clamped to `WINDOW` at load (a longer interval would prune part of
the stream unexamined). A section without `EVERY` inherits `[global]
DEFAULT_EVERY`.

**Design decisions:**

- **Not keyed on User-Agent.** The UA is attacker-controlled; randomising one
  header would defeat it. The UA breakdown rides on the alert as evidence.
- **The evidence cap cannot suppress detection.** `MAX_TRACKED_PER_HOST`
  bounds the sample buffer only; the subnet and IP sets the thresholds read
  are separate, so a cheap flood from one subnet cannot bury a farm.
  Truncation is stated on the alert.
- **Alert-only, structurally.** At ~1 solve per IP a ban cannot work (the
  address never returns), and the pool is residential, so the ban lands on a
  real customer. Two `Extra` keys enforce it:
  - `ip_scope=host`: the sink must not resolve a source address. Its fallback
    scans the samples, which quote User-Agents, for anything IP-shaped: a
    client could name its own "source" and get the alert dropped by the
    global ignore list (`Chrome/118.0.0.0` is IP-shaped enough by accident).
  - `enforcement=observe`: stops the sink short of any block if `BLOCK` is set.

  **Leave `BLOCK` unset on this section** and use `ACTION`. `BLOCK` would not
  block, but it moves the alert onto a path that logs without notifying, so
  you would quietly stop being alerted. The daemon logs a warning if it finds one.

#### `ACTION`

| value | effect |
|---|---|
| `observe` | **default**, also when absent: notification + `cfm.detector.log` |
| `logonly` | log record only, no notification: a vhost already triaged and accepted as farmed |
| `deny`, `block` | **reserved**: refused at load with a logged reason, fall back to `observe` |

`block` does not fit this traffic: the address is gone before the alert
fires, and the ban lands on a residential visitor. `deny` has no safe
subject: a vhost-wide 403 takes the site down, and the narrow form, a
UA-cluster traffic rule, is evaded by randomising one header. The actuator
that fits (raising the vhost's PoW difficulty while flagged) needs per-vhost
difficulty and a faster browser solver first; see
`docs/roadmaps/challenge-engine.md`.

`COOLDOWN` (30m) bounds how often the alert is emitted per vhost.
`NOTIFY_COOLDOWN` (6h) bounds the notifications, on every track: between the
two the alert is logged without a mail. A farm runs for hours.

#### Where the finding shows up

| Surface | What you get |
|---|---|
| Email (and Slack if routed) | the full alert: solves, distinct IPs and subnets, solves per IP, the UA breakdown, the impossible-UA count |
| `cfm.detector.log` | the same, greppable as `Challenge/SolverFarm` |
| `detection_history` `solver_farm` row | the finding, with `payload.humanity` (below) |
| WebUI → WebDetector | a blue **farm** badge in *WebTop* → Flags and in *Suspicious + challenged vhosts* → Status |
| `cfm web live` (TUI) | `F` in the leading slot of the `SUP` column |
| `/var/lib/cfm/notify.log.jsonl` | one JSON record per notification |
| `cfm.challenges.log` | per solve: `ua=`, `solve_ms=`, `ua_impossible=` |
| WebUI → WebDetector → Forensics | `challenge_solved` rows with the UA, a **Solve** latency column, the impossible-UA pill and filter |

Notification is on by default: the section matches the `[detector "*"]`
catch-all in `notify.conf` (email), and the alert's `warn` severity passes the
default gate. Slack needs an explicit `[detector "challenge_solver_farm"]`
block (a commented example is in `configs/notify.conf`), and `[channel
"slack"]` ships disabled. Because the detector never blocks, the notification
*is* the product.

#### The `farm` badge

The badge is **not** driven by the alert, which `COOLDOWN` throttles while the
farm continues. The detector marks the vhost on *every* over-threshold
evaluation, with a TTL of `max(3 × EVERY, WINDOW)`, so the badge means "farmed
right now". Expiry is the only way a mark goes away (a missed callback cannot
badge a vhost forever), and the marks are dropped when the detectors manager
stops (a reload leaves no stale badge). `solver_farm` rides on the
`top-short`, `suspicious`, `long-top`, `challenge/vhosts` and
`challenge/vhost/status` responses (the last for scoped tokens). It is `pill
info` (blue), not `warn` / `danger`, and independent of the score: a farm
solves correctly, so a farmed vhost need not look suspicious.

Alerts also carry `impossible_ua`, the solves with a self-contradictory
User-Agent (below): corroboration only, never part of a threshold.

#### Humanity context

A fingerprint is a population, not one client: a farm and a real audience can
share one coarse TLS bucket. So every finding carries, for the solves of its
cluster, the ChallengeV2 Rung-1 **hs buckets** (`none` = the solve line's
`hs=-`, no payload; `unscored` = the rung was off, never counted as 0; `0`,
`1-59`, `60-99`, `100+`), the **top 5 exact `tells`** and **top 5 countries**
(by count, then key), `n` (solves covered) and `truncated` (an evidence cap
dropped a solve in the window: the counts are of a sample).

The detector is fed the solve events and the withheld solves (an unsolicited
solve that failed Rung 1 and got no cookie, once per address and host per
hour). A Rung-1 reject under an arm produces neither, so an armed
fingerprint's summary shows who got through, not who tried; the rejected side
is `detection_history type=challenge_v2_reject`.

The cluster is on the finding's vhost: for `cross_host` (alone or combined),
the cross-host fingerprint's solves there over `XH_WINDOW` (the row's
`solves` / `distinct_*` are node-wide, so `n` need not match); for
`fp_concentration`, the per-host fingerprint's solves over `WINDOW`; for
`subnet_spread` alone, every solve on the vhost over `WINDOW`. The country is
the one resolved at verify, else looked up once per address for a firing
cluster.

It appears as a `[challenge] humanity of passed solves …` alert line (after
the UA lines, so the Alerts page's 5 sample lines usually cut it), as
`Finding.Humanity`, and as `payload.humanity` on the history row. That key is
admin-only, stripped for scoped (cPanel) callers like `ips`
(`docs/endpoint_scope_inventory.md`). It is **evidence only**: no track,
threshold or mark reads it. `challenge_cookie_discard` does not carry it.

### `login_bruteforce` — why it exists

Nothing else banned a WordPress brute forcer: the addresses the shadow
`login_spray` signal flagged were almost never blocked by anything. The edge
marks every login POST (the login column, `docs/webdetector-signals-v2.md`
§3), the web detector reads the origin's answer as a failure or a success,
and the login ledger publishes every failure. This detector bans per client
over `WINDOW` (1h) on either rule (`0` turns a rule off):

- **One site:** `SITE_FAILS` (4) failed logins on one site, a registrable
  domain (`www.`, `staging.` and the bare name are one site).
- **Spray:** failed logins on `SITES` (3) different sites, any number on each.
  A proxy pool sprays one or two tries per site per address, which no per-site
  count sees.

A lostpassword / register form shown again weighs a third of a failure: on
the one-site rule, and for a site to count on the spray rule (one failed
login, or three forms).

**Client and ban subject.** A client is an IPv4 address or an IPv6 /64 (one
subscriber, who can rotate inside it). The finding names the /64's address
with the most failures in the window, and the ban takes that client's whole
/64 (every automatic IPv6 ban does: `docs/edge-ipv6.md` "IPv6 /64
grouping"), so an attacker rotating inside its /64 is out after one round. In
a /64 with several failing
addresses, a finding is a dry run when its worst address has a single failure
(a VPS provider's shared /64), or, on the one-site rule, no more than half of
`SITE_FAILS` there (two colleagues who mistyped twice each). A second such
alert within `WINDOW` bans the worst address: an attacker alternating two
addresses does that every round, colleagues do not.

**Never counted or banned:**

- A failure on a site where the client failed and succeeded at least as often
  (the ledger's per-site record: a site's own tool). A success alone is not
  ownership. The record is the ledger's fixed 24h window, in memory: a
  restart, a `detectors.conf` save or a tailed log's rotation empties it, and
  a tool that fails first after that counts until its successes catch up.
  Successes are per client and site, not per account (a known gap on a site
  with open registration).
- A 2FA password step (`mfa`: the edge's `li=2`, a real login cookie set and
  cleared in one answer). A cleared cookie alone is a failure:
  `wp-login.php?reauth=1` clears it on every failed login.
- A password reset that went through (200, its `wp-resetpass-` cookie
  cleared). A login hidden behind `?action=lostpassword` (the body's
  `action=login` wins in PHP) that fails with 200 and a reset / register form
  shown again cannot be told apart at the edge, so both are the
  third-of-a-failure above: a customer who forgot the password and tries a
  few addresses is not banned, a bot hiding its logins there needs three
  times the tries. On a site whose plugin answers a failed login with a
  redirect, such a hidden login reads `na` (a known gap).
- An answer WordPress did not write: a failure needs `wordpress_test_cookie`,
  which wp-login.php sets on every request before any action or plugin runs.
  A server-level captcha or bot page, a suspended-account page or a site
  broken before wp-login.php ran is "?".
- A protected post's password (`?action=postpass`, its `wp-postpass_` cookie set).
- The failures just before a success: a success takes back up to 3 of the same
  address's latest failures on that site within 15 minutes (Two Factor 0.8+
  sends no cookie on the password step, so its second-factor form and a
  mistyped code read as failures). A failure counts only once it is 2 minutes
  old, so that success arrives first: five client sites opened in parallel
  tabs, all on Two Factor, are not a spray.
- Bypass clients (crawlers, CDN prefixes), `[global] IGNORE_IPS`, private,
  loopback, link-local and CGNAT addresses, `ALLOW_IPS` / `ALLOW_NETS`.
- Cloudflare's own proxy ranges (`trusted_proxies.conf`; the edge sees one
  only when a Worker's subrequest names itself). That exempts every Worker: a
  brute force from Workers is a known gap, since banning one bans them all.
- `ALLOW_ASNS` (the default even for a written section that omits it):
  reverse proxies and WAF CDNs CFM does not trust to name the client (Sucuri,
  Imperva, Fastly, Akamai, StackPath, Bunny). Behind one, every visitor reads
  as the proxy's address, and a 3-day fleet ban would take every site behind
  it down. Cloudflare's ASN is not listed: WARP and the Workers' egress share
  it, and an attacker can use both. Apple Private Relay egress shares Fastly's
  and Akamai's (a known gap).

**Leniency and geo.** `[login_bruteforce.leniency]` gives a 10-minute ban,
reported nowhere (customers who lock themselves out use unblock.myip.gr). It
matches the country (GR, CY) OR the Greek and Cypriot eyeball ASNs (OTE,
Vodafone, Wind, Nova, Cyta, GRNET), for a range the geo database places
abroad, OR Cloudflare's (13335): a WARP egress address is shared by many
users. An address with no geo record (no GeoLite / IPLocate database,
`[global] ENRICH = 0`) only logs "would block" (`geo=unknown`): the leniency is
decided on the country. After an alert only later failures count toward the
next one, so a lenient client that keeps failing is banned again.

**Known gaps** where a legitimate client can still be banned: a CDN or reverse
proxy on a cloud's ASN (CloudFront, Azure Front Door, Google's load balancer,
Gcore, CDN77: an ASN exemption would exempt everyone renting a server there,
so it needs a generated range list like the bypass list); a login monitor
whose stored password went stale, once the owner record empties; a
lostpassword request the site cannot mail (200, a third); a captcha failing a
real user (reCAPTCHA v3 on a VPN, Turnstile blocked by an extension) or
Wordfence's verify-by-email, which answer 200 with the right password; SASE
gateways (Zscaler, Netskope) that put Greek staff on foreign addresses.
Conversely, a site whose answers carry no `wordpress_test_cookie` (a renamed
`TEST_COOKIE`) never counts a failure.

**Armed by default** (`DRY_RUN = 0`, also when omitted) since 2026-11-10,
after a dry-run burn-in that set 4 and 3: botnets sent 4 tries per address,
or tried 3–4 sites, to stay under the first thresholds (5 and 5), and the
lower ones caught markedly more addresses, none Greek or Cypriot. A `DRY_RUN`
value that is neither 0 nor 1 keeps the dry run and logs it. With `DRY_RUN =
1` each would-be ban is an alert with `mode=dryrun` (with `host`, `rule`,
`site`, `leniency`, and `geo=unknown` / `ipv6_ambiguous` when they apply), at
most once per client per `WINDOW`; nothing is banned or reported.

Armed, the ban is the section sink's: `BLOCK = 3d`, reported to cfm-web, and
recorded in the edge ban store for a client behind Cloudflare
(`[webdetector] EDGE_BAN_MODE = enforce`, the default, 403s it there). With
`log` such a client keeps failing, and `BLOCK_COOLDOWN = 6h` keeps it from
being mailed and reported again every few minutes.

**Built in.** A node whose `detectors.conf` has no `[login_bruteforce]` runs
the stock section and its leniency (`applyBuiltinLoginBruteforce`). A written
section is taken as written; one without `BLOCK` still bans for 3 days; one
without a `.leniency`, or with one that has no `MATCH_COUNTRY` / `MATCH_ASN`,
still gets the GR/CY one (cfm-admin's "Add" writes the section without it,
and "Add leniency companion" writes it empty). Turn the leniency off with
`ENABLED = 0` in the `.leniency`. `[webdetector] LOGIN_SIGNALS = 0` stops the
login events at the source (the detector then sees nothing). The
config-drift report skips the type. A node with no readable `detectors.conf` at start-up runs only the built-in
control-plane protection, not this.

Only WordPress logins carry an outcome today. A Joomla
(`/administrator/index.php`), Drupal or Laravel login joins when
`authOutcome` learns to read its answer.

Each ban is a notifier event. With hundreds a day per node, route `[detector
"login_bruteforce"]` in `notify.conf` (e.g. `notify = 0`) if the mail is too
much. That silences the mail only; every alert still lands in
`cfm.detector.log` (`Type: WEB/LOGIN_BRUTEFORCE, ip …`, the `Blocked:` line,
up to 10 sample failures with their host) and in the alert log
(`/var/lib/cfm/alerts.db`, `docs/alerts.md`), `muted` included: MCP `alerts
kind=WEB/LOGIN_BRUTEFORCE` for the rows, `alerts_summary
kind=WEB/LOGIN_BRUTEFORCE group_by=country,asn` (or `mode`, `delivery`,
`hour`) with `node="all"` for the fleet picture.

### `challenge_cookie_discard` — why it exists

The mirror image of `challenge_solver_farm`, and its blind spot.

Solving mints a signed clearance cookie (`cfm_clearance` on web,
`cfm_clearance_p<port>` on panel ports) valid for `CHALLENGE_COOKIE_LIFE`
(45m in the stock config). A browser stores it and does not solve again until
it expires. An address that re-solves minutes later **never stored the
cookie**: a pipeline with no cookie jar, driving a headless browser per
request and paying the challenge every time. The solver-farm detector keys on
a vhost because a farm burns a fresh address per solve; this one keys on the
**address**, for a few addresses solving dozens of times each. Neither sees
the other's traffic.

**Calibration** (a sliding 10-minute window over a day of production solves):
nearly every address solved once; the plausibly legitimate repeaters (an
iPhone, an iPad, a webmail NAT with several devices) topped out at **4**, and
the abusive population started at 6. `MIN_SOLVES` defaults to **8**, a 2×
margin: a user who opens several tabs is challenged in each before any cookie
is set (a small burst), while the real target sustains 30+ solves over minutes.

- **Not keyed on User-Agent** (attacker-controlled). The UA, vhost and URI
  breakdowns ride on the alert as evidence only.
- **Blocking is coherent here.** The subject is one real address abusing the
  challenge now, so the alert sets `Extra["ip"]` authoritatively (the sink
  never scans the samples, which quote User-Agents and URIs). It still **ships
  alert-only**: watch it, then set `BLOCK = 6h` when you trust it. A soft TTL,
  not `permanent`, because the addresses seen were residential proxy exits
  that may belong to a real visitor later. `BLOCK = dryrun` is the
  intermediate step. This section has no `DRY_RUN` key: one is silently
  ignored while `BLOCK` bans for real.
- **Neither cap can hide the behaviour.** `MAX_TRACKED_PER_IP` bounds the
  evidence buffer only (dropped records still count, and truncation is
  stated). `MAX_TRACKED_IPS` bounds the address map (the key is
  client-controlled); when full, only *new* addresses are refused, so a flood
  of one-shot solvers can delay a new finding but cannot erase one already
  accumulating.

Greppable as `Challenge/CookieDiscard` in `cfm.detector.log`; notification
follows the `[detector "*"]` catch-all.

### User-Agent plausibility (`internal/uaplausible`)

Reports whether a UA contradicts *itself*: a combination no shipping browser
emits. Examples from real traffic: an iPhone carrying Blink's
`AppleWebKit/537.36` (iOS must use the system WebKit, which reports `60x`), a
bare `Chrome/` token on iOS (Chrome on iOS is `CriOS`), a Firefox carrying
the Blink WebKit token, a Chrome UA missing `KHTML, like Gecko`.

Three rules are about the **shape of a Chrome version string**, because the
observed farm *generates* UAs: each Chrome major carried 110–170 distinct
build numbers, drawn roughly uniformly. A table of real release builds would
catch it, but writing one from memory is what this package forbids, and it
would need maintaining every release. These rules state properties of
Chrome's own version scheme across majors 15 → 150 and need no table:

| rule | what it says | evidence |
|---|---|---|
| `chrome_impossible_patch` | 4th component ≥ 1000 | the highest real patch seen is 280 (outliers to 819); the generator draws 1000–1999 |
| `chrome_nonzero_minor` | 2nd component ≠ 0 | essentially every real Chrome string has minor 0, across a decade |
| `chrome_reduced_build_with_patch` | build 0 **and** patch ≠ 0 | a reduced UA freezes the last three together (`145.0.0.0`) |

They flagged most distinct UA strings but about 2% of requests: one
generator minting a fresh string per request dominates the vocabulary, not
the traffic. **Chromium derivatives** (Edge, Opera, Vivaldi,
Brave, Samsung, Yandex, Electron, WebView, …) carry the upstream Chromium
version in their `Chrome/` token, because their own numbers there would break
UA sniffing; none was flagged. Forks with no product token of their own pass
as Chrome.

**Corroboration, never a threshold.** The verdict reaches a log tag, a history
field, a counted column on two detectors' alerts and +30 on the shadow
`challenge_score`; nothing blocks, throttles or challenges on it. A wrong rule
is fixed by holding that rule, not the package. One exception:
`legacy_edge_on_modern_chrome` (an EdgeHTML `Edge/12`–`18` token beside
Chrome/80+) is also read by the ChallengeV2 scorer as the tell `ua_lie` (in
the device-claim group); even there it never fails a solve alone (see
`docs/traffic-classifier.md`, "ua_lie").

Checked on every challenge solve, it is surfaced as `ua_impossible=<reasons>`
in `cfm.challenges.log`, `payload.ua_impossible` on the `challenge_solved`
history event, the `impossible_ua` count on solver-farm alerts, and an
`impossible` pill and **impossible UA only** filter in the forensics table.
Each is written only for an *impossible* verdict: absence means coherent.

- **Coherence, not freshness.** An old but consistent UA is a real person on
  an old browser and is never flagged.
- **No staleness scoring.** Calibrating "current" by volume lets the attacker
  define normal: on the source capture one Chrome major dominated *because
  the farm dominated the traffic*.
- `Verdict.Family` reports the **engine**, so every Chromium derivative reads
  as `Chrome`. `HeadlessChrome/` is deliberately not matched: a headless UA is
  honest, not impossible.

Validate a new rule against a real UA corpus first: an exact-match
`(KHTML, like Gecko)` draft flagged legitimate crawlers (Amazonbot, YouBot,
GeedoShopProductFinder) that append their identity inside the same
parentheses, caught only because it was measured before shipping.

---

## 3) Custom detectors

`[custom:<name>]` sections match your own regex rules against a log file or a
journald unit and count failures per captured IP and / or user.

### Required syntax and keys

```ini
[custom:your_name]
ENABLED = 1
MODE = file                 ; file (default) | journal
LOG_PATH = /var/log/auth.log
; JOURNAL_UNIT = sshd.service
; JOURNAL_MATCHES = _SYSTEMD_UNIT=sshd.service
EVERY = 2s
WINDOW = 10m
COOLDOWN = 20m
SAMPLE_LIMIT = 10

AUTHFAIL_IP = 12
AUTHFAIL_USER = 8

MATCH_TARGET = both         ; ip | user | both
FAIL_REGEX =
    ... one regex per line, with named captures ...

; optional pre-filter: a line matching any of these is skipped
IGNORE_REGEX =
    ... one regex per line ...

BLOCK = dryrun
BLOCK_COOLDOWN = 20m
```

- `MODE` is `file` or `journal`; any other value (`docker` included) tails
  `LOG_PATH`. Custom sections have no docker source and no auto resolution.
- `FAIL_REGEX` (alias `RULES`) is required: one Go regex per line, at most 128.
  A rule that does not compile, or lacks the captures `MATCH_TARGET` needs,
  fails the section at load with a per-rule diagnostic. An `IGNORE_REGEX` line
  that does not compile is logged and skipped.
- Defaults when omitted: `EVERY` = `[global] DEFAULT_EVERY` (else 2s),
  `WINDOW` = `[global] DEFAULT_WINDOW` (else 10m), `COOLDOWN` = `[global]
  DEFAULT_COOLDOWN` (else 20m), `AUTHFAIL_IP` 20, `AUTHFAIL_USER` 10,
  `MATCH_TARGET` both, `BLOCK` no.
- Lines longer than 16 KiB are skipped; one pass reads at most 3000 lines.
- Alerts are `CUSTOM/AUTHFAIL`. The section takes a `[custom:<name>.leniency]`.

### Capture groups and normalization

- `(?P<ip>...)`: the source IP, parsed (brackets stripped); a capture that is
  not an IP counts as no match.
- `(?P<user>...)`: the account, trimmed and lower-cased.

`MATCH_TARGET` decides which are required and counted:

- `ip`: requires `ip`; counts per IP against `AUTHFAIL_IP`.
- `user`: requires `user`; counts per user against `AUTHFAIL_USER`.
- `both` (default, and any unknown value): every rule needs both captures; a
  line counts only when both captured, on both counters.

Each matching rule counts, so a line two rules match counts twice. A per-user
alert has no IP key: to block, the sink takes the source address from the
sample lines.

### Example — two rules and an ignore list

```ini
[custom:mail_auth_mix]
ENABLED = 1
MODE = file
LOG_PATH = /var/log/mail.log
EVERY = 3s
WINDOW = 15m
COOLDOWN = 20m
SAMPLE_LIMIT = 12
AUTHFAIL_IP = 15
AUTHFAIL_USER = 10
MATCH_TARGET = both
IGNORE_REGEX =
    cfm-healthcheck
    trusted-monitor
FAIL_REGEX =
    authentication failure; .*rhost=(?P<ip>\S+).*user=(?P<user>\S+)
    SASL (?:LOGIN|PLAIN) authentication failed.*rip=(?P<ip>\S+).*user=(?P<user>\S+)
BLOCK = dryrun
BLOCK_COOLDOWN = 20m
```

For a journal source, set `MODE = journal`, `JOURNAL_UNIT` and optionally
`JOURNAL_MATCHES` (space-separated `FIELD=value`) instead of `LOG_PATH`. The
unit name is used as given: on Debian the sshd unit is `ssh.service`.

---

## 4) Troubleshooting

### Enabled, but no alerts

- The start-up log lists `[detectors] sections: enabled=[…] disabled=[…]`,
  one `[detectors] start <section> (…)` line per running detector, and
  `[detectors] failed to init <section>: …` for one that failed.
- The source exists and receives new lines (`cfm detectors-srcresolve`), and
  `EVERY` / `WINDOW` suit your test cadence. Keep `BLOCK = dryrun` while
  validating with a known-bad line.

### Source not found

- `MODE=file`: `LOG_PATH` exists and is readable. `MODE=journal`: the unit
  name (`sshd.service` vs `ssh.service`). `MODE=docker`: the container name,
  and that the daemon can read `docker logs`.
- `MODE=auto`: the start-up resolution line (`source=… (reason)`, or `no log
  source confirmed (...)`) lists what was tried.

### Regex compiles but no matches

Check escaping in the ini value, the named captures `MATCH_TARGET` needs, and
an over-broad `IGNORE_REGEX`. Start with a broad pattern, then tighten.

### False positives

Raise thresholds or widen `WINDOW`; use `BLOCK = dryrun` or a short TTL while
tuning; use the section's allow keys, `[global] IGNORE_IPS` / `IGNORE_NETS`
and leniency companions. For web traffic, review path / UA lists.

#### One site's tool trips the malpath list: a host-scoped path exclude

The webdetector's two malpath checks read `/etc/cfm/webdetector_malpaths.txt`
(substring, case-insensitive, query cut): `CHALLENGE_PATHS` challenges an IP
on its first hit (v2 tier, and it revokes the clearance cookie), and `MALPATH`
bans an IP after `20` hits in `WINDOW`. When a legitimate tool on ONE site
hits a listed name (elFinder thumbnails, Duplicator's `dup-installer/`
during a migration), carve that path out on that site instead of editing the
list for every site:

```
cfm webtop challenge exclude add /images/.tmb/ --type path --scope example.gr
cfm webtop challenge exclude list
cfm webtop challenge exclude remove /images/.tmb/ --type path --scope example.gr
```

- A request on a scope host under the path is not counted by either check
  (decided when the line is counted; the per-IP counters span hosts). The
  same path on another site, and every other path on this one, still count.
- Only a plain path is carved out: a request path with a `.`/`..` segment,
  `//`, a backslash or a percent-encoded dot, slash or backslash still counts
  (`/images/.tmb/../../.env` sits under the prefix, but the origin serves
  `/.env`).
- Matching is a path-segment prefix (`/images/.tmb/` covers everything under
  it; `/admin` covers `/admin` and `/admin/x`, not `/administrator`), or a
  glob anchored at both ends (`/images/*/.tmb/*`; `*` stays within one
  segment), case-insensitive. The first segment must be a literal name:
  `/`, `/*`, `/*.php`, `/[!/]*` are refused (that is a host exclude).
- `--scope` names the site exactly and also covers its `www.` alias
  (`--scope example.gr` covers `www.example.gr`, not `shop.example.gr`). An
  admin may scope to `*.example.gr` (the subdomains; a tenant does not see
  such an entry); `*`, `*.*`, `*.gr`, `*.com.gr` and other globs are refused,
  and so is a value glob that does not compile.
- `--scope` is required (repeat it for several sites): a path exclude without
  it would exempt the path everywhere, so it is refused, and one an older
  version stored stays inert (`list` and cfm-admin show it as such; remove it
  without `--scope`).
- A cPanel tenant's scoped token may add, list and remove these on its own
  vhosts: an add is pinned to its vhosts (or the subset it names), and a
  remove takes its own hosts out of every entry on that path, so an entry
  shared with another site keeps covering that site.
  `docs/endpoint_scope_inventory.md` has the rules. In cfm-admin
  (WebDetector → WAF engine → Dynamic excludes) the challenge card offers
  `path` to admins and tenants, with a required scope field (a tenant picks
  among its own sites, prefilled with the first in alphabetical order) and a
  Scope column; the WAF card's `path` stays admin-only, and so does the
  challenge card's for a token that holds only wildcard vhosts.
- Each skipped hit is logged to the challenges log at most once a minute per
  (check, exclude): `[challenge][malpath] action=path_exclude_skip`.
- This is only the malpath checks. The WAF has its own path + rule excludes
  (`cfm webtop waf exclude add … --type path --rule <id> --scope <host>`), and
  a host exclude (`challenge exclude add <host>`) keeps its meaning.

### Outbound alerts need DNS corroboration

When the outbound sentinel warns on per-uid destination churn or burst rates,
confirm the uid / gid and process from the alert first. Pivot to
[`admin-notes/ad-hoc-dns-forensics.md`](admin-notes/ad-hoc-dns-forensics.md)
only when baseline telemetry is not enough, and keep captures short,
identity-scoped and temporary.

---

## 5) Cross-links

- Reference config and inline presets: [`../configs/detectors.conf`](../configs/detectors.conf)
- Config layering and source resolution design: `docs/detectors-config-unification.md`
- WAF autoblock: `docs/waf-autoblock-design.md` · NGM panel logins: `docs/ngm-auth-detector.md`
- Alert log: `docs/alerts.md` · Outbound sentinel: `docs/outbound-sentinel.md`
- Leniency companion sections: [§6](#6-leniency-companion-sections)

---

## 6) Leniency companion sections

A `[<section>.leniency]` block gives a section a **softer block policy** for
sources that match a country or ASN, and can keep those blocks off the shared
fleet blocklist. Origin is never trusted to skip enforcement: a match only
*softens* the action (a short ban instead of a permanent one); see
`webdetector-refactor.md` §4a for why GeoIP / ASN must stay additive-only.

**Lookup.** Only the exact companion of the running section is read:
`[ssh_auth]` reads `[ssh_auth.leniency]`, `[custom:x]` reads
`[custom:x.leniency]`. There is no type-level or global `[leniency]`
fallback, and one companion per section (named multi-leniency is not built).
`login_bruteforce` is the one section given a built-in companion (§2).

**Where it runs.** The section sink checks it after enrichment, before the
cooldown and block switch. A match replaces the whole policy (`BLOCK` and
`BLOCK_COOLDOWN`) and the report settings. It never applies when the section's
own `BLOCK` is `no` (the sink returns earlier), when the alert has no IP, when
enrichment is off (`[global] ENRICH = 0`) or has no record for the address,
or when the companion has no `MATCH_COUNTRY` / `MATCH_ASN`. A per-alert dry
run and a per-alert ban cap (§1) still apply after it.

```ini
[exim_security.leniency]
MATCH_COUNTRY  = "GR,CY"           ; ISO codes (recommended); OR logic
; MATCH_ASN   = "AS6799,AS6866"    ; with or without "AS"; OR with country
BLOCK          = "1h"              ; no | dryrun | permanent | <duration>
BLOCK_COOLDOWN = "30m"
SEND_TO_API       = YES            ; YES (default) | NO: report the block at all
SEND_TO_BLOCKLIST = lenient        ; lenient | blacklist (default): the
                                   ; destination list when SEND_TO_API = YES.
                                   ; "lenient" records the block centrally
                                   ; (support / unblock lookups) but it is
                                   ; NEVER served to the fleet.
```

- `MATCH_COUNTRY` tokens split on commas and spaces. ISO codes compare to the
  record's ISO code; an English name works only as one word or from the
  built-in name table, so prefer ISO codes.
- Keys default like a section's: an omitted `BLOCK` means **no block**, and
  `BLOCK_COOLDOWN` is 15m. Write both.
- `BLOCK = no`: the alert is logged, with no firewall action and no report.
- `ENABLED = 0` in a companion is read only for `login_bruteforce`; elsewhere
  remove the `MATCH_*` keys or the section.
- Hot reload picks up edits like any other section. Companions are not listed
  in the `sections: enabled=[…]` log line; a parsed one logs `[detectors]
  <section>: leniency enabled countries=[…] asns=[…] block=… cooldown=…
  send_to_api=…`.

When a source matches, the log reads:

```
[leniency][exim_security] ip=94.68.43.7 matched (country=GR) → block=1h0m0s cooldown=30m0s send_to_api=true send_to_blocklist=lenient
```

and the alert carries `leniency=yes leniency_reason=country=GR` (plus
`send_to_api=no` / `lenient` when the report was skipped or went to the
lenient list). The intended result: a GR/CY address failing auth is banned
briefly, locally or on the lenient list only; a foreign or datacenter address
gets the section's normal ban and goes to the fleet blocklist.
