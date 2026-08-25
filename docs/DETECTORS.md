# Detectors Guide

This guide explains how to configure CFM detectors safely in production, starting from `dryrun` and then moving to active blocking.

- Main runtime file: `/etc/cfm/detectors.conf`
- Reference template/examples: [`../configs/detectors.conf`](../configs/detectors.conf)
- Leniency companion sections: [§6](#6-leniency-companion-sections)
- Web UI / detectors settings page: [`cfm-admin-webtop.md`](cfm-admin-webtop.md)

---

## 1) Detector model overview

### Section naming

CFM parses detector sections using these patterns:

- `[type]`  
  Single built-in detector section (for example `[ssh_auth]`, `[mysql]`, `[webdetector]`).
- `[type:instance]`  
  Named instance pattern, used for custom detectors (for example `[custom:ssh_file]`).
- `[type.leniency]` (and `[type:instance.leniency]` where relevant)  
  Optional companion section for softer policy on matched Country/ASN cohorts.

### Source modes (`MODE`)

Depending on detector type, sources can be:

- `file`: tail a log file (`LOG_PATH`)
- `journal`: read systemd journald (`JOURNAL_UNIT` / `JOURNAL_MATCHES`)
- `docker`: read container logs (`DOCKER_CONTAINER`, optional `DOCKER_ARGS`) where supported
- `auto`: resolve the source automatically. `ssh_auth`, `dovecot_auth`,
  `postfix_security`/`postfix_relays`/`postfix_queues` and
  `exim_security`/`exim_relays`/`exim_queues` use the shared resolver
  (`internal/detectors/srcresolve`; more detectors migrate per
  `docs/detectors-config-unification.md` — `ftpd`/`modsec`/`mysql` still
  carry their own older autodetects with different semantics). The shared
  resolver tries, in order: journald units with entries → merely-active units
  (resolved to their canonical name, so a Debian `sshd.service` alias picks
  `ssh.service`) → docker container discovery by name pattern (exactly one
  match, never a guess — and checked before files, so a containerized service
  beats a stale host log) → known log-file locations. **Explicit values
  always win**: a concrete `MODE`, `JOURNAL_UNIT`, `LOG_PATH`, or
  `DOCKER_CONTAINER` short-circuits auto and is used verbatim (precedence:
  container → unit → path; postfix `JOURNAL_MATCHES` also passes through
  verbatim). If nothing is confirmed, the detector tails its historical
  default source provisionally (self-heals when it appears) and logs the
  resolution trace (`no log source confirmed (...)`). Two service-specific
  rules (design doc §3a): **exim has no journal candidates at all** — exim
  writes its own mainlog and never syslogs it, so its unit's journal carries
  only stray child-process noise; and **postfix journal candidates are
  signature-checked** (recent entries must carry the `postfix/...[pid]:` tag,
  guarding against journald's cgroup attribution). The **mail detectors
  self-disable** ("detector disabled (auto)" in the log, section skipped)
  when their MTA is nowhere to be found, so exim sections go quiet on
  postfix-only hosts and vice versa without hand-set `ENABLED=0`. What each
  checks before disabling: postfix sections probe binary/unit/discovered
  container/log (and stay alive provisionally when the docker CLI exists but
  no container was found — the container may not be up yet at boot; the manager
  re-resolves automatically on a bounded retry once it appears); exim sections
  probe binary/unit (plus
  the mainlog for `exim_security`/`exim_relays`) — exim-in-docker is not
  probed. `postfix_queues` also auto-wraps its queue commands in
  `docker exec` when postfix lives only in a discovered container (mailcow).

With `auto` available you normally set nothing; pin explicit keys only for
custom layouts. If a detector supports multiple source backends and you do pin
one, choose exactly one clear path in each section (comment the others out).

**Preview before trusting it:** `cfm detectors-srcresolve` (alias
`detectors-resolve`), the cfm-admin Detectors page "Source resolution" card,
`GET /api/v1/detectors/source-resolution`, and the `detectors_srcresolve` MCP
tool all show the dry-run resolution for every section on the host — same
planners the daemon runs, probes live, nothing changes. Check it per node
before removing hand-set source pins from a config. The CLI additionally
joins **daemon coverage** (`/api/v1/detectors/coverage`): a DAEMON column per
row (unit active/stopped/absent), extra `<type> (not in config)` rows for GAP
(a daemon runs here but nothing watches it) and dormant verdicts, and a
summary count — one command answering "does the daemon exist, did I detect
it, am I following it".

**Explicit `JOURNAL_UNIT` pins are alias-normalized on the
srcresolve-adopted detectors** (`ssh_auth`, `dovecot_auth`,
`postfix_security`/`postfix_relays`): a pinned unit is resolved to its
canonical systemd name (`systemctl show -p Id`) before tailing — journald
indexes only the canonical Id, so a config carrying `JOURNAL_UNIT =
sshd.service` dropped onto a Debian host (where that is an `Alias=` of
`ssh.service`) now tails the real journal instead of an empty stream. Same
service, corrected name; the resolution line shows the rewrite (`explicit
JOURNAL_UNIT sshd.service → canonical ssh.service`). Detectors still on
their own tailing (`ftpd`, `proxmox_auth`, `custom`) use the pinned name
verbatim until they migrate to the shared resolver.

### Overlay files (`/etc/cfm/detectors.d/`)

The daemon reads `/etc/cfm/detectors.conf` (the base, package-owned conffile)
and then merges every `/etc/cfm/detectors.d/*.conf` over it in lexicographic
filename order (`10-…` before `20-…`). Put deliberate per-host overrides in
overlays — one file per concern works well (`10-mysql.conf`, `20-ssh.conf`) —
so the base file stays pristine and package upgrades update it in place (no
more `.rpmnew`/`.dpkg-dist`). Merge semantics:

- same section + key → the overlay value **replaces** the base value
- `KEY += value` → **appends** to the earlier value (list keys join with
  `", "`, multiline rule blocks stack line-by-line) — extend common lists
  like `IGNORE_NETS` or `CHALLENGE_VHOST_IGNORE` without forking them; an
  inline `;`/`#` comment on the earlier value is dropped before joining (the
  scalar readers cut at the first `;`/`#`, so appending after it would
  silently discard the addition)
- a section only in an overlay is added whole (named instances, host extras)
- hot reload watches overlays like the base: edits, and also files being
  added, removed, or renamed (the reload signature hashes the overlay set,
  not just mtimes — an overlay installed with `cp -p`/`rsync -a` still
  triggers)
- only **real, regular `*.conf` files** are read. Hidden files (`.#…` editor
  locks, `.foo.conf`), **symlinks of any kind**, directories and other special
  entries are ignored — one stray entry never drops the other overlays, and the
  daemon never follows a link out to an arbitrary target (put a real file here,
  not a link). Note the corollary: a misnamed file (`10-ssh.CONF`,
  `10-ssh.conf.bak`, `10-ssh.txt`) is simply not seen, and a typo'd key/section
  inside a valid file is skipped by the lenient parser exactly as in the base
  file — verify what actually applied with `cfm detectors-srcresolve`.

The package ships `detectors.d/` **empty** and never installs files into it.
A regular `*.conf` overlay that fails to **read or parse** is a hard read
error — never silently applied half-merged: on a hot reload the running
detectors are kept (and the error logged); at daemon start the base config
alone is applied (base-only start, loudly logged) rather than degrading to
builtin-only protection (which stays reserved for the base file itself being
unreadable).

**Not overridable via overlay:** the auto-managed tokens `CHALLENGE_TOKEN` and
`OPENRESTY_TOKEN` are **base-owned** — the daemon generates/persists them into
the base `detectors.conf` and pins the runtime to the base value, ignoring an
overlay override (an overlay value would otherwise be re-healed into the base
every reload, an endless rotate loop, and would desync the `cfm_bridge_token.lua`
the daemon writes). Set these in the base file if you set them at all; PR6 moves
their generation out of the conffile entirely. Every other `[webdetector]` knob
(`OPENRESTY_SOCK`, `LOG_PATH`, thresholds, …) is overlay-tunable as normal. Verify the
merged result with `cfm detectors-srcresolve` and the cfm-admin "Source
resolution" card. `config_drift` computes `missing_sections`/`missing_keys`
against the MERGED view — a feature you adopt via an overlay stops being
reported missing — while value diffs stay stock-vs-BASE (overlay values are
intentional per-host state, summarized as counts). Note: the cfm-admin config
editor currently edits the BASE file and shows a notice when overlays exist;
editing overlays from the UI is planned.

### Threshold / window / cooldown semantics

Most detectors use this model:

- `EVERY`: poll interval (how often detector scans)
- `WINDOW`: rolling time window used for counters
- threshold keys (for example `AUTHFAIL_IP`, `DENIED_USER`, `MODSEC_IP`): alert when count is `>= threshold` inside `WINDOW`
- `COOLDOWN`: detector-side alert dedupe interval per key (helps reduce noisy repeats)
- `SAMPLE_LIMIT`: max matched lines attached to alert context

### Block behavior and block cooldown

Autoblock is configured per detector section:

```ini
BLOCK = off        ; aliases: no, 0
# BLOCK = dryrun
# BLOCK = permanent
# BLOCK = 30m      ; Go-style duration, plus a "d" (days) unit
# BLOCK = 7d       ; days extension: 7d == 168h; composites like 1d12h work too
BLOCK_COOLDOWN = 20m
```

- `off`/`no`/`0`: alert only, never write firewall block set
- `dryrun`: logs “would block …” without enforcement
- `permanent`: non-expiring nft block
- duration (for example `10m`, `2h`, `24h`, `7d`): TTL block, auto-expired by timed sets
- `BLOCK_COOLDOWN`: minimum time before same section can block same IP again

> **Duration units.** All duration values in `detectors.conf` (`BLOCK`, `EVERY`,
> `WINDOW`, `COOLDOWN`, `TIMEOUT`, mysql `QUERY_RULES` max-time, …) use Go's
> duration syntax — `s` (seconds), `m` (minutes), `h` (hours) — extended by CFM
> with a lowercase **`d` (days)** unit, where `1d == 24h`. Units compose
> (`1d12h`, `2d30m`) and days may be fractional (`1.5d == 36h`). There is no
> `w` (weeks) or `y` unit — use `168h`/`14d` etc. A value the parser cannot
> read (e.g. `7days`, uppercase `7D`) silently falls back to the built-in
> default, so keep to lowercase `d`.

> **Production-safe rollout:** begin with `BLOCK=dryrun`, tune, then move to short TTL (for example `10m` or `30m`) before permanent blocks.

---

## 2) Built-in detector catalog

Typical defaults below are representative from the shipped template and should be tuned per host profile.

| Detector key | What it detects | Key knobs | Typical defaults |
|---|---|---|---|
| `cfm_endpoints` | CFM login/token/API abuse stages; built in and active even without the config file | `STAGE1/2/3_THRESHOLD`, `STAGE2_CHALLENGE_TTL`, `BLOCK`, IP/network allowlists | `EVERY=2s`, `WINDOW=2m`, `BLOCK=15m` |
| `ssh_auth` | SSH auth failures / brute-force | `MODE`, `AUTHFAIL_IP`, `AUTHFAIL_USER`, `DDOS_IP`, `BLOCK` | `MODE=auto`, `WINDOW=15m`, `BLOCK=permanent` |
| `dovecot_auth` | Dovecot auth abuse | `MODE`, `AUTHFAIL_IP`, `AUTHFAIL_USER`, `BLOCK` | `MODE=auto`, `WINDOW=15m`, `BLOCK=permanent` |
| `ftpd` | FTP auth failures | `MODE`, `AUTHFAIL_IP`, `AUTHFAIL_USER`, `BLOCK` | `MODE=auto`, `WINDOW=15m`, `BLOCK=permanent` |
| `cpanel` | cPanel auth/root login anomalies | `AUTHFAIL_IP`, `AUTHFAIL_USER`, `ROOT_IP`, `BLOCK` | `WINDOW=10m`, `BLOCK=1h` |
| `mysql` | MySQL/MariaDB auth failures / scans | `LOG_PATH`, `DENIED_IP`, `DENIED_USER`, `ROOT_IP`, `SCAN_IP`, `BLOCK` | `WINDOW=10m`, `LOG_PATH=auto`, `BLOCK=permanent` |
| `mysql_governor` | Processlist pressure, long query, conn cap enforcement | `MODE`, `POLL_EVERY`, `QUERY_RULES`, `CONN_RULES`, kill limits | `MODE=enforce`, `POLL_EVERY=5s` |
| `exim_security` | Exim security/auth/reject patterns | `LOG_PATH` (auto-resolved; self-disables without exim), `REJECT_LOG_PATH`, per-rule thresholds, `BLOCK` | `WINDOW=30m`, `BLOCK=12h` |
| `exim_relays` | Exim relay/throughput abuse | `LOG_PATH` (auto-resolved; self-disables without exim), `LOCAL_USER_MAX`, `AUTH_*`, `UNAUTH_IP_MAX`, `BLOCK` | `WINDOW=15m`, `BLOCK=dryrun` |
| `exim_queues` | Exim queue growth/frozen queue pressure | `QUEUE_TOTAL_MAX`, `QUEUE_FROZEN_MAX`, `COOLDOWN` | `EVERY=60s`, alerting focus; also publishes the queue count to the health snapshot (`cfm health` / dashboard Mail queue tile) via `internal/mailq` |
| `postfix_security` | Postfix auth/reject/rbl/tls anomalies | `MODE` (source auto-resolved; self-disables without postfix) or explicit Docker/Journal source keys, thresholds, `BLOCK` | `MODE=auto`, `WINDOW=30m`, `BLOCK=permanent` |
| `postfix_relays` | Postfix relay-style abuse counters | `MODE` (source auto-resolved; self-disables without postfix), threshold family similar to Exim relays, `BLOCK` | `MODE=auto`, `WINDOW=15m` |
| `postfix_queues` | Postfix queue saturation | `TOTAL_CMD`, `LIST_CMD` (auto: host mailq, or `docker exec` into a discovered postfix container; self-disables without postfix), queue thresholds | `EVERY=60s`, alerting focus; also publishes the queue count to the health snapshot (`cfm health` / dashboard Mail queue tile) via `internal/mailq` |
| `modsec` | ModSecurity denial bursts per IP | `LOG_PATH`, `MODSEC_IP`, `BLOCK` | `WINDOW=15m`, `BLOCK=permanent` |
| `outbound` | outbound abuse sentinel (per-uid SMTP/scan/HTTP bursts) | `OUTBOUND_*` thresholds, allow users/groups, dedupe | `WINDOW=60s`, alerting focus |
| `health` | host health anomalies (CPU/RAM/disk/temp/net spikes) | `% thresholds`, spike multipliers, watch lists | `EVERY=20s`, mostly alerting |
| `webdetector` | L7 abuse behavior / challenge integration | `MODE`, path files, scoring knobs, challenge knobs, `BLOCK` | `EVERY=5s`, `WINDOW=120s`, `BLOCK=2h` |
| `challenge_solver_farm` | distributed challenge-solving botnets, by solver spread per vhost | `MIN_SUBNETS`, `MIN_SOLVES`, `WINDOW`, `COOLDOWN`, `PREFIX_V4/V6`, allowlists | `EVERY=30s`, `WINDOW=60s`, `MIN_SUBNETS=40`, **alert-only** |
| `challenge_cookie_discard` | clients that re-solve the challenge while still holding valid clearance | `MIN_SOLVES`, `WINDOW`, `COOLDOWN`, `MAX_TRACKED_IPS`, allowlists, `BLOCK` | `EVERY=30s`, `WINDOW=10m`, `MIN_SOLVES=8`, **alert-only unless `BLOCK` is set** |

### `challenge_solver_farm` — why it exists

Bots that solve the challenge *correctly* defeat every per-IP threshold by
construction: they solve once per address from a large residential-proxy pool.
Measured on a production edge over 23h, one farm produced 101,880 solves on a
single vhost from 95,281 distinct IPs (**1.07 solves per IP**) spread across
77,792 distinct `/24`s. A per-IP counter only ever sees a first-and-only request.

The detector therefore keys on the **vhost**, and counts the number of distinct
client subnets that solve it within `WINDOW`. Calibration was re-derived by
replaying that capture through the detector at its original timestamps, so the
figures describe what the code measures — a **sliding** window sampled every
`EVERY`, not disjoint one-minute buckets. The distinction matters: the maximum
over sliding windows is always ≥ the maximum over fixed buckets, so bucket-derived
numbers overstate the headroom.

| | farm vhost | every other vhost |
|---|---|---|
| distinct `/24` per window | median 73, p01 49, max 122 | **max 27** |
| evaluations flagged at `MIN_SUBNETS=40` | 2758 / 2761 | **0 / 3212** |

Two deliberate design choices:

- **Not keyed on User-Agent.** The UA is attacker-controlled; keying detection on
  it would be defeated by randomising a header. The separation above holds
  UA-agnostically. The UA breakdown rides on the alert as attribution evidence.
- **The evidence cap cannot suppress detection.** `MAX_TRACKED_PER_HOST` bounds
  the sample buffer only; the subnet and IP sets the threshold reads are tracked
  separately. Otherwise a cheap flood from a single subnet could fill the buffer
  and bury a farm's spread behind it. Truncation is always stated on the alert.
- **Alert-only, structurally.** At ~1 solve per IP a per-IP ban cannot work — the
  address never returns — and the pool is residential, so banning it risks a real
  customer. What to *do* about a flagged vhost (raise its PoW difficulty,
  rate-limit challenge issuance, block a cluster) is a separate, deliberate
  decision. Two `Extra` keys carry that, doing different jobs:
  - `ip_scope=host` — the finding is about a vhost, so the sink must not resolve
    a source address for it. Its resolver otherwise falls back to scanning the
    alert's samples for anything IP-shaped, and those samples quote the observed
    User-Agents; a client could then name its own "source" address, have it
    matched by the global ignore list, and get the alert dropped before any
    notification. An ordinary `Chrome/118.0.0.0` is IP-shaped enough to cause the
    same mis-attribution by accident.
  - `enforcement=observe` — stops the sink short of any block if a `BLOCK` policy
    is configured on the section.

  **Leave `BLOCK` unset on this section** — use `ACTION` instead. `BLOCK` would
  not block, but it *would* move the alert onto a path that logs without
  notifying, so you would quietly stop being alerted. The daemon logs a warning
  if it finds one.

#### `ACTION`

| value | effect |
|---|---|
| `observe` | **default**, and what you get when the key is absent: notification + `cfm.detector.log` |
| `logonly` | log record only, no notification — for a vhost already triaged and accepted as farmed |
| `deny`, `block` | **reserved**: recognised, refused at load with a logged reason, falls back to `observe` |

`deny` and `block` are defined but not implemented, deliberately. `block` does
not work on this traffic shape — at 1.07 solves per address the address is gone
before the alert fires, and the pool is residential, so the ban lands on a real
visitor. `deny` has no safe subject: a vhost-wide 403 takes the customer's site
down, and the narrow form is a UA-cluster traffic rule that a farm evades by
randomising one header. The actuator that fits — raising the vhost's PoW
difficulty while flagged — needs per-vhost difficulty and a faster browser
solver first; see `docs/roadmaps/challenge-engine.md`.

#### Where the finding shows up

| Surface | What you get |
|---|---|
| Email (and Slack if routed) | The full alert: solves, distinct IPs, distinct subnets, solves-per-IP, the UA breakdown and the impossible-UA share |
| `cfm.detector.log` | Same content, greppable as `Challenge/SolverFarm` |
| WebUI → WebDetector | A blue **farm** badge in *WebTop* → Flags and in *Suspicious + challenged vhosts* → Status |
| `cfm web live` (TUI) | `F` in the leading slot of the `SUP` column |
| `/var/lib/cfm/notify.log.jsonl` | One JSON record per notification |
| `cfm.challenges.log` | Per solve: `ua=`, `solve_ms=`, `ua_impossible=` |
| WebUI → WebDetector → Forensics | `challenge_solved` rows with the UA, a **Solve** latency column, and the impossible-UA pill/filter |

Notification is on by default: the section matches the `[detector "*"]` catch-all
in `notify.conf`, which routes to email, and the alert's `warn` severity passes
the (unset) default severity gate. Slack needs an explicit `[detector
"challenge_solver_farm"]` block — there is a commented example in
`configs/notify.conf` — and the `[channel "slack"]` itself ships disabled.

Because the detector never blocks, the notification *is* the product. That is
why a `BLOCK` value, which silences it, is worth warning about.

#### The `farm` badge

The badge is **not** driven by the alert. `COOLDOWN` rate-limits alerts to one
per 30 minutes because a farm runs for hours, so a badge fed by alerts would
blink off while the attack continued. Instead the detector marks the vhost on
*every* over-threshold evaluation — before the cooldown is consulted — and the
mark carries a TTL of `max(3 × EVERY, WINDOW)`. So the badge means "farmed right
now" and clears on its own within one TTL of the farm stopping.

There is deliberately no un-mark path: expiry is the only way a mark goes away,
so a missed callback cannot leave a vhost badged forever. `solver_farm` rides on
the `top-short`, `suspicious`, `long-top`, `challenge/vhosts` and
`challenge/vhost/status` responses (the last so scoped tokens, which reach the
list only through it, get the badge too). The marks are dropped when the
detectors manager stops, so a reload that disables or retunes the detector
cannot leave stale badges behind.

The badge is styled `pill info` (blue), not `warn`/`danger`: those already mean
"scored suspicious" and "challenge is on", and this detector never enforces
anything. Note it is orthogonal to the score beside it — a farm solves the
challenge *correctly*, so a farmed vhost need not look suspicious at all.

Note the calibration is one server over one day. A very large vhost with a
genuinely global mobile audience could legitimately spread wider; `MIN_SUBNETS`
is a knob and `ALLOW_HOSTS` / `ALLOW_UA_CONTAINS` / `ALLOW_NETS` / `ALLOW_IPS`
exempt known-good sources.

`EVERY` is clamped to `WINDOW` at load — a longer evaluation interval would prune
part of the stream away before it was ever examined, and a section that omits
`EVERY` inherits `[global] DEFAULT_EVERY`, which ships at 60s.

Alerts also carry `impossible_ua` — how many solves in the window submitted a
self-contradictory User-Agent (see below). It is corroboration for the operator
reading the alert, never part of the threshold: a farm can send a well-formed UA
whenever it chooses.

### `challenge_cookie_discard` — why it exists

The mirror image of `challenge_solver_farm`, and its exact blind spot.

Solving mints a signed clearance cookie (`cfm_clearance` on web, `cfm_clearance_p<port>` on panel ports) valid for `CHALLENGE_COOKIE_LIFE`
(45m by default). A browser stores it and does not solve again until it expires.
An address that re-solves minutes later is saying something very specific: **it
never stored the cookie**. That is not aggressive crawling — it is a request
pipeline with no cookie jar, driving a headless browser per request. The
challenge is working perfectly and the client is paying it every single time.

`challenge_solver_farm` keys on a vhost because a farm burns a fresh address per
solve (~1.07 solves/IP), so no per-IP counter can see it. This one keys on the
**address**, for the population that does the opposite: a few addresses solving
dozens of times each. Neither detector sees the other's traffic.

Calibration, from the same 23h capture (111,537 solves, 97,556 distinct
addresses) replayed through a **sliding** 10-minute window:

| max solves by one address per 10m window | addresses |
|---|---|
| 1 (never re-solved) | 97,182 — **99.6%** |
| 3 or more | 248, of which **244** carried one identical desktop Chrome UA |
| exactly 5 | **0** |
| worst offender | **138** (1,121 solves across the day, one UA, two vhosts) |

The four remaining repeaters are the plausibly-legitimate ones and they top out
at **4**: an iPhone and an iPad on small vhosts, one datacenter client, and a
webmail address sending three different User-Agents — a NAT or VPN exit with
several real devices behind it. Legitimate traffic stops at 4, the abusive
population resumes at 6, so the gap in the distribution sits at 5.

`MIN_SOLVES` defaults to **8** — a 2× margin over the busiest legitimate
repeater, still flagging 219 of the 248. The margin is deliberate rather than
tight: a user who opens several tabs at once is challenged in each of them
before any cookie is set, which is a small instantaneous burst, while this
detector's real target sustains 30+ solves over minutes.

Design choices, and how they differ from `challenge_solver_farm`:

- **Not keyed on User-Agent**, for the same reason: it is attacker-controlled.
  The UA, vhost and URI breakdowns ride on the alert as evidence only.
- **Blocking is coherent here.** The subject is one real address abusing the
  challenge right now, so the alert is an ordinary per-IP finding and sets
  `Extra["ip"]` authoritatively — the sink never has to guess (its fallback
  scans samples for anything IP-shaped, and these samples quote User-Agents and
  URIs). It still **ships alert-only**: leave `BLOCK` unset to watch it first,
  then `BLOCK = "6h"` in `[challenge_cookie_discard]` when you trust it. A soft
  TTL rather than `permanent` is right because every address observed was a
  residential proxy exit that may belong to a real visitor later. The
  intermediate step is `BLOCK = "dryrun"`, which runs the whole blocking path and
  reports what it *would* have banned without touching nftables — note there is
  no generic `DRY_RUN` key in this framework, so setting one here would be
  silently ignored while `BLOCK` kept banning for real.
- **Neither cap can hide the behaviour.** `MAX_TRACKED_PER_IP` bounds the
  evidence buffer only — records it drops are still counted toward the solve
  total, and truncation is stated on the alert. `MAX_TRACKED_IPS` bounds the
  address map (the key is client-controlled, so it must be bounded); when it is
  reached, only *new* addresses are refused, so a flood of one-shot solvers can
  delay a new finding but cannot erase one already accumulating.

Greppable as `Challenge/CookieDiscard` in `cfm.detector.log`; notification
follows the same `[detector "*"]` catch-all as every other section.

### User-Agent plausibility (`internal/uaplausible`)

Reports whether a UA contradicts *itself* — a combination no shipping browser
emits. Examples, all present in real traffic: an iPhone carrying Blink's
`AppleWebKit/537.36` (iOS is required to use the system WebKit, which reports
`60x`), a bare `Chrome/` token on iOS (Chrome on iOS is `CriOS`), a Firefox
carrying the Blink WebKit token, a Chrome UA missing `KHTML, like Gecko`.

Three of the rules are about the **shape of a Chrome version string**, and they
exist because the observed farm does not reuse one forged UA — it *generates*
them. In the capture, Chrome majors 39–60 carry 110–170 distinct build numbers
each, drawn roughly uniformly from `810..9996`, while every other major has at
most 8 and they sit tightly on the real release build: 3,128 of 4,151 distinct
Chrome version strings from a single generator, using only four device templates
(`SM-G900P Build/LRX21T`, `Nexus 5 Build/MRA58N`, `Pixel 2 Build/OPD3.170816.012`,
`iPhone OS 11_0`).

The tempting rule — "major 43 must have build 2357" — is a lookup table of Chrome
release builds. Writing one from memory is exactly what this package's doc comment
forbids, and it would need maintaining for every future release. These three need
no table; each states a property of Chrome's own version scheme that holds across
the whole corpus, majors 15 → 150:

| rule | what it says | evidence |
|---|---|---|
| `chrome_impossible_patch` | 4th component ≥ 1000 | highest non-generated patch in the capture is **280**, with outliers to 819; the generator draws 1000–1999 |
| `chrome_nonzero_minor` | 2nd component ≠ 0 | 4,149 of 4,151 Chrome strings have minor 0, a decade of releases |
| `chrome_reduced_build_with_patch` | build 0 **and** patch ≠ 0 | a reduced UA freezes the last three together (`145.0.0.0`); all 70 distinct `build==0` strings are that clean form bar one |

Together with the existing rules this flags **64.5% of the distinct UA strings**
but only **2.22% of the requests** — and that gap *is* the finding: one generator
minting a fresh string per request dominates the vocabulary while barely moving
the traffic share.

**Chromium derivatives.** They all carry a `Chrome/` token, so the fair question
is whether any writes something other than the upstream Chromium version there.
Measured across the capture — **69 distinct derivative UA strings in 12 families**
(Edge, Opera, Vivaldi, Brave, Samsung, Yandex, Electron, Chromium, WebView, MIUI,
Sputnik, Edge Android), 1,497 requests — **none is flagged**, and their highest
patch is **280** (Opera's `Chrome/120.0.6099.280`) against a bound of 1000. That
is what the token is *for*: a derivative advertises the Chromium build it was
made from, using Chromium's own version string, because inventing its own numbers
there would break UA sniffing everywhere. Forks with no product token of their
own (Brave by default, Cromite, ungoogled-chromium) are indistinguishable from
plain Chrome here by construction and pass on that upstream version alone.

If one ever does land here, the cost is bounded by design: **this verdict is
corroboration, never a threshold.** It reaches a log tag, a history field and a
counted column on two detectors' alerts — nothing blocks, throttles or challenges
on it. The fix is to hold the offending rule, not the package.

It is checked on every challenge solve and surfaced three ways:

- `ua_impossible=<reasons>` in `cfm.challenges.log`
- `payload.ua_impossible` on the `challenge_solved` history event
- `impossible_ua` count on `challenge_solver_farm` alerts

All three are written only when the verdict is *impossible*, so their absence on
a solve means the UA was coherent, not that the check did not run.

In the WebUI, the forensics history table shows an `impossible` pill next to the
offending UA (with the matched rules in its tooltip) and has an
**impossible UA only** filter.

Two boundaries worth keeping in mind:

- **Coherence, not freshness.** An old-but-consistent UA is a real person on an
  old browser and is never flagged.
- **No staleness scoring.** It is tempting to score a UA by how far behind the
  fleet its version is. On the capture these rules came from, Chrome 118 was
  72.5% of all Chrome requests *because the farm dominated the traffic* —
  calibrating "current" by volume lets the attacker define normal.

`Verdict.Family` reports the **engine** identity, so every Chromium derivative
(Edge, Opera, Samsung Internet, Brave, Vivaldi, Yandex, Electron apps) reads as
`Chrome`. `HeadlessChrome/` is deliberately not matched at all — a headless UA is
honest, not impossible.

When adding a rule, validate it against a real UA corpus first. The
`(KHTML, like Gecko)` exact-match draft of one rule flagged legitimate crawlers
(Amazonbot, YouBot, GeedoShopProductFinder) that append their identity inside
the same parentheses — caught only because the rule was measured before shipping.

---

## 3) Custom detectors

Custom detectors use regex rules with named captures and can read from file or journal (and docker where source plumbing is available for that section pattern).

### Required syntax and keys

```ini
[custom:your_name]
ENABLED = 1
MODE = file                 ; file | journal (docker only where supported)
LOG_PATH = /var/log/auth.log
; JOURNAL_UNIT = sshd.service
EVERY = 2s
WINDOW = 10m
COOLDOWN = 20m
SAMPLE_LIMIT = 10

AUTHFAIL_IP = 12
AUTHFAIL_USER = 8

MATCH_TARGET = both         ; ip | user | both
FAIL_REGEX =
    ... named captures ...

; optional pre-filter
IGNORE_REGEX =
    ... regex to skip noisy benign lines ...

BLOCK = dryrun
BLOCK_COOLDOWN = 20m
```

### Capture groups and normalization

Use named captures in `FAIL_REGEX`:

- `(?P<ip>...)` for source IP
- `(?P<user>...)` for account/user key

Matching behavior:

- `MATCH_TARGET=ip` requires named `ip`
- `MATCH_TARGET=user` requires named `user`
- `MATCH_TARGET=both` requires both captures

Normalization behavior (engine-side):

- IP capture is parsed/normalized before block decisions
- user capture is trimmed and counted as detector key material
- if both are present, both per-IP and per-user counters can trigger

### Example A — single regex (safe starter, file source)

```ini
[custom:ssh_file_safe]
ENABLED = 1
MODE = file
LOG_PATH = /var/log/auth.log
EVERY = 2s
WINDOW = 10m
COOLDOWN = 20m
SAMPLE_LIMIT = 10
AUTHFAIL_IP = 20
AUTHFAIL_USER = 10
MATCH_TARGET = both
FAIL_REGEX =
    Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)
BLOCK = dryrun
BLOCK_COOLDOWN = 20m
```

### Example B — multi-regex + ignore-regex (file source)

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
BLOCK = 15m
BLOCK_COOLDOWN = 20m
```

### Example C — journal source

```ini
[custom:sshd_journal_safe]
ENABLED = 1
MODE = journal
JOURNAL_UNIT = sshd.service
JOURNAL_MATCHES = _SYSTEMD_UNIT=sshd.service
EVERY = 2s
WINDOW = 10m
COOLDOWN = 20m
SAMPLE_LIMIT = 10
AUTHFAIL_IP = 12
AUTHFAIL_USER = 8
MATCH_TARGET = ip
FAIL_REGEX =
    Failed password for .* from (?P<ip>\S+) port \d+ ssh2
BLOCK = dryrun
BLOCK_COOLDOWN = 20m
```

### Example D — docker/container log source (where section supports it)

```ini
[custom:container_auth_probe]
ENABLED = 1
MODE = docker
DOCKER_CONTAINER = auth-service
DOCKER_ARGS = --details,--tail=200
EVERY = 3s
WINDOW = 10m
COOLDOWN = 20m
SAMPLE_LIMIT = 10
AUTHFAIL_IP = 12
AUTHFAIL_USER = 8
MATCH_TARGET = both
FAIL_REGEX =
    login failed.*ip=(?P<ip>\S+).*user=(?P<user>\S+)
BLOCK = dryrun
BLOCK_COOLDOWN = 20m
```

---

## 4) Troubleshooting

### “enabled but waiting”

Symptoms:
- Section shows enabled but no alerts.

Checks:
- Confirm source path/unit/container exists and is receiving new lines.
- Confirm `EVERY` and `WINDOW` are not too large for your test cadence.
- Generate one known-bad synthetic line matching your regex and observe counters.

Safe action:
- Keep `BLOCK=dryrun` while validating.

### Outbound alerts need DNS corroboration

Symptoms:
- Outbound sentinel warns on unusual per-uid destination churn or burst rates.

Checks:
- Confirm the triggering uid/gid and process metadata from the alert line.
- Pivot to the ad-hoc DNS forensics runbook only when baseline telemetry is insufficient:
  [`admin-notes/ad-hoc-dns-forensics.md`](admin-notes/ad-hoc-dns-forensics.md).

Safe action:
- Keep captures short, identity-scoped, and temporary (no permanent detector/rule changes).

### Source not found

Symptoms:
- Logs indicate missing file/journal unit/container.

Checks:
- `MODE=file`: verify `LOG_PATH` path/permissions.
- `MODE=journal`: verify unit name (`sshd.service` vs `ssh.service` distro difference — `MODE=auto` handles this itself where supported).
- `MODE=docker`: verify container name and that daemon user can read `docker logs`.
- `MODE=auto`: read the startup resolution line (`source=… (reason)` or `no log source confirmed (...)` in the detector log) — it lists exactly what was tried.

### Regex compiles but no matches

Symptoms:
- Section loads cleanly, but counters remain zero.

Checks:
- Escape rules properly (double-backslashes where needed in ini templates).
- Make sure named captures (`?P<ip>`, `?P<user>`) exist per `MATCH_TARGET`.
- Add temporary broad pattern first, then tighten incrementally.
- Remove over-broad `IGNORE_REGEX` rules that may swallow target lines.

### False positives

Symptoms:
- Legitimate clients trigger alerts/challenges/blocks.

Mitigation path:
- Lower sensitivity (raise thresholds, widen `WINDOW`).
- Use `BLOCK=dryrun` or short TTL while tuning.
- Add detector-specific allow/ignore controls and leniency companions where appropriate.
- For web traffic, review path/UA lists and tune high-noise signatures.

---

## 5) Cross-links

- Reference config and inline presets: [`../configs/detectors.conf`](../configs/detectors.conf)
- Leniency companion sections: [§6](#6-leniency-companion-sections)
- Web UI / detector settings docs: [`cfm-admin-webtop.md`](cfm-admin-webtop.md)

---

## 6) Leniency companion sections

`[<section>.leniency]` companion blocks let a detector apply a **softer block
policy** to sources that match a country or ASN, and optionally keep those
blocks off the shared fleet blocklist. Origin is never trusted: a match only
*softens* the action (e.g. a temp-ban instead of permanent), it never skips
enforcement — see `webdetector-refactor.md` §4a and CLAUDE.md §6 for why
GeoIP/ASN must stay additive-only.

**Where it runs.** The section sink (`internal/detectors/autoblock_sink.go`)
checks leniency after enrichment and before the cooldown/block switch: on a
match it swaps to the softer `effectivePol` and sets the API-report flag. No
detector logic or `*_register.go` changes — leniency is purely a sink policy.

**Config syntax:**
```ini
[exim_security.leniency]
MATCH_COUNTRY  = "GR,CY"           ; ISO or full name, OR logic
; MATCH_ASN   = "AS6799,AS6866"    ; optional, OR with country
BLOCK          = "1h"              ; no | dryrun | permanent | <duration>
BLOCK_COOLDOWN = "30m"
SEND_TO_API       = YES            ; YES (default) | NO — report the block at all
SEND_TO_BLOCKLIST = lenient        ; lenient | blacklist (default) — destination
                                   ; list when SEND_TO_API=YES. "lenient" records
                                   ; the block centrally for visibility (support /
                                   ; unblock lookups) but is NEVER served to the
                                   ; fleet, so a known-good origin is not propagated.
```

**Log output** — when leniency matches:
```
[leniency][exim_security] ip=94.68.43.7 matched (country=GR) → block=1h cooldown=30m0s send_to_api=false
```
plus `leniency=yes  leniency_reason=country=GR  send_to_api=no` on the alert.

**Intended behaviour:**
- GR/CY IP failing auth 6× → blocked 1h locally, NOT sent to the fleet API.
- Non-domestic / datacenter IP failing auth 6× → normal permanent block, sent to API.
- No `[<section>.leniency]`, or enricher disabled, or no `MATCH_*` → normal block (leniency silently skipped).
- `BLOCK = no` in leniency → alert logged, no firewall action, no API.
- Hot-reload picks up leniency edits on the next reload; `.leniency` sections do not appear in the "enabled sections" log line.

**Multi-leniency (v2 — not built):** named instances
(`[exim_security.leniency:domestic]`, `[…:trusted]`) for per-match policies
would need `*leniencyPolicy` → `[]*leniencyPolicy` in the sink with
first-match-wins (~20 lines on top of the current foundation).
