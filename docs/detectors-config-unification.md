# Detectors config unification — auto-detected sources, layered overrides, fleet-converged defaults

**Status: DESIGN (2026-08-25) — implementation not started.**
Evidence base: a 10-server fleet audit of live `/etc/cfm/detectors.conf`
(3deers, earth, mailcowdocker, mars, orion, rigel, saf, speedhost, titan,
virgo) diffed against the stock reference with `detconf`-identical parsing.

---

## 1. Problem

`/etc/cfm/detectors.conf` is a conffile: upgrades seed it once and never touch
it again. Because every host must hand-edit it (MTA flavor, log paths, journal
vs file vs docker, panel differences), every host's copy is modified, so
package upgrades leave `.rpmnew`/`.dpkg-dist` files and **new knobs never
reach the fleet**. The audit found the failure mode live:

- `[cfm_endpoints]` (shipped in stock) is present on **zero** servers.
- ~10 newer stock keys (`PANEL_DECISION_MODE`, `PANEL_WAF_MODE`,
  `*_GOODBOT_EXEMPT`, `UNDER_ATTACK_FP_*`, `HISTORY_MAX_ROWS`, …) exist on no
  server.
- The reverse also happens — the fleet is *ahead* of stock: `[api_abuse]`
  exists in code and on 3 servers but not in the reference; `webdetector`
  `MODE=folder`/`LOG_DIR`/`GLOB`/`RECURSIVE` run live (saf) but are
  undocumented in stock; `waf_security BLOCK` is `7d` on all 7 holders while
  stock says `6h`.
- Hand-editing breeds silent bugs: 5 servers carry
  `SESSION_ALL_FAILED": = 6` / `SLOW_FAIL_BLOCK" = 6` — the stray `"` makes
  the key invalid, the parser folds both lines into the previous key's
  multiline value, and **both thresholds silently run at built-in defaults**.

Goal: make the shipped `detectors.conf` byte-identical across the fleet (so
upgrades can update it cleanly), by (A) auto-detecting everything
environment-derived, (B) moving deliberate per-host deltas into an overlay
layer the package never touches, and (C) converging tuned defaults onto
values the fleet has already validated.

Classification of the ~120 divergent `(section, key)` pairs found:

| Bucket | Share | Mechanism |
|---|---|---|
| Environment-derived (MTA flavor, paths, journal/file/docker, panel) | ~25% | **A. auto-detect** |
| Policy tuning (thresholds, BLOCK policies) | ~50% | **C. converge defaults** + overlay for deliberate outliers |
| Per-host by nature (tokens, vhost lists, allow-lists, governor rules) | ~15% | **B. overlay** / auto-generated |
| Noise (case `yes`/`YES`, `''` vs `auto`, dead keys, typos) | ~10% | one-time cleanup |

## 2. Non-goals

- No change to detector *behaviour* (parsing, scoring, sink policy) beyond
  source resolution and leniency lookup order.
- No remote/central config management — each node stays self-contained.
- No YAML/format migration; `detconf` syntax stays as-is.

---

## 3. Mechanism A — source auto-resolution (`internal/detectors/srcresolve`)

**The knobs are NOT removed.** `MODE`, `LOG_PATH`, `JOURNAL_UNIT`,
`DOCKER_CONTAINER`, `TOTAL_CMD`, … all keep working exactly as today, and stay
documented (commented) in stock as the escape hatch for custom setups. What
changes is the **default**: where a key is absent (or set to `auto`), a shared
resolver picks the source. **An explicit value always wins over auto.**

This generalises what already exists piecemeal: `ftpd` has full
`MODE=auto` (auto|file|journal), `modsec`/`mysql` have `LOG_PATH=auto`,
`exim_*` fall back to a hard-coded candidate list on empty `LOG_PATH`
(`exim/relays.go`), `dovecot` autodetects within its configured mode. One new
package, `internal/detectors/srcresolve`, owns the chain so it is written
once, unit-tested once, and every register calls it:

```
resolve(service):
  1. explicit config (MODE/LOG_PATH/JOURNAL_UNIT/DOCKER_*)   → use verbatim
  2. journal candidates (unit exists & journald readable)     → journal mode
  3. file candidates per (distro, panel), first that exists   → file mode
  4. docker discovery (name pattern, exactly-one match)       → docker mode
  5. service not present at all                               → self-disable
     (detector reports "disabled: <service> not found", not an error)
```

**Parity invariant:** for every detector, auto's first candidate is today's
default, so hosts whose config omits the key see identical behaviour after
the upgrade (e.g. `ssh_auth` tries `sshd.service` journal first — exactly the
current `MODE=journal` default).

Candidate tables (from the audit + current code):

| Service | Journal units | File candidates | Docker pattern |
|---|---|---|---|
| ssh | `sshd.service`, `ssh.service` (Debian — live on saf) | `/var/log/secure` (EL), `/var/log/auth.log` (Debian) | — |
| dovecot | `dovecot.service` | `/var/log/maillog`, `/var/log/mail.log`, `/var/log/dovecot.log` | `*dovecot-mailcow*` |
| exim | `exim.service` (future-proofing; no current host uses it) | `/var/log/exim_mainlog` (cPanel), `/var/log/exim4/mainlog` (Debian), `/var/log/exim/mainlog` (DA/EL — live on saf; **already in code's list**, saf's explicit value is redundant) + rejectlog siblings | — |
| postfix | `postfix@-.service`, `postfix.service` | `/var/log/maillog` (EL), `/var/log/mail.log` (Debian) | `*postfix-mailcow*`; queue cmds become `docker exec <c> postqueue …` automatically |
| modsec | — (file-only) | `/usr/local/apache/logs/error_log` (cPanel EA4), `/var/log/httpd/error_log` (EL), `/var/log/apache2/error_log` (Debian) — stock drops its hard-coded apache2 path | — |
| webdetector edge log | — | derive from the daemon's own edge knowledge: OpenResty/Angie/apache tsv (`/var/log/apache2/access_cfm_tsv.log`), nginx combined (`/var/log/nginx/access_cfm_combined.log` — earth), DirectAdmin per-domain folder → `MODE=folder LOG_DIR=/var/log/nginx/domains GLOB=*.log` (saf) | — |
| cpanel detector | n/a — presence check `/usr/local/cpanel` | | |

Self-disable rules (kills the biggest section-presence divergence): exim
detectors auto-disable where exim isn't installed (mailcowdocker sets
`ENABLED=0` by hand today), postfix detectors likewise on exim-only hosts,
`[cpanel]` on non-cPanel hosts, `[modsec]` where no modsec log exists.
`ENABLED=0` stays as an explicit hard-off that beats auto.

Docker discovery matches container names per service pattern and requires
**exactly one** match; zero or several → self-disable with a logged reason
telling the operator to set `DOCKER_CONTAINER` explicitly (fail closed, no
guessing).

Observability: each detector's resolved source (`mode=journal
unit=sshd.service`, `mode=file path=…`, `mode=docker container=…`,
`disabled: not installed`) is logged at startup **and** surfaced in
`/api/v1/detectors/status` → the `detectors_status` MCP tool, so a wrong
resolution is visible in one call. `whats_wrong` must not flag an
auto-disabled detector as a failure.

## 4. Mechanism B — config layering (`/etc/cfm/detectors.d/`)

Even with perfect auto-detection, one deliberate per-host threshold keeps the
conffile "modified" and resurrects `.rpmnew`. So deliberate deltas move out:

- Read order: `/etc/cfm/detectors.conf` (base, package-owned), then
  `/etc/cfm/detectors.d/*.conf` sorted lexicographically (`10-…`, `50-…`).
- Merge: same section+key → later wins (replace). New: `KEY += value`
  appends to list-valued keys (comma-joined) — needed for `IGNORE_NETS`,
  `IGNORE_IPS`, `CHALLENGE_VHOST_IGNORE`, `ALLOW_*`, so hosts extend the
  common base instead of forking the whole list.
- Sections may exist only in an overlay (named instances, host-local extras).
- `Sections.StampNS` becomes max mtime across all read files, so hot-reload
  and drift stamps stay correct.
- `detconf` grows `ReadLayered(basePath, dropinDir)`; all consumers move to
  it (manager, admin editor read path, configdrift live side, detector
  coverage endpoint). With no overlay present, output is byte-identical to
  `ReadSectionsFile(basePath)` — asserted by a parity test.
- **WebUI admin editor writes only an overlay** (`90-webui.conf`), never the
  base — today `detectorscfg/admin_config.go` rewrites
  `/etc/cfm/detectors.conf` in place, which would dirty the conffile again.
  The editor shows the merged view with per-key provenance (base/overlay).
- Packaging ships the empty `detectors.d/` directory and **never** installs
  files into it (that would recreate the conffile problem one level down).
- `config_drift` (API + MCP) keeps comparing stock vs **base** — overlays are
  intentional per-host state, not drift. It additionally reports
  `overlay_files`/`overlay_keys` counts so an audit sees the overlay exists.

End state: `/etc/cfm/detectors.conf` is pristine → upgrades update it in
place; every new stock knob reaches every host on the next upgrade; a host's
entire personality is its (tiny) overlay.

## 5. Mechanism C — global `[leniency]` + persisted auto-tokens

**Global leniency.** Six near-identical `[X.leniency]` blocks exist across
the fleet (GR,CY / short TTL / lenient list) with accidental micro-variation.
Since leniency is purely a sink policy (`autoblock_sink.go`, DETECTORS.md §6),
add one lookup fallback — no detector changes:

```
[type:instance.leniency] → [type.leniency] → [leniency]   (first found wins)
```

Stock ships one global block; per-detector blocks remain for overrides.
Audit cleanup folded in: 5 servers put `AUTHFAIL_IP`/`AUTHFAIL_USER`/`DDOS_IP`
*inside* `.leniency` sections — the sink ignores unknown keys, so these are
dead lines (someone believed they set softer thresholds for GR; they set
nothing). Validation should warn on unknown keys in `.leniency` sections.

**Tokens.** `CHALLENGE_TOKEN` / `OPENRESTY_TOKEN` are per-host secrets living
in the conffile — the last blocker to a byte-identical file.
`challenge_server.go` already generates an ephemeral fallback when the key is
absent; make it **generate-once-and-persist** under `/var/lib/cfm/`
(`root:cfm 0640`, same enforced ownership as the rendered Lua token files) so
restarts keep cookies valid. Conffile value still wins where present
(migration path: delete the key whenever, nothing breaks).

---

## 6. Fleet-converged defaults

The audit gives real burn-in data. Per the operator, the heavy-traffic nodes
are **orion, titan, earth, mars** — their values carry the most weight (they
absorbed the FP pressure that forced retuning), with one caveat: titan is the
experiments box, so titan-only deltas read as burn-in, not consensus.

Legend: **bold** = change stock; ⚠ = needs operator sign-off in review;
"overlay" = deliberate outlier stays as that host's overlay line.

### 6.1 Strong signals (heavy nodes agree — adopt)

| Key | Stock | Heavy-4 (earth/mars/orion/titan) | Proposed |
|---|---|---|---|
| `[webdetector] BLOCK` | 2h | 1h / 1h / 1h / 1h | **1h** |
| `[webdetector] OPENRESTY_OK_IP_TTL` | 10m | 45m ×4 (+rigel, virgo) | **45m** |
| `[webdetector] AGENT_COUNT` | 20 | 25 / 25 / 25 / 35 | **25** |
| `[webdetector] AGENT_LIST` | curl,wget,python-requests,Go-http-client,spider,FacebookExternalHit | 3 of 4: python-requests,Go-http-client,spider | **python-requests,Go-http-client,spider** ⚠ (fleet dropped curl/wget/FacebookExternalHit as FP-prone — legit tooling & FB previews) |
| `[webdetector] IP404_COUNT` | 250 | 200 / 300 / 280 / 350 | **300** |
| `[webdetector] IP40X_COMBO` | 120 | 160 / 290 / 220 / 300 | **250** |
| `[webdetector] IP40X_UNIQUE_PATHS` | 20 | 20 / 35 / 25 / 40 | **30** |
| `[webdetector] IP403_COUNT` | 150 | 200 / 250 / 60 / 250 | **200** (orion 60 = deliberate aggressive → overlay) |
| `[webdetector] ORIGIN_KEEPALIVE` | 0 | 1 on all 7 holders | **1** (+ document IDLE_SEC/MAX_REQS; see docs/proxy-performance.md) |
| `[waf_security] BLOCK` | 6h | 7d on all 7 holders | **7d** |
| `[cpanel] AUTHFAIL_IP/_USER` | 5 | 10 / 10 / 10 / 8 | **10** |
| `[cpanel] ROOT_IP` | 3 | 5 / 5 / 5 / 5 | **5** |
| `[exim_security] BLOCK` | 12h "interim" | permanent / permanent / permanent / 24h | **permanent** ⚠ (the 2026-04-22 interim note is stale — fleet moved on; titan 24h → overlay) |
| `[exim_security] NO_MAIL` | 8 | 10 / 8 / 8 / 15 | **10** |
| `[exim_security] SENDER_VERIFY_FAIL` | 12 | 0 / 0 / 6 / 0 | **0 (off)** ⚠ — 3 of 4 heavy MX disabled it (FP-prone); orion 6 → overlay |
| `[exim_security] RCPT_REJECT` | 12 | 0 / 0 / 6 / 0 | **0 (off)** ⚠ — same pattern |
| `[exim_security] SESSION_ALL_FAILED` | 6 | 50 / (typo) / (typo) / 50 | **50** ⚠ — earth+titan are the only heavy nodes where the knob works; both raised it deliberately |
| `[exim_security] SLOW_FAIL_BLOCK` | 6 | 20 / (typo) / (typo) / 20 | **20** ⚠ |
| `[api_abuse]` | *missing from stock* | live on 3deers/titan/virgo | **add section**: `ENABLED=1`, `STAGE1_THRESHOLD=10`, `ALLOW_IPS=127.0.0.1`, `ALLOW_NETS=10.0.0.0/8`, `PATH_EXCEPTIONS=/api/v1/embed/bootstrap, /cfm-admin/api/v1/embed/bootstrap` |
| `[health] CONN_EST/SYN/TOTAL_SPIKE` | 5.0 | 5.0 / 5.0 / 3.0 / 5.0 | keep **5.0** (orion 3.0 → overlay) |
| `[leniency]` (new global) | — | 15m/15m dominant (earth+titan dovecot 1h/30m) | **MATCH_COUNTRY=GR,CY · BLOCK=15m · BLOCK_COOLDOWN=15m · SEND_TO_API=yes · SEND_TO_BLOCKLIST=lenient** |

### 6.2 Keep stock; outliers become overlay lines

`[dovecot_auth]` 10/10 + `BLOCK=permanent` (titan 24h, saf 3/3, mailcow 5/5 →
overlay or adopt fleet value at migration); `[ssh_auth]` 8/8/8 (titan 5/5/6,
saf 4/4/4); `[modsec] MODSEC_IP=20` (titan 15, speedhost 10);
`[exim_relays]`/`[exim_queues]` stock values (titan's mild lowering →
overlay); `[ftpd]` 8/8 (speedhost 5/5); challenge subnet / suspicious-vhost
thresholds (titan's across-the-board lowering is Under-Attack burn-in →
overlay); `[challenge_solver_farm]`/`[challenge_cookie_discard]` (orion vs
titan differ — both mid-burn-in); `[health] CONN_TOTAL_ABS=20000` (titan
10000 = smaller box → overlay); `[mysql_governor]` rule blocks are per-tenant
by nature → overlay forever.

### 6.3 Split decisions ⚠ (operator picks in review)

| Key | Stock | Heavy-4 | Options |
|---|---|---|---|
| `[exim_security] PROTO_ERR` | 8 | 0 / 8 / 8 / 0 | keep 8 (earth+titan overlay 0) — or adopt 0 |
| `[exim_security] BLOCK_COOLDOWN` | 10m | 30m / 10m / 10m / 30m | keep 10m — or 30m |
| `[mysql] BLOCK` | permanent | 24h / permanent / permanent / 24h | propose **24h** (matches waf_security's self-healing-TTL philosophy; earth/saf/titan already there) — or keep permanent |
| `[health] THROUGHPUT_MIN_MBPS` | 60 | 80 / 70 / 60 / 80 | propose **70** |
| `[health] PORT_SPIKE_X` | *not in stock* | 5.0 / 3.0 / 3.0 / 5.5 | **add to stock**; propose 5.0 |
| `[health] PORT_WATCH` | *not in stock* | role-dependent everywhere | add superset `80,443,25,110,143,21,22,3306,465,587` now; **v2: auto-derive from listening services** (it is environment, not policy) |

### 6.4 Reverse-drift: document in stock what already runs

`OPENRESTY_MODE`, `API_LISTEN`, `CHALLENGE_HTTPS_LISTEN` (present on most
servers, absent from stock); webdetector folder mode
(`MODE=folder`/`LOG_DIR`/`GLOB`/`RECURSIVE` — live on saf); `IP403WAF_COUNT`
(orion). Normalize stock `IGNORE_NETS` `172.17.0.1/16` → `172.17.0.0/16`
(host bit set — copied verbatim to most of the fleet).

---

## 7. Immediate operator fixes (no code needed — do before/while Phase 1)

1. **mailcowdocker, mars, orion, rigel, speedhost**: fix
   `SESSION_ALL_FAILED": = 6` / `SLOW_FAIL_BLOCK" = 6` (stray `"` → both
   thresholds silently ignored today).
2. **3deers**: `CHALLENGE_VHOST = victim.com,` — panel patterns
   (`webmail.*, whm.*, cpanel.*`) are missing, so panel vhosts are
   unprotected there; `victim.com` looks like a test leftover (also present
   in several servers' lists — sweep it out).
3. **titan**: `CHALLENGE_HOST_BYPASS = api.mybank.gr,` trailing comma.
4. **speedhost**: `[exim_security.leniency] BLOCK = permanent` defeats the
   purpose of leniency → `15m`.
5. **earth, mars, orion, rigel, speedhost**: delete dead
   `AUTHFAIL_*`/`DDOS_IP` keys inside `.leniency` sections (ignored by the
   sink).
6. **mars**: delete `[httpd_access]` / `[nginx_access]` — no such detectors
   exist in code; silently ignored.
7. Case/cosmetic sweep: `SEND_TO_API yes` casing, `LOG_PATH ""` vs `auto`.

## 8. Per-server end state (expected overlay after all phases)

| Server | Expected overlay content |
|---|---|
| mailcowdocker | *(empty)* — everything was environment (docker/MTA/panel), now auto |
| mars, rigel, virgo, 3deers | ≤5 lines (allow-list extras via `+=`) |
| earth | ≤5 lines (PROTO_ERR=0 if not adopted; dovecot leniency 1h if kept) |
| saf | ≤6 lines (deliberately tight thresholds for a small box: ssh 4/4, dovecot 3/3) |
| speedhost | ≤6 lines (ftpd 5/5, modsec 10, cpanel 4) |
| orion | ~10 lines (aggressive IP403=60, CONN spikes 3.0, governor rules, solver-farm burn-in) |
| titan | the playground set (~15 lines: under_attack, abuse_shadow, lowered challenge thresholds, TTL blocks) |

## 9. Rollout (small single-concern PRs, per CLAUDE.md §9)

1. **PR 1 — this doc** (+ CLAUDE.md §7 row, ROADMAP index entry).
2. **PR 2 — `srcresolve` package** + adopt in `ssh_auth`/`dovecot_auth`
   (journal-unit candidates, `MODE=auto` default, self-disable). Unit tests
   with fake FS/unit probes; parity tests (journal-first == today).
3. **PR 3 — exim/postfix on srcresolve** incl. docker discovery and
   docker-ized queue commands; MTA-flavor self-disable (kills the
   postfix-vs-exim section divergence).
4. **PR 4 — webdetector edge-source auto** (engine-derived path, folder mode
   for DA) + modsec candidate cleanup.
5. **PR 5 — `detconf` layering** (`ReadLayered`, `+=`, StampNS, parity
   test), consumers switched, **WebUI editor → overlay**, `config_drift`
   overlay counts. This PR flips the conffile back to pristine-able.
6. **PR 6 — global `[leniency]` fallback + persisted tokens.**
7. **PR 7 — stock `detectors.conf` converged defaults** (§6 table, one
   reviewable diff) + CHANGELOG. Behaviour change on hosts that inherit
   defaults — ships alone, like the `cleanScalar` fix did.
8. **Fleet migration** (operational, per server): apply §7 fixes → upgrade →
   move deltas to overlay → verify `config_drift` reports clean base →
   delete token keys. `detectors_status` shows each resolved source.

Every code PR: adversarial self-review before opening; update
`docs/DETECTORS.md` (§6 leniency lookup order, new §source-resolution) and
`docs/endpoint_scope_inventory.md` if any endpoint changes, in the same
change.

## 10. Risks & open questions

- **Auto changes behaviour only where keys are absent.** Explicit values win,
  so upgraded hosts are unaffected until they delete lines. The parity
  invariant (§3) covers the absent-key case.
- **Docker discovery ambiguity** fails closed to self-disable + log; never
  guesses among multiple matches.
- **Threshold convergence (PR 7) is the only behaviour-visible step** for
  hosts tracking stock defaults; it lands as its own PR with the ⚠ decisions
  from §6.3 resolved in review.
- Open: should `PORT_WATCH` auto-derive in v1 or v2? Should mailcow's softer
  dovecot/postfix thresholds (5/5) become the fleet default for docker-mail
  hosts or stay overlay? Does the WebUI need per-key "reset to base" UX at
  the same time as PR 5, or later?
