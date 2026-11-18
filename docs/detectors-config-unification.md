# Detectors config unification — auto-detected sources, layered overrides, fleet-converged defaults

## 1. Goal

Make the shipped `/etc/cfm/detectors.conf` identical across the fleet, so
package upgrades can update it in place and new stock knobs reach every node.

The problem is that it is a conffile and every host had to hand-edit it: MTA
flavour, log paths, journal vs file vs docker, thresholds. So every copy was
"modified", upgrades left `.rpmnew` / `.dpkg-dist` files beside it, and new
keys never arrived. The 2026-08 audit of ten nodes found `[cfm_endpoints]` on
none of them.

The fix has three parts:
- **(A)** auto-detect what the environment decides;
- **(B)** move deliberate per-host deltas into an overlay the package never
  touches;
- **(C)** converge stock defaults on values the fleet has already validated.

(A), (B) and the per-host secrets are built. This file now holds the
decisions behind them and the work still open. How the built parts behave is
in `docs/DETECTORS.md` "Source modes" and "Overlay files".

---

## 2. Non-goals

- No change to detector behaviour (parsing, scoring, sink policy) beyond
  source resolution and the leniency lookup order.
- No remote or central config management: each node stays self-contained.
- No format migration: `detconf` syntax stays.

---

## 3. Mechanism A — source auto-resolution (built)

`internal/detectors/srcresolve` picks each detector's source from its config
plus per-detector candidate lists. The rules are in its package comment
(`internal/detectors/srcresolve/srcresolve.go:1-41`) and in `docs/DETECTORS.md`
"Source modes":
- an explicit value always wins;
- auto's first candidate is the detector's old default (the parity
  invariant);
- docker discovery never guesses between two containers.

The per-section planners shared by the registers and the dry-run preview are
in `internal/detectors/source_report.go`. Adopted by: `ssh_auth`,
`dovecot_auth`, the exim family and the postfix family.

### 3a. Journald is not a trustworthy source for every service

This decision shapes the resolver. Do not undo it.

1. **A daemon that writes its own log files never populates its journal.**
   Exim writes `mainlog` / `rejectlog` to disk on every install CFM runs on,
   and its unit's journal holds only startup stderr and child output.
2. **Journald attributes lines by cgroup, not by daemon.** Exim spawns
   dovecot's LDA for local delivery, so dovecot lines land under
   `_SYSTEMD_UNIT=exim.service` (seen on titan, 2026-08-25).

Hence:
- exim gets file candidates only. Journald is available only through an
  explicit `JOURNAL_UNIT` (`internal/detectors/source_report.go:136-142`).
- Services that really syslog (sshd, dovecot, postfix) keep journal
  candidates. Postfix's are signature-checked: recent entries must carry the
  daemon's tag, not just exist (`srcresolve.go:72-80` `JournalSignature`).

---

## 4. Mechanism B — config layering (built)

`/etc/cfm/detectors.conf` is read first, then `/etc/cfm/detectors.d/*.conf`
in lexicographic order. Merge rules (`internal/detconf/layered.go:1-35`):
- the same section and key in a later file replaces the earlier value;
- `KEY += value` appends to it;
- a section only in an overlay is added whole.

Every consumer reads the merged view: the manager
(`internal/detectors/manager.go:741-744`), `config_drift`, the source preview,
`cfm test` and the MCP config tool. Packaging creates the directory empty and
never installs into it (`packaging/debian/DEBIAN/postinst:33-38`,
`packaging/rpm/SPECS/cfm.spec:74,124`).

`config_drift` takes missing sections and keys from the MERGED view, so an
overlay that adopts a feature stops it reading as missing. Value diffs stay
stock-vs-BASE, because overlay values are intentional per-host state
(`internal/apiserver/config_drift_endpoint.go:12, 120-125, 191-197`).

**Open:** the cfm-admin editor still writes the BASE file. It only shows a
notice when overlays exist (`internal/apiserver/detectors_api.go:142-150`).
Every save through it dirties the conffile again. The plan was for it to
write one overlay (`90-webui.conf`) and show the merged view with per-key
provenance. `GET ?view=merged` already returns the merged view and its
overrides (`detectors_api.go:118-134`).

---

## 5. Mechanism C — global `[leniency]` (not built)

The 2026-08 audit found six near-identical `[X.leniency]` blocks across the
fleet (GR,CY / short TTL / lenient list), with accidental differences between
them. Leniency is purely a sink policy, so a lookup fallback changes no
detector:

```
[type:instance.leniency] → [type.leniency] → [leniency]   (first found wins)
```

Stock would ship one global block, and per-detector blocks stay for
overrides. Today only the exact `[<section>.leniency]` is read
(`internal/detectors/manager.go:665-668`). Two things block it:
- a bare `[leniency]` section would currently be instantiated as a detector
  type and fail as `unknown section type` (`manager.go:488-502`);
- validation should also warn on unknown keys in a `.leniency` section. The
  audit found `AUTHFAIL_IP` / `AUTHFAIL_USER` / `DDOS_IP` inside them on five
  nodes. `parseLeniencyPolicy` reads only `MATCH_COUNTRY`, `MATCH_ASN`, the
  block-policy keys, `SEND_TO_API` and `SEND_TO_BLOCKLIST`
  (`internal/detectors/leniency.go:53-106`), so those lines set nothing.

The per-host secrets that were also part of this step are done:
`CHALLENGE_TOKEN` / `OPENRESTY_TOKEN` live in `/var/lib/cfm/secrets/`
(`internal/hostsecrets/hostsecrets.go:1-20`), and stock ships both lines as
`placeholder` (`configs/detectors.conf:1463-1474, 2266-2270`).

---

## 6. Fleet-converged defaults (not built)

These are stock changes proposed from the 2026-08 audit. The heavy-traffic
nodes (orion, titan, earth, mars) carry the most weight, except that titan is
the experiments box: titan-only deltas are burn-in, not consensus.

None has landed. The "Stock now" column is the current reference file. ⚠ =
needs operator sign-off. "overlay" = the outlier stays as that host's overlay
line. Per-node values are as audited in 2026-08 and have not been re-read since.

### 6.1 Strong signals (heavy nodes agree)

| Key | Stock now | Heavy-4 (earth / mars / orion / titan) | Proposed |
|---|---|---|---|
| `[webdetector] BLOCK` | 12h (`:1415`) | 1h ×4 | **1h** |
| `[webdetector] OPENRESTY_OK_IP_TTL` | 10m (`:1527`) | 45m ×4 (+rigel, virgo) | **45m** |
| `[webdetector] AGENT_LIST` | curl,wget,python-requests,Go-http-client,spider,FacebookExternalHit (`:1396`) | 3 of 4: python-requests,Go-http-client,spider | python-requests,Go-http-client,spider ⚠ (curl / wget / FacebookExternalHit are FP-prone: legit tooling and FB previews) |
| `[webdetector] IP404_COUNT` | 250 (`:1388`) | 200 / 300 / 280 / 350 | **300** |
| `[webdetector] IP40X_COMBO` | 120 (`:1422`) | 160 / 290 / 220 / 300 | **250** |
| `[webdetector] IP40X_UNIQUE_PATHS` | 20 (`:1423`) | 20 / 35 / 25 / 40 | **30** |
| `[webdetector] IP403_COUNT` | 150 (`:1395`) | 200 / 250 / 60 / 250 | **200** (orion 60 → overlay) |
| `[webdetector] ORIGIN_KEEPALIVE` | 0 (`:1566`) | 1 on all 7 holders | **1** (see `docs/proxy-performance.md`) |
| `[waf_security] BLOCK` | 6h (`:311`) | 7d on all 7 holders | **7d** |
| `[cpanel] AUTHFAIL_IP` / `_USER` | 5 (`:1001-1002`) | 10 / 10 / 10 / 8 | **10** |
| `[cpanel] ROOT_IP` | 3 (`:1003`) | 5 ×4 | **5** |
| `[exim_security] BLOCK` | 12h (`:728`) | permanent / permanent / permanent / 24h | **permanent** ⚠ (titan 24h → overlay) |
| `[exim_security] NO_MAIL` | 8 (`:712`) | 10 / 8 / 8 / 15 | **10** |
| `[exim_security] SENDER_VERIFY_FAIL` | 12 (`:708`) | 0 / 0 / 6 / 0 | **0 (off)** ⚠ (FP-prone; orion 6 → overlay) |
| `[exim_security] RCPT_REJECT` | 12 (`:709`) | 0 / 0 / 6 / 0 | **0 (off)** ⚠ |
| `[exim_security] SESSION_ALL_FAILED` | 6 (`:723`) | 50 / typo / typo / 50 | **50** ⚠ (earth and titan are the only heavy nodes where the key parses) |
| `[exim_security] SLOW_FAIL_BLOCK` | 6 (`:724`) | 20 / typo / typo / 20 | **20** ⚠ |
| `[health] CONN_EST/SYN/TOTAL_SPIKE` | 5.0 (`:1289-1291`) | 5.0 / 5.0 / 3.0 / 5.0 | keep 5.0 (orion 3.0 → overlay) |
| `[leniency]` (new global, §5) | — | 15m / 15m dominant | MATCH_COUNTRY=GR,CY · BLOCK=15m · BLOCK_COOLDOWN=15m · SEND_TO_API=yes · SEND_TO_BLOCKLIST=lenient |

Settled since the audit:
- `[webdetector] AGENT_COUNT` is 35 (`configs/detectors.conf:1398-1406`).
- Stock `IGNORE_NETS` is the RFC1918 ranges plus `84.54.49.0/24`
  (`configs/detectors.conf:101`), pinned by `reference_defaults_config_test.go`.
- `[api_abuse]` is NOT added to stock: it is a deprecated alias that is
  merged into `cfm_endpoints` in memory
  (`internal/detectors/api_abuse_register.go:103-175`; `docs/DETECTORS.md`).
  Nodes still running `[api_abuse]` (3deers, titan and virgo in the audit)
  move its keys into a `[cfm_endpoints]` overlay.

### 6.2 Keep stock; outliers become overlay lines

- `[dovecot_auth]` 10/10 and `BLOCK=permanent` (titan 24h, saf 3/3, mailcow 5/5);
- `[ssh_auth]` 8/8/8;
- `[modsec] MODSEC_IP=20`;
- `[exim_relays]` / `[exim_queues]`;
- `[ftpd]` 8/8;
- the challenge subnet / suspicious-vhost thresholds (titan's lowering is
  Under-Attack burn-in);
- `[challenge_solver_farm]` / `[challenge_cookie_discard]` (mid burn-in);
- `[health] CONN_TOTAL_ABS=20000`;
- `[mysql_governor]` rule blocks (per tenant: overlay forever).

### 6.3 Split decisions ⚠ (operator picks in review)

| Key | Stock now | Heavy-4 | Options |
|---|---|---|---|
| `[exim_security] PROTO_ERR` | 8 (`:711`) | 0 / 8 / 8 / 0 | keep 8 (earth and titan overlay 0), or adopt 0 |
| `[exim_security] BLOCK_COOLDOWN` | 10m (`:729`) | 30m / 10m / 10m / 30m | keep 10m, or 30m |
| `[mysql] BLOCK` | permanent (`:1095`) | 24h / permanent / permanent / 24h | 24h (self-healing TTL, like waf_security), or keep permanent |
| `[health] THROUGHPUT_MIN_MBPS` | 60 (`:1293`) | 80 / 70 / 60 / 80 | 70 |

`PORT_SPIKE_X` and `PORT_WATCH` were proposed for stock, but no code reads
either key (no match in `internal/`). On the nodes that carry them they are
dead lines: clean them up as in §7, don't ship them. A port watch derived from
the listening services would be new detector work.

### 6.4 Undocumented keys that run

`IP403WAF_COUNT` is read (`internal/detectors/webdetector_register.go:674`;
0 = off, orion runs 5); stock lists it, commented out at its default, since
2026-11-18. The webdetector folder mode is now documented
as commented examples (`configs/detectors.conf:1320-1350`). The other keys the
audit found live but undocumented are retired and are dead lines on the
nodes, not stock candidates:
- `OPENRESTY_MODE`: ignored with a warning, see `docs/edge-unification-plan.md`;
- `CHALLENGE_HTTPS_LISTEN`: the 9099 listener is gone;
- `API_LISTEN`: deprecated, `webdetector_register.go:629-630`.

---

## 7. Operator fixes on the fleet (no code)

These come from the 2026-08 audit and have not been re-verified since. Check
each with `config_drift` / `detectors_config` before acting.

1. mailcowdocker, mars, orion, rigel, speedhost: `SESSION_ALL_FAILED": = 6` /
   `SLOW_FAIL_BLOCK" = 6`. The stray `"` makes the key invalid, so both
   thresholds run at built-in defaults.
2. 3deers: `CHALLENGE_VHOST = victim.com,`. The panel patterns
   (`webmail.*, whm.*, cpanel.*`) are missing. `victim.com` is a test
   leftover found on several nodes: sweep it out.
3. titan: `CHALLENGE_HOST_BYPASS = api.mybank.gr,` has a trailing comma.
4. speedhost: `[exim_security.leniency] BLOCK = permanent` defeats leniency.
   Set it to `15m`.
5. earth, mars, orion, rigel, speedhost: delete the dead `AUTHFAIL_*` /
   `DDOS_IP` keys inside `.leniency` sections (§5).
6. mars: delete `[httpd_access]` / `[nginx_access]`. No such detectors exist,
   and an unknown section type is logged and marked init-failed
   (`internal/detectors/manager.go:501-502`).
7. Remove the retired keys from §6.4 and `PORT_SPIKE_X` / `PORT_WATCH`.
8. Case and cosmetic sweep: `SEND_TO_API yes` casing, `LOG_PATH ""` vs `auto`.

---

## 8. Remaining work

- **PR 6: global `[leniency]` fallback** (§5). The persisted-token half
  shipped.
- **Edge-source auto.** Not built: `[webdetector]` still defaults to
  `MODE=file` with the apache tsv path
  (`internal/detectors/webdetector_register.go:611-612`). The aim: derive the
  edge log from the daemon's own edge knowledge (tsv, nginx combined,
  DirectAdmin folder mode).

  The modsec half shipped on 2026-11-18: stock is `LOG_PATH = auto`, and in
  `MODE = auto` a concrete path that does not exist falls back to the
  candidate scan with a warning (`resolveModsecLogPath`, `docs/DETECTORS.md`
  "Source modes"). The old stock path was cPanel EA4's real one, so the cPanel
  nodes were fine; 3deers, avglb, saf and watchdog watched nothing.
- **cfm-admin editor writes an overlay** (§4).
- **PR 7: stock converged defaults** (§6), one reviewable diff plus
  CHANGELOG. It changes behaviour on hosts that inherit defaults, so it ships
  alone, like the `cleanScalar` fix did, with the §6.1 ⚠ rows and §6.3
  resolved in review.
- **Fleet migration** (operational, per node): apply §7, upgrade, move deltas
  to an overlay, confirm `config_drift` reports a clean base.
  `detectors_srcresolve` shows each resolved source.

Every code PR also updates `docs/DETECTORS.md` (leniency lookup order,
"Source modes") and `docs/endpoint_scope_inventory.md` if an endpoint changes,
in the same change.

## 9. Open questions

- Should mailcow's softer dovecot / postfix thresholds (5/5) be the default
  for docker-mail hosts, or stay an overlay?
- Does the editor need a per-key "reset to base" when it moves to an overlay?
