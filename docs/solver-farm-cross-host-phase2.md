# Solver-farm detection — cross-host fingerprint aggregation (Phase 2)

> **⚠️ SUPERSEDED — historical design note, NOT current state.** The canonical,
> as-built reference is the node hub **`docs/traffic-classifier.md`** and the
> central ledger **`cfm-web:docs/fingerprint-reputation.md`**. Kept for
> archaeology; where this note disagrees with the hubs or the code, they win.

> **Status:** DESIGN NOTE (pre-code). Extends the shipped Phase-1
> fingerprint-concentration track (`docs/solver-farm-fingerprint-concentration.md`,
> `internal/detectors/solverfarm/detector.go`) with a **third** evaluation that
> catches a farm spread so *thinly per vhost* that the per-`(host, fp)`/60 s
> country guard structurally misses it — the "known low-rate residue" Phase-1
> §5.3 documented and deferred to its §11. Grounded on a live 2-node capture
> (`c28caa00`, `95070673`; titan + orion, ~12 h, 2026-09-09). Read Phase-1 first.
> Owner: challenge/webdetector.

All signals here ship **shadow/log-only first**, exactly like Phase-1: an
fp-concentration-only finding writes `cfm.detector.log` and sends **no**
notification through burn-in. `logonly → alert → seed`, never a per-IP block
(≈1 solve/IP, residential-risky — see the `solverfarm` package doc).

---

## 1. Why Phase 2 — the residue is a full farm, confirmed live

Phase-1 catches a farm whose fingerprint concentrates on **one vhost** (≥ 8 `/24`
**and** ≥ 6 countries under a single fp in a 60 s window). It deliberately left a
gap it could name but not yet measure: a farm that puts only a *trickle* on each
of *many* vhosts never reaches 6 countries in any single vhost's 60 s window,
even though the same fingerprint is unmistakably a farm across the fleet.

The 24 h burn-in turned that hypothetical into a measured fact. Aggregating the
`challenge_solved` stream **per fingerprint across all of a node's vhosts**
(≈12 h, per node):

| node | fingerprint | class | hosts | **countries** | `/24` | solves | **solves/IP** |
|---|---|---|---:|---:|---:|---:|---:|
| titan | `c28caa00` | farm (aggressive) | 12 | **69** | 1008 | 1140 | **1.00** |
| orion | `95070673` | **farm (thin)** | 23 | **41** | 449 | 1008 | **1.05** |
| titan | `77a50fbb` (common iOS) | legit | 6 | 1 | 23 | 35 | 1.46 |
| orion | `7b6c7d83` | legit | 8 | 1 | 7 | 11 | 1.57 |
| orion | `6edad59b` | legit | 6 | 1 | 14 | 14 | 1.00 |
| orion | `42d907e9` | legit | 4 | 2 | 20 | 23 | 1.15 |

`95070673` is a **full-blown farm** — 23 vhosts, 41 countries, 449 `/24`s, ~1
solve/IP — that Phase-1 barely sees: its **per-host 60 s country-peak** is
`electroexpert = 6`, one other host `= 6`, and **`1` on all 21 others**. It
scrapes the whole catalogue of two dozen shops one page at a time, from a
residential-proxy pool, and slips under the per-vhost bar on every host but the
one or two busiest. Phase-1 keyed on the vhost; this farm's invariant lives
**above** the vhost.

## 2. The invariant that survives thinning

Spread a farm thin enough per vhost and the per-vhost concentration vanishes —
but a different invariant sharpens: **across the vhosts it touches, the farm is
one fingerprint, many countries, ~1 solve per IP, and a super-majority of each
targeted vhost's challenged solves.** A legitimate shared browser fingerprint
(a popular iOS/Chrome stack that many honest visitors happen to share) is the
opposite on every axis.

> **Group-by, never match — same rule as Phase-1.** The detector never names
> `c28caa00` or `95070673`. It groups a node's in-window solves **by whatever
> fingerprint each carries** and asks whether *some* fingerprint crosses the
> cross-host farm shape. Both live farms trip it; a rule keyed on either value
> would already be blind to the other.

### 2.1 Cross-host loses one guard — so we add two

Phase-1's load-bearing guard is **country spread within one vhost's window**. It
works because a legitimate shared-fingerprint population is geographically
*clustered per vhost* (a Greek shop's iOS users are in Greece). Aggregating
across vhosts **weakens that guarantee**: a genuinely global browser fingerprint,
pooled over many sites, could accumulate several countries honestly (Phase-1 §6
"residual risk"). Cross-host therefore cannot lean on country spread alone.

The load-bearing guard is **`max_fp_share` per host** — the farm's fingerprint
**dominates** each vhost it touches (`c28caa00` = 100/100/87/70 %; `95070673` =
100/95/90/85/83 %), while a legit shared browser is a **minority** of a diverse
population (`77a50fbb` ≤ 17 %, `42d907e9` ≤ 33 %, `19877aeb` ≈ 3 %). This is the
axis a legit fingerprint *structurally* cannot cross — it is, by definition, one
browser among many on an honest vhost. Country spread is the secondary guard
(farms 27–79 on their dominant hosts, legit ≤ 9).

> **Burn-in correction (2026-09-11) — `solves_per_ip` is NOT a discriminator, do
> not gate on it.** The Phase-1 §5.3 snapshot suggested farms sit at ~1.0 and
> legit ≥ 1.15. The **weekday burn-in refuted that**: on a fleet of product-catalog
> shops (few repeat visits) *everything* sits at ~1.0–1.2 — farm `95070673` = 1.11,
> yet legit `7b6c7d83` = 1.00, `19877aeb` = 1.08, `6edad59b` = 1.08. A
> `MAX_SOLVES_PER_IP ≤ 1.10` ceiling would have **excluded the 95070673 farm
> (1.11) and admitted the legit fps** — backwards. So `solves_per_ip` is carried as
> **evidence only**, never a gate. The real separation is **share (primary) +
> country spread (secondary) + host/subnet floors**. The closest legit call,
> `19877aeb` (a globally-distributed shared browser: 9 countries, s/ip 1.08), is
> excluded decisively by **share ≈ 3 % vs the 50 % floor (~16× margin)** — which is
> exactly why share, not s/ip, is the guard.

So cross-host is **safer** than a naive "one fp, many countries" would be, not
riskier: it requires country spread **AND** per-host dominance together. A
global-audience browser fails the dominance gate (it is a minority everywhere)
even if it passes the country count.

## 3. Design — a cross-host track on the existing detector

Add a **third** evaluation to `solverfarm.Detector`, sharing its ingest, window
plumbing, pruning, allow-lists, cooldown, mark and alert path. No new detector,
no new event stream, no new enrichment (Phase-1 already delivers `Fingerprint`
and the `countryFn`).

### 3.1 Per-node, per-fingerprint aggregate

Alongside the existing per-host `subnets` set (L2 high-rate) and per-`(host, fp)`
aggregate (Phase-1 low-rate), aggregate over a **node-level window longer than
60 s** — a thin farm emits few solves per host per minute, so the cross-host tally
needs time to accumulate its spread. Burn-in measured `95070673` at ~63 solves/h;
**`XH_WINDOW = 30m`** lets its dominant hosts accumulate well past the country
floor (as-built: a single node-level buffer of fingerprinted solve records —
`{host, fp, subnet, ip, country, when}` — pruned to the window each pass and
re-aggregated, bounded by a cap). Per fingerprint the tally is: distinct hosts,
countries, subnets, ips, solves.

Each `(host, fp)` contribution is admitted to the fp's cross-host tally **only if
the fp is a super-majority of that vhost's fingerprinted solves in the window** —
the **`fp_share ≥ MIN_XH_HOST_SHARE` pre-gate**, the one guard a legit minority
browser cannot forge. Only the qualifying pairs' subnets/countries/hosts are
summed. A popular browser that is a 10 % slice of every vhost never contributes a
single host to any fp's cross-host tally, so it can never reach the host/country
floors no matter how many sites it appears on. (`solves_per_ip` is **not** part of
the pre-gate — burn-in showed it does not separate; see the §2.1 correction — it
is carried on the alert as evidence.)

### 3.2 Cross-host verdict

Flag a fingerprint (and mark **every** contributing vhost `solver_farm`) when,
over the window, its qualifying contributions satisfy **all**:

- `hosts     ≥ MIN_XH_HOSTS`     (floor, counted over the pre-gated hosts)
- `countries ≥ MIN_XH_COUNTRIES` (secondary guard; primary is the share pre-gate)
- `subnets   ≥ MIN_XH_SUBNETS`   (floor)

(No `solves_per_ip` gate — the burn-in correction. The **share pre-gate** in §3.1
is the primary guard; these three are the spread floors it feeds.)

The empty/`-` fingerprint is **never** a group key (same as Phase-1 — it would
pool unrelated clients into a phantom fleet-wide farm, the worst possible false
positive here). `ALLOW_FPS` still exempts a known-legitimate shared stack.

The verdict raises the same `Challenge/SolverFarm` finding and the same
`webdetector.MarkSolverFarm` mark as the other two tracks; downstream (WebUI
badge, Track-2 seed) is unchanged. The alert carries `tracks=cross_host` (or a
`+`-joined set when several tracks fire), plus `xh_fp`, `xh_hosts`,
`xh_countries`, `xh_subnets`, `xh_host_share`, `xh_solves_per_ip` evidence in
`Extra` (the last as evidence, not a gate).

## 4. Calibration — measured per node (2026-09-11 weekday burn-in)

Per-node aggregation over the ~15 h weekday window (the FP-guard's real test):

| axis | farms (`c28caa00` titan, `95070673` orion) | legit (all observed) | floor/pre-gate | role |
|---|---|---|---|---|
| per-host `max_fp_share` (**pre-gate**) | dominant hosts **85–100 %** | `42d907e9` ≤ 33 %, `77a50fbb` ≤ 39 %, `19877aeb` ≈ 3 % | `MIN_XH_HOST_SHARE = 0.50` | **primary guard** |
| distinct **countries** (pre-gated hosts) | 27–79 | ≤ 9 (`19877aeb`) | `MIN_XH_COUNTRIES = 12` | secondary guard |
| distinct `/24` | 489–1030 | ≤ 47 (`77a50fbb`) | `MIN_XH_SUBNETS = 30` | floor |
| distinct **hosts** | 22 / 10 | ≤ 7 (`42d907e9`) | `MIN_XH_HOSTS = 4` | floor |
| `solves_per_ip` | **1.01 / 1.11** | 1.00–1.57 (no separation) | — | **evidence only** |

The **share pre-gate is the discriminator**: farms dominate the vhosts they hit
(85–100 %), every legit fp is a minority (≤ 39 %, most ≤ 9 %), so the 50 % floor
splits them with a clean gap and — crucially — a legit fp's `(host, fp)` pairs
never enter the pool, so its country/subnet spread never even accrues. `countries`
is the secondary guard, raised to **12** because the closest legit fp `19877aeb`
reached **9** countries cross-host (a globally-distributed shared browser); its
share of ~3 % excludes it on the pre-gate with a ~16× margin regardless.

**`solves_per_ip` is deliberately absent from the gate** (see the §2.1 burn-in
correction): farm `95070673` = **1.11** while legit `7b6c7d83` = 1.00 and
`19877aeb`/`6edad59b` = 1.08 — full overlap. A ceiling would have excluded the farm
and admitted the legit fps. It is reported as evidence only.

**Validated live:** on `www.vitolighting.com` (orion) `95070673` was 90 % share /
27 countries — the per-host track flagged it there, and the cross-host track would
additionally mark the ~21 other vhosts where the same fp stays under the per-host
bar. The closest legit call, `19877aeb`, was excluded on all of share (3 %),
per-host 60 s country-peak (1), and the country floor (9 < 12).

## 5. False-positive analysis — the global-audience case, now doubly guarded

The one residual FP Phase-1 could not exclude by construction (§6) was a vhost
with a large, genuinely global legitimate audience under a persistent challenge,
whose dominant browser fingerprint spans many countries honestly. Cross-host
aggregation would *seem* to make that worse (it pools countries across vhosts) —
but the two added guards close it:

- Such a browser is a **minority** of each vhost's diverse solves → fails
  `MIN_XH_HOST_SHARE`, so its `(host, fp)` pairs never enter the pool. This is the
  guard, and burn-in confirmed it holds: `19877aeb`, a real globally-distributed
  shared browser (9 countries cross-host), sat at ~3 % share and never entered the
  pool.

A farm fails it: it *is* the traffic on the vhosts it targets. So the case Phase-1
flagged as "the signal to watch" is, for the cross-host track, **excluded by
design** (per-host dominance) rather than by threshold luck. Until burn-in of the
cross-host track itself is clean, **log-only**: a mis-tuned threshold *reports*,
never blocks.

> **What "log-only" does and doesn't mean.** As with Phase-1, log-only suppresses
> the *notification*, not the *mark*: a cross-host-only finding still MARKs every
> contributing vhost `solver_farm` — that is precisely how the burn-in is observed
> (`challenge_vhosts` shows `solver_farm: true`). The mark drives the WebUI badge
> and the Track-2 seed, and the Track-2 seed is itself shadow (`AbuseShadow`,
> would-harden logs only), so nothing the burn-in marks ever blocks or challenges a
> visitor. "Log-only" is about mail; "never blocks" is about enforcement; the mark
> sits between them as observation.

Verified good bots remain excluded upstream (exempted from the challenge, absent
from the solve stream); `ALLOW_HOSTS/IPS/NETS/UA_CONTAINS/FPS` still apply.

## 6. Plumbing — reuses Phase-1 wholesale

Nothing new crosses a package boundary. The fingerprint and country enrichment
already flow into the detector (Phase-1: `core.InputEvent.Fingerprint`,
`SetEnricher`/`countryFn`, off the hot `Enqueue` path). Cross-host adds, inside
`solverfarm.Detector`:

- a node-level buffer of fingerprinted solve records (`{host, fp, subnet, ip,
  country, when}`), pruned to `XH_WINDOW` each pass and re-aggregated — one buffer,
  bounded by a cap, cheaper to reason about than incrementally-windowed counters;
- a per-`(host, fp)` **share** computation (per-host fp solves ÷ per-host
  fingerprinted solves in the window) to run the admission pre-gate;
- the `MIN_XH_*` / `MIN_XH_HOST_SHARE` evaluation in `RunOnce`, sharing the mark,
  cooldown and alert (each qualifying vhost gets its own per-host alert + mark);
- the `tracks=cross_host` + `xh_*` alert `Extra` fields.

A nil enricher (no GeoIP) leaves `countryFn` nil, which **fail-safe disables**
the country-bearing tracks — cross-host included — exactly as Phase-1 does.

## 7. Config surface (additive to `[challenge_solver_farm]`)

A config predating these inherits the defaults (no upgrade-prompt churn), same as
Phase-1:

| Key | Default | Meaning |
|---|---|---|
| `XH_TRACK` | `1` | enable the cross-host track (kill-switch) |
| `XH_WINDOW` | `30m` | sliding window for cross-host aggregation |
| `MIN_XH_HOST_SHARE` | `0.50` | **primary guard** — per-vhost dominance to admit a `(host, fp)` pair |
| `MIN_XH_HOSTS` | `4` | distinct pre-gated vhosts one fp must span (floor) |
| `MIN_XH_COUNTRIES` | `12` | distinct countries under that fp (secondary guard) |
| `MIN_XH_SUBNETS` | `30` | distinct `/24` under that fp (floor) |

(No `MAX_XH_SOLVES_PER_IP` — the burn-in showed `solves_per_ip` does not separate
farm from legit, so it is evidence only, not a config gate.)

**Default-on, log-only through burn-in** — identical discipline to Phase-1's
`FP_TRACK`: the track arms on the next binary upgrade, never blocks, and a
cross-host-**only** finding is **log-only** (no notification), so a new signal
whose global-audience edge is not yet fully re-confirmed cannot mail operators
fleet-wide. The proven subnet-spread track still notifies per `ACTION`; a
**combined** finding (cross-host + per-host or + subnet-spread — a farm confirmed
by two independent invariants) notifies. Promote cross-host-only findings to
notify after burn-in; `XH_TRACK = 0` disables. `TestWAFSecurityFamilyCoverage`
has no bearing here; extend `solverfarm`'s own coverage test for the new keys.

## 8. Test plan

Unit tests (`internal/detectors/solverfarm/detector_test.go`, replayed via the
injectable `nowFn` + `countryFn`, extending the Phase-1 harness):

- **Positive — thin farm:** replay the `95070673` shape — one fp, ≥ 4 hosts each
  ≥ 50 % share, ≥ 12 countries and ≥ 30 `/24` node-wide, but **< 6 countries in any
  single host's 60 s window** → Phase-1 stays silent, cross-host flags, and
  **every** contributing vhost is marked.
- **Negative — popular browser across many sites:** one fp on 8 hosts, many
  countries, **≤ 20 % share per host** → does not flag (share pre-gate empties the
  pool, so no host's countries ever accrue). This is the `19877aeb` shape.
- **Negative — s/ip does not rescue nor condemn:** a farm at `solves_per_ip = 1.1`
  still flags (s/ip is not a gate); a legit minority at `solves_per_ip = 1.0` still
  does not (share pre-gate) — the guard is share, not s/ip.
- **Negative — single busy vhost minority:** one fp on 1 host, 49 `/24`, 6
  countries, but ~5 % share → not pooled cross-host (share pre-gate + hosts floor).
- **Regression:** Phase-1's per-`(host, fp)` path and the L2 `MIN_SUBNETS = 40`
  path are unchanged; the empty fingerprint is never a group key on any track.
- **Fail-safe:** nil `countryFn` disables the cross-host track (never fires
  without confirmed geographic spread).

## 9. Fleet-global extension (out of scope — future)

The track aggregates **per node**. Both live farms clear the bar on a single node
(`c28caa00` on titan, `95070673` on orion), so node-local catches today's
adversary. A farm that deliberately puts **≤ 3 vhosts per node** across the whole
fleet would still slip under `MIN_XH_HOSTS` on each node while being obvious
fleet-wide. Catching that needs a **cross-node** fp aggregate via cfm-web central
(the fleet already ships per-node solve summaries there) — a bigger change,
deferred until such a farm is actually observed (CLAUDE.md: don't code a signature
for a threat we cannot yet see). Node-local cross-host is the grounded first cut.

## 10. Actuation (out of scope — deferred, shared Stage-E)

Unchanged from Phase-1 §10: this track only *identifies*. What to do is the
Stage-E decision shared with the vhost lane — **ChallengeV2** (interactive
drag/puzzle) is the right soft rung for the solver-farm class (PoW is pure CPU a
farm solves trivially; interaction/rendering is what a headless stack lacks). The
mark becomes the `solver_farm` daemon seed already budgeted in the per-client
score. No enforcement lands from this doc.

---

### Grounding references

- Phase-1 (as-built): `docs/solver-farm-fingerprint-concentration.md`,
  `internal/detectors/solverfarm/detector.go`,
  `internal/detectors/challenge_solver_farm_register.go`.
- Live capture: `detection_history type=challenge_solved` on titan + orion,
  2026-09-09 (~12 h, 2400 solves; farms `c28caa00`/`95070673`, controls
  `77a50fbb`/`7b6c7d83`/`6edad59b`/`42d907e9`).
- Feeds: `docs/challenge-score.md` (Track-2 per-client score),
  `docs/traffic-classifier.md` (master plan), `docs/roadmaps/challenge-engine.md`.
