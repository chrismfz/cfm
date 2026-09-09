# Solver-farm detection — cross-host fingerprint aggregation (Phase 2)

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

The live data hands us **two independent guards that a legit fingerprint cannot
forge**, both measured above:

- **`solves_per_ip`** — farms sit at **1.00–1.05** (one-shot proxy IPs); every
  legit fp measured sits at **≥ 1.15**, most **≥ 1.4** (real visitors revisit and
  navigate). A super-thin farm is ~1.0 *by construction* — it has one job per IP.
- **`max_fp_share` per host** — the farm's fingerprint **dominates** each vhost it
  touches: `c28caa00` = 100 % / 100 % / 87 % / 70 % of challenged solves on its
  top vhosts; `95070673` = 100 % / 95 % / 85 % / 83 %. A legit shared browser is a
  **minority** of a diverse population: `77a50fbb` peaks at **17 %** (mostly
  6–10 %). This is the axis a legit fingerprint *structurally* cannot cross —
  it is, by definition, one browser among many on an honest vhost.

So cross-host is **safer** than a naive "one fp, many countries" would be, not
riskier: it requires country spread **AND** ~1 solve/IP **AND** per-host
dominance together. A global-audience browser fails the last two even if it
passes the first.

## 3. Design — a cross-host track on the existing detector

Add a **third** evaluation to `solverfarm.Detector`, sharing its ingest, window
plumbing, pruning, allow-lists, cooldown, mark and alert path. No new detector,
no new event stream, no new enrichment (Phase-1 already delivers `Fingerprint`
and the `countryFn`).

### 3.1 Per-node, per-fingerprint aggregate

Alongside the existing per-host `subnets` set (L2 high-rate) and per-`(host, fp)`
aggregate (Phase-1 low-rate), maintain a **node-level** map keyed on **fingerprint
only**, over a **longer** sliding window than 60 s (a thin farm emits few
solves per host per minute; propose `XH_WINDOW = 10m`, calibrate in burn-in):

- `hosts` — distinct vhosts this fp solved
- `countries` — distinct ISO-2 under this fp (node-wide)
- `subnets` — distinct client `/24` (v6 `/48`) under this fp
- `ips`, `solves` — for the aggregate `solves_per_ip`

Each `(host, fp)` contribution is admitted to the fp's cross-host tally **only if
that pair is itself farm-shaped on its vhost** — a **pre-gate** that keeps a legit
minority fingerprint out of the pool entirely:

- per-host `fp_share ≥ MIN_XH_HOST_SHARE`  (the fp is a super-majority of *that*
  vhost's window solves), **and**
- per-host `solves_per_ip ≤ MAX_XH_SOLVES_PER_IP`.

Only the qualifying pairs' subnets/countries/hosts are summed. A popular browser
that is a 10 % slice of every vhost never contributes a single host to any fp's
cross-host tally, so it can never reach the host/country floors no matter how many
sites it appears on.

### 3.2 Cross-host verdict

Flag a fingerprint (and mark **every** contributing vhost `solver_farm`) when,
over the window, its qualifying contributions satisfy **all**:

- `hosts     ≥ MIN_XH_HOSTS`
- `countries ≥ MIN_XH_COUNTRIES`   (primary discriminator)
- `subnets   ≥ MIN_XH_SUBNETS`
- aggregate `solves_per_ip ≤ MAX_XH_SOLVES_PER_IP`

The empty/`-` fingerprint is **never** a group key (same as Phase-1 — it would
pool unrelated clients into a phantom fleet-wide farm, the worst possible false
positive here). `ALLOW_FPS` still exempts a known-legitimate shared stack.

The verdict raises the same `Challenge/SolverFarm` finding and the same
`webdetector.MarkSolverFarm` mark as the other two tracks; downstream (WebUI
badge, Track-2 seed) is unchanged. The alert carries `tracks=cross_host` (or a
`+`-joined set when several tracks fire), plus `xh_fp`, `xh_hosts`,
`xh_countries`, `xh_subnets`, `xh_solves_per_ip` evidence in `Extra`.

## 4. Calibration — measured per node (2026-09-09)

The separation is decisive on **every** axis; the three guards are AND-ed so any
one of them already excludes every legit fingerprint observed:

| axis | farms (`c28caa00`, `95070673`) | legit (all observed) | proposed floor/ceiling | margin |
|---|---|---|---|---|
| distinct **countries** / node / window | **41–69** | ≤ 3 | `MIN_XH_COUNTRIES = 10` | ~4× to the floor, ~13× farm-to-legit |
| distinct `/24` | 449–1008 | ≤ 23 | `MIN_XH_SUBNETS = 30` | ~15× |
| distinct **hosts** | 12–23 | ≤ 8 | `MIN_XH_HOSTS = 4` | *floor, not discriminator* |
| **`solves_per_ip`** | 1.00–1.05 | ≥ 1.15 (mostly ≥ 1.4) | `MAX_XH_SOLVES_PER_IP = 1.10` | tight — corroborator |
| per-host `max_fp_share` (pre-gate) | 70–100 % | ≤ 17 % | `MIN_XH_HOST_SHARE = 0.50` | ~3× |

As with Phase-1's `MIN_SUBNETS = 40` and `MIN_FP_COUNTRIES = 6`, **hosts** is a
*floor against a trickle*, not the discriminator — a legit fp reached **8** hosts
(`7b6c7d83`), yet is excluded by every other guard (1 country, 1.57 solves/IP, and
it never clears the 50 % per-host share pre-gate). `countries` is primary;
`solves_per_ip` and `max_fp_share` are the two guards that make cross-host safe
where country spread alone would not be.

`MAX_XH_SOLVES_PER_IP = 1.10` is deliberately tight (the closest legit,
`42d907e9`, sits at 1.15 with only 2 countries — already excluded by the country
guard). It is a corroborator, not the primary gate; the country floor carries the
decision, and the ceiling only hardens the global-audience edge case.

**Watch item surfaced by the capture:** `c2e09593` (titan, single host, 49 `/24`,
6 countries/60 s, 1.00 solves/IP, but only ~5 % of that vhost's solves) looks
farm-shaped on the concentration axes yet is a *minority* of its one vhost — a
possible small/newer farm or a shared automation stack. The cross-host track's
share pre-gate correctly declines to pool it (5 % < 50 %); Phase-1's per-host
track may flag it borderline. It is a burn-in **watch**, not a threshold input.

## 5. False-positive analysis — the global-audience case, now doubly guarded

The one residual FP Phase-1 could not exclude by construction (§6) was a vhost
with a large, genuinely global legitimate audience under a persistent challenge,
whose dominant browser fingerprint spans many countries honestly. Cross-host
aggregation would *seem* to make that worse (it pools countries across vhosts) —
but the two added guards close it:

- Such a browser is a **minority** of each vhost's diverse solves → fails
  `MIN_XH_HOST_SHARE`, so its `(host, fp)` pairs never enter the pool.
- Its users **revisit and navigate** → `solves_per_ip` well above 1.10.

A farm fails neither: it *is* the traffic on the vhosts it targets, and it is
one-shot per IP. So the case Phase-1 flagged as "the signal to watch" is, for the
cross-host track, **excluded by design** rather than by threshold luck — provided
burn-in confirms the share/`s-per-ip` separation holds on a high-traffic global
vhost (the same re-confirmation Phase-1 asks for). Until then, **log-only**: a
mis-tuned threshold *reports*, never blocks.

Verified good bots remain excluded upstream (exempted from the challenge, absent
from the solve stream); `ALLOW_HOSTS/IPS/NETS/UA_CONTAINS/FPS` still apply.

## 6. Plumbing — reuses Phase-1 wholesale

Nothing new crosses a package boundary. The fingerprint and country enrichment
already flow into the detector (Phase-1: `core.InputEvent.Fingerprint`,
`SetEnricher`/`countryFn`, off the hot `Enqueue` path). Cross-host adds, inside
`solverfarm.Detector`:

- a per-node `map[fp]*xhAgg` (hosts/countries/subnets/ips/solves), pruned with the
  window like the existing per-`(host, fp)` map — its natural superset;
- a per-`(host, fp)` **share + solves/IP** computation (both already derivable
  from state Phase-1 tracks) to run the admission pre-gate;
- the `MIN_XH_*` / `MAX_XH_SOLVES_PER_IP` / `MIN_XH_HOST_SHARE` evaluation in
  `RunOnce`, sharing the mark, cooldown and alert;
- the `tracks=cross_host` + `xh_*` alert `Extra` fields.

A nil enricher (no GeoIP) leaves `countryFn` nil, which **fail-safe disables**
the country-bearing tracks — cross-host included — exactly as Phase-1 does.

## 7. Config surface (additive to `[challenge_solver_farm]`)

A config predating these inherits the defaults (no upgrade-prompt churn), same as
Phase-1:

| Key | Default | Meaning |
|---|---|---|
| `XH_TRACK` | `1` | enable the cross-host track (kill-switch) |
| `XH_WINDOW` | `10m` | sliding window for cross-host aggregation |
| `MIN_XH_HOSTS` | `4` | distinct vhosts one fp must span (floor) |
| `MIN_XH_COUNTRIES` | `10` | distinct countries under that fp (primary guard) |
| `MIN_XH_SUBNETS` | `30` | distinct `/24` under that fp |
| `MIN_XH_HOST_SHARE` | `0.50` | per-vhost dominance to admit a `(host, fp)` pair |
| `MAX_XH_SOLVES_PER_IP` | `1.10` | aggregate solves/IP ceiling (revisit guard) |

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

- **Positive — thin farm:** replay the `95070673` shape — one fp, ~1 solve/IP,
  ≥ 4 hosts each ≥ 50 % share, ≥ 10 countries and ≥ 30 `/24` node-wide, but
  **< 6 countries in any single host's 60 s window** → Phase-1 stays silent,
  cross-host flags, and **every** contributing vhost is marked.
- **Negative — popular browser across many sites:** one fp on 8 hosts, 1–3
  countries, `solves_per_ip = 1.5`, **≤ 20 % share per host** → does not flag
  (share pre-gate empties the pool).
- **Negative — global-audience dominant browser:** one fp, ≥ 10 countries, but a
  **minority** per host (share < 0.5) and `solves_per_ip > 1.1` → does not flag
  (both added guards).
- **Negative — single busy vhost:** the `c2e09593` shape (49 `/24`, 6 countries,
  but 5 % share, one host) → not pooled cross-host (share + hosts floor).
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
