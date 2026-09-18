# Solver-farm detection — fingerprint-concentration (low-and-slow) track

> **⚠️ SUPERSEDED — historical design note, NOT current state.** The canonical,
> as-built reference is the node hub **`docs/traffic-classifier.md`** and the
> central ledger **`cfm-web:docs/fingerprint-reputation.md`**. Kept for
> archaeology; where this note disagrees with the hubs or the code, they win.

> **Status:** DESIGN NOTE (pre-code). Extends the existing
> `challenge_solver_farm` detector (`internal/detectors/solverfarm/detector.go`)
> with a **second, complementary** track that catches a *low-and-slow* farm the
> current subnet-spread threshold structurally misses. Grounded on a live capture
> (`c28caa00` on `techking.gr`, 2026-09-08). Read `docs/challenge-score.md`
> (Track-2, the per-client score this feeds) and `docs/traffic-classifier.md`
> (master plan) first. Owner: challenge/webdetector.

All signals here ship **shadow/log-only first** (the parent detector is
alert-only by construction). `logonly → alert → seed` promotion, never a block:
at ~1 solve per IP a per-IP ban is useless and residential-risky — see the
`solverfarm` package doc.

---

## 1. What already exists, and why it missed this farm

`challenge_solver_farm` (`internal/detectors/solverfarm/detector.go`,
registered in `internal/detectors/challenge_solver_farm_register.go`) is already
the right *kind* of detector and is **deliberately fingerprint- AND UA-agnostic**:

- It aggregates the **challenge-solve event stream** (`SubscribeChallengeSolveEvents`)
  by **distinct client `/24` subnets solving one vhost within a sliding 60 s
  window** (`MIN_SUBNETS = 40`, `MIN_SOLVES = 40`, `EVERY = 30 s`).
- The key is the **spread of solvers**, never the User-Agent: the package doc is
  explicit that UA is attacker-controlled and is carried as *evidence*, never as
  the detection key.
- Calibrated against 23 h of production traffic containing a live farm:
  distinct `/24`s per 60 s window measured **median 73 / p01 49 / max 110** for
  the farm vs **max 22–27** across every other vhost. `MIN_SUBNETS = 40` caught
  1380/1381 farm-minutes with **0** hits on 1605 legitimate vhost-minutes — a
  ~1.5× margin over the busiest legitimate vhost.
- Alert-only: `ip_scope=host` + `enforcement=observe`; `ACTION` ∈ {observe,
  logonly}; `deny`/`block` reserved-and-refused with the reasoning in the package
  doc.

**The gap.** That calibration assumes a *fast* farm (~110 solves/min). The farm
captured on 2026-09-08 is **low-and-slow**: **~8.2 solves/min** on `techking.gr`
(59 solves over 7.2 min, measured from `detection_history`). In any 60 s window
that is **~8 distinct subnets** — far under `MIN_SUBNETS = 40`. So
`challenge_vhosts` shows `techking.gr` `solver_farm: false` and the detector is
**correctly silent by its own threshold**.

We **cannot** simply lower `MIN_SUBNETS`: legitimate vhosts reached **22–27**
distinct `/24`s per 60 s in the calibration set, so a bar near 8 would
false-positive on a genuinely global mobile audience. A different *discriminator*
is needed for the low-rate regime — not a lower count of the same one.

## 2. The discriminator: fingerprint **concentration**, not a signature

The low-and-slow farm hides under the subnet-count bar, but it exposes a
different invariant: **its solvers, however widely spread across IPs and
countries, collapse onto a single client fingerprint.** A real audience of the
same size is fingerprint-*diverse*.

> **Group-by, never match.** The rule is *not* `fp == "c28caa00"`. It is: group a
> vhost's in-window solves **by whatever fingerprint each carries**, and flag when
> a **single fingerprint** spans an implausible spread of subnets **and**
> countries. `c28caa00` is today's instance; it is a **labelled positive** for
> calibration and tests, **never** a value in the code.

Why this is inherently **fingerprint-agnostic** — directly answering "today it's
`c28caa00`, tomorrow another tool":

- **New tool → new single fingerprint × wide spread → trips identically.** The
  detector never learns or names any fingerprint value; it measures the *shape*
  (one fp, many networks, many countries), which every single-stack solver farm
  produces regardless of which stack it is.
- **The FP-guard is diversity, and it is unforgeable by legitimate traffic.** A
  real population of N solvers has ~N fingerprints and is geographically
  clustered per network. A farm is **1 fingerprint × N subnets × many
  countries** — a combination no honest audience produces. See §6.

## 3. Arms race — this is one invariant in a layered framework

The user's concern is the right one, so the design is explicitly **layered** and
**mechanism-agnostic**, not a single brittle line:

| Adversary move | What still catches it |
|---|---|
| **L0 — today:** one stack, one fingerprint, spread across a proxy pool | **this track** (fingerprint concentration), even at ~8 solves/min |
| **L1 — swaps tool:** new single fingerprint | **this track, unchanged** — it keys on concentration, not the value |
| **L2 — goes loud:** ramps to 40+ subnets/60 s | the **existing** subnet-spread rule (fp-blind) |
| **L3 — randomises the fingerprint per connection** (e.g. uTLS ClientHello shuffling) | concentration collapses → fall back to **behavioural invariants** the farm still shares: solve-latency clustering, catalogue-walk (pagination/faceting on one vhost), the UA-vs-TLS-version mismatch, and the aggregate "many one-shot residential IPs solving one vhost in a tight window" |

Fingerprint concentration is the **cheapest** invariant that catches the current
adversary; the framework leaves room to add the L3 behavioural invariants as
their own scored sub-signals when a fingerprint-randomising farm actually
appears. We build L0/L1 now (grounded, real), and note L3 as future work rather
than speculatively coding it (CLAUDE.md: never write a signature from a threat we
cannot yet see).

## 4. Grounding — the `c28caa00` capture (2026-09-08, `techking.gr`)

From `detection_history type=challenge_solved host=techking.gr` (durable log):

- **~59 `challenge_solved` in 7.2 min** (08:20:40 → 08:27:53 UTC) ⇒ **~8.2/min**.
- **One TLS fingerprint `c28caa00` across the entire farm** — every solve but one.
- **~50 distinct IPs, each a different country**: Brazil (many), Mexico,
  Argentina, Nepal, Syria, Vietnam, South Africa, Nigeria, Ukraine, Kazakhstan,
  Bangladesh, Oman, Colombia, Russia, Spain, Cambodia, Türkiye, Bolivia,
  Uzbekistan, Pakistan, Chile, Paraguay, Congo, Kenya, Portugal, Belgium… —
  residential / mobile ASNs (a proxy network).
- **UA rotation, TLS constant**: User-Agents span Chrome 135–149 on both Windows
  and macOS, yet the TLS ClientHello fingerprint is *identical* — the tell that
  the UA is decoration and one stack is behind all of them.
- Solves the PoW (`diff 16`) in **427–2115 ms** and walks the **product
  catalogue** (`θήκη-…` case SKUs, `?page=N`, `?manufacturer_id=N`).

**The built-in negative control.** In the same window sits one *real* visitor:
`141.255.120.79`, Greece / Vodafone, iPhone `CriOS`, fingerprint **`77a50fbb`**
(different), solve **9700 ms** (human-plausible), hitting `/` — not the catalogue.
Different fingerprint, different geography, different behaviour: the discriminator
separates it cleanly. This single legitimate solve is the smallest proof that
concentration — not rate, not UA — is the right axis.

## 5. Design — a low-rate track on the existing detector

Add a second evaluation to `solverfarm.Detector`, sharing its ingest, window,
pruning, cooldown, allow-lists, and alert plumbing. **No new detector, no new
event stream.**

### 5.1 Per-fingerprint state (in addition to the per-host subnet set)

Within each host's window, maintain per **fingerprint**:

- `subnets` — distinct client `/24` (v6 `/48`) seen under this fp
- `countries` — distinct ISO-2 of the solving IPs under this fp *(corroborator;
  see §7 on plumbing)*
- `solves`, and a small evidence sample

The existing per-host `subnets`/`ips` sets and the `MIN_SUBNETS = 40` rule stay
exactly as they are (the L2 high-rate path). Both paths raise the **same**
`Challenge/SolverFarm` finding and the same "farmed right now" mark
(`webdetector.MarkSolverFarm`), so downstream (WebUI badge, the Track-2 seed in
`docs/challenge-score.md` §4) needs no change.

### 5.2 Low-rate verdict (fingerprint-concentration)

Flag a `(host)` when **some single fingerprint** in the window satisfies **all**:

- `fp.subnets  ≥ MIN_FP_SUBNETS`   (**8** — calibrated, §5.3)
- `fp.countries ≥ MIN_FP_COUNTRIES` (**6** — the load-bearing FP-guard, §5.3)
- `fp` is **usable**: non-truncated and GREASE-normalised (§7); the empty/`-`
  fingerprint (edge could not stamp one) is **never** a group key — it would pool
  unrelated clients into a phantom "farm". (Confirmed necessary: a real
  no-fingerprint group `ligaapola.gr × (none)` reached 3 countries in the capture.)

Corroborating stats carried on the alert (never in the threshold): `max_fp_share`
= top-fp solves ÷ window solves, `distinct_fps`, `solves_per_ip`, top UA share,
`impossible_ua` count. On the `c28caa00` capture `max_fp_share ≈ 1.0`,
`distinct_fps ≈ 1`, `solves_per_ip ≈ 1.0`.

The two thresholds are **AND**ed on purpose: subnet-spread rules out a single
busy client; country-spread rules out a single-country CGNAT/proxy that happens
to share a client stack (§6).

### 5.3 Calibration — measured fleet-wide (2026-09-08)

Two fleet snapshots of the `challenge_solved` stream (titan single-node, 172 min,
2000 solves; and an 11-node fan-out) aggregated per `(host, fp)` with a 60 s
sliding-window peak. Distinct **countries under one fingerprint per 60 s** is the
separating axis:

| `(host, fp)` | class | /24 (60 s peak) | **countries (60 s peak)** | solves/IP |
|---|---|---:|---:|---:|
| `techking.gr × c28caa00` | farm | 33 | **22** | 1.00 |
| `karol.gr × c28caa00` | farm | 10 | **10** | 1.00 |
| `www.mathematica.gr × 95070673` | farm (2nd fp) | 4 | 3 | 1.04 |
| `www.anastasiadi.gr × ba6b4aad` | **legit near-FP** | 17 *(over 5 min)* | **2** | 1.05 |
| `* × 77a50fbb` (common iOS) | legit | ≤2 | **≤1 per host** | ~1.3 |

**Farms sit at 10–22 countries/60 s; every legitimate group observed sits at
≤3.** `MIN_FP_COUNTRIES = 6` splits them with a ~2× margin — the same
methodology and margin the parent's `MIN_SUBNETS = 40` was set with.
`MIN_FP_SUBNETS = 8` is a floor against a trickle; it is **not** the
discriminator — `www.anastasiadi.gr × ba6b4aad` reached **17 `/24`s** yet is
legitimate, and only the country guard (2 countries) excludes it.

**Fingerprint-agnostic, vindicated by the data:** the capture holds **two**
distinct farm fingerprints — `c28caa00` (60 vhosts, ~58 countries fleet-wide)
**and** `95070673` (36 vhosts, 15 countries). A rule keyed on `c28caa00` would
already be blind to `95070673`; the concentration metric flags both by shape.

**Known low-rate residue → Phase 2 (designed):** `95070673` is spread so thin
*per vhost* that the per-`(host, fp)`/60 s test does not reach `MIN_FP_COUNTRIES`
there (measured per-host 60 s country-peak ≤ 6, `1` on most hosts), even though
the fingerprint is unmistakably a farm **per node** (23 vhosts, 41 countries,
~1.05 solves/IP, 83–100 % of each targeted vhost's solves on the 2026-09-09
capture). Catching that regime needs a **cross-host, per-fingerprint**
aggregation with a per-vhost dominance + `solves_per_ip` pre-gate — designed in
`docs/archive/solver-farm-cross-host-phase2.md`. The first cut catches the aggressive,
single-vhost-heavy farm (`c28caa00` on its main targets) cleanly; the thin
cross-host farm is a documented follow-up, not a reason to hold the first shadow
deploy.

## 6. False-positive analysis (the load-bearing part)

The one realistic FP is **a legitimate population that shares a fingerprint** —
e.g. a corporate fleet of managed identical browsers, or a mobile carrier's
CGNAT where many users egress the same in-app-browser stack.

- **Subnet-spread alone** could FP here (an office/CGNAT can hold several `/24`s).
- **Country-spread is the guard.** A corporate fleet or a carrier CGNAT is
  **one country** (or a small handful). A residential-proxy farm is **dozens**.
  `MIN_FP_COUNTRIES` is precisely the axis a legitimate shared-fingerprint
  population cannot cross. **Observed, not hypothetical:** the 2026-09-08 capture
  contains exactly this near-FP — `www.anastasiadi.gr × ba6b4aad` spread across
  **17 `/24`s** (it would clear any subnet-only bar) yet stayed at **2
  countries**, and the common iOS fingerprint `77a50fbb` appeared on 17 vhosts but
  never exceeded ~1 country *per host*. Both are excluded by the country guard;
  the `c28caa00` farm crossed 22 countries in a single 60 s window.
- **Verified good bots** are already excluded upstream by the challenge/PTR layer
  (they are exempted from the challenge, so they do not appear in the solve
  stream), and the parent detector's `ALLOW_HOSTS/IPS/NETS/UA_CONTAINS` still
  apply. Add `ALLOW_FPS` for a known-legitimate shared fingerprint (e.g. a
  monitored synthetic-checker fleet) — the deliberate, auditable escape hatch.
- **`solves_per_ip`** stays a sanity check: a real repeat-visitor population sits
  well above 1.0; a farm sits at ~1.0 by construction.
- **Residual risk — a globally popular browser under a persistent challenge.**
  The country guard's premise (a shared-fingerprint population is geographically
  clustered) holds for corporate/CGNAT pools but weakens for a vhost whose
  *legitimate* global audience is large AND under a persistent challenge
  (under-attack mode): the dominant browser's fingerprint can then span many
  countries honestly. In the 2026-09-08 capture no legitimate group exceeded 3
  countries per window (the challenged vhosts had no such audience), but the case
  is not excluded by construction — it is the signal to watch in burn-in. Because
  the track is alert/shadow-only it surfaces as a would-alert, never a block, and
  the levers are: raise `MIN_FP_COUNTRIES`, or add a `max_fp_share` guard (the
  flagged fingerprint must be a super-majority of the vhost's window solves — a
  farm's is ~100%, a legit dominant browser a minority), the natural next
  refinement if burn-in shows this. Re-confirm on a high-traffic global vhost
  before the numbers ever gate enforcement.

Because the whole track is **alert/shadow-only**, a mis-tuned threshold *reports*
a vhost, it never blocks one. Thresholds move to enforcement only after a
shadow burn-in the way every other CFM signal does.

## 7. Plumbing (small; the infrastructure already exists)

The fingerprint is **already captured** — it just is not delivered to the
detector:

- **`ChallengeSolve.TLSFP`** (`internal/webdetector/challenge_server.go`) already
  holds a short id for the client's TLS ClientHello, stamped by the edge via the
  `X-CFM-TLS` header and parsed by `tlsfp.Parse` (which exposes `GREASE` and
  `Truncated` and maintains a first-seen dictionary). GREASE is already
  normalised — that is *why* `c28caa00` is stable across the farm's connections.
- **`ChallengeSolve.InputEvent()`** (`internal/webdetector/challenge_solve_events.go`)
  maps `Scope/SrcIP/UA/Signal` into `core.InputEvent` but **drops `TLSFP`**.

Changes (as built):

1. `core.InputEvent` (`internal/detectors/core/input_event.go`): added
   `Fingerprint string` — one new field. Country is **not** on the envelope; it
   is enriched inside the detector (below), keeping the shared event minimal.
2. `ChallengeSolve.InputEvent()`: sets `Fingerprint: s.TLSFP`.
3. `solverfarm.Detector`: a `SetEnricher(*enrich.Enricher)` method the detectors
   manager already auto-wires (`manager.go` asserts the interface), which builds
   a `countryFn` from `LookupGeoFast().CountryISO` (Country/ASN only, no blocking
   rDNS). Country is looked up in `RunOnce` — off the hot `Enqueue` path — only
   for fp-bearing solves. A nil enricher leaves `countryFn` nil, which
   **fail-safe disables** the track (it can never fire without confirming
   geographic spread). The detector adds a per-`(host, fp)` aggregation (distinct
   subnets + countries, pruned with the window), the
   `MIN_FP_SUBNETS`/`MIN_FP_COUNTRIES` evaluation alongside the existing subnet
   rule (sharing its mark, cooldown and alert), and the
   `fp_track`/`top_fp`/`fp_subnets`/`fp_countries`/`tracks` alert `Extra` fields.

**Usability filter (as built).** The empty fingerprint is never a group key (it
would pool unrelated clients). GREASE is already normalised into `TLSFP` by
`tlsfp.Parse` at the edge — which is *why* `c28caa00` is stable — so no GREASE
handling is needed here. The `Truncated` flag is **not** carried on
`ChallengeSolve` today (only the `TLSFP` id is), so v1 does not separately
exclude a truncated fingerprint; this is acceptable (truncated ClientHellos are
rare and cannot plausibly reach the AND of the subnet and country floors by
collision), and carrying the flag to exclude them is a small follow-up.

## 8. Config surface (new keys on `[challenge_solver_farm]`)

Additive to the existing section (`DefaultsTemplate` in the register); a config
predating them inherits the defaults, so no upgrade prompt churn:

| Key | Default (proposal) | Meaning |
|---|---|---|
| `MIN_FP_SUBNETS` | `8` | distinct `/24` under one fingerprint to flag the low-rate track |
| `MIN_FP_COUNTRIES` | `6` | distinct countries under that fingerprint (the FP-guard) |
| `FP_TRACK` | `1` | enable the concentration track (kill-switch) |
| `ALLOW_FPS` | *(empty)* | fingerprints exempt from the track (known-legit shared stacks) |

These defaults are **calibrated on the 2026-09-08 fleet capture** (§5.3), not
guesses: farms measured 10–22 countries/60 s under one fingerprint, every
legitimate group ≤3, so `MIN_FP_COUNTRIES = 6` carries a ~2× margin. The unit
test replays that capture at its original timestamps (the detector already
supports an injectable `nowFn`) as the labelled positive, with the
`ba6b4aad`/`77a50fbb` groups as the negatives — the same methodology the
`MIN_SUBNETS = 40` figure was set with. Re-confirm against a fresh capture before
the numbers ever gate enforcement.

**Default-on, log-only through burn-in.** `FP_TRACK` defaults to `1`, so the
track arms on the next binary upgrade for every `[challenge_solver_farm]` section
(the parent detector is itself on-by-default). It never blocks, and an
fp-concentration-**only** finding is **log-only** — it writes `cfm.detector.log`
but sends **no notification** — so a new signal (whose global-audience FP class
is not yet fully mitigated, §6) cannot mail operators fleet-wide on upgrade; it
is not the silent-BLOCK arm CLAUDE.md §6 warns of. The proven subnet-spread track
still notifies per `ACTION`, and a **combined** finding (both tracks — a confirmed
high-rate farm) notifies too. Promote fp-only findings to notify after burn-in
confirms the thresholds; `FP_TRACK = 0` turns the track off entirely.

## 9. Test plan

Unit tests (`internal/detectors/solverfarm/detector_test.go`, replayed via
`nowFn`):

- **Positive:** replay the `c28caa00` shape — ~8 solves/min, one fp, ≥8 subnets,
  ≥6 countries in a window → low-rate track flags; `max_fp_share ≈ 1.0`.
- **Negative — diversity:** same subnet/country spread but **one fp per solve**
  (a real global audience) → does **not** flag (fp diversity high).
- **Negative — single-country CGNAT:** one fp, ≥8 subnets, **1 country** → does
  **not** flag (country guard).
- **Negative — busy legit vhost:** the calibration negative → neither track flags.
- **Control:** the `77a50fbb` legitimate solve inside a farm window does not by
  itself move any threshold.
- **Regression:** the existing `MIN_SUBNETS = 40` fp-blind path is unchanged (the
  23 h calibration assertions still hold); the empty/truncated fingerprint is
  never a group key.

## 10. Actuation (out of scope here — deferred, shared with Track-1)

This track only *identifies* a low-and-slow farm; **what to do** about it is the
Stage-E decision shared with the vhost lane (`docs/challenge-score.md` §5/§6).
For the solver-farm class specifically, that doc already notes **ChallengeV2 (an
interactive drag/puzzle) is the right soft rung** — PoW is pure CPU that a farm
solves trivially, while interaction/rendering is what a headless stack lacks.
The mark this track raises becomes the **`solver_farm` daemon seed** already
budgeted in the per-client score (`docs/challenge-score.md` §4, `+5/solve`),
spreading guilt to the swarm's solving IPs. No enforcement lands from this doc.

## 11. Non-goals / decisions to confirm in review

- **Not** a per-fingerprint block — same reasoning as the parent (residential,
  ~1 solve/IP). Alert + seed only.
- **Country vs ASN** as the spread axis: country is the clearer FP-guard and
  cheaper to explain; ASN is finer but noisier. Recommend country; confirm in
  review.
- **Where country enrichment happens** (detector vs event envelope) — §7.
- **L3 (fingerprint randomisation)** behavioural invariants are **future work**,
  built only when such a farm is actually observed — not written speculatively.

---

### Grounding references

- Existing detector: `internal/detectors/solverfarm/detector.go`,
  `internal/detectors/challenge_solver_farm_register.go`.
- Solve event + fingerprint: `internal/webdetector/challenge_solve_events.go`
  (`InputEvent()`), `internal/webdetector/challenge_server.go`
  (`ChallengeSolve.TLSFP`, `X-CFM-TLS`, `tlsfp.Parse`),
  `internal/detectors/core/input_event.go`.
- Live capture: `detection_history type=challenge_solved host=techking.gr`,
  2026-09-08 (`c28caa00`; control `77a50fbb`).
- Feeds: `docs/challenge-score.md` (Track-2 per-client score),
  `docs/traffic-classifier.md` (master plan), `docs/roadmaps/challenge-engine.md`.
