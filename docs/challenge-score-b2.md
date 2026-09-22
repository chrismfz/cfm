# Track-2 Stage 1b/B2 — post-clearance edge tell: scope note

> **▶ RETIRED 2026-09-22 (operator-ratified).** `cfm_pcw` shipped, ran
> log-only for its whole life, and **fed no decision** — so it was removed:
> the Lua module, its `cfm.lua` Step-2b wiring, the `cfm_pcw` shared dict in
> both edge confs, the `[webdetector] POST_CLEARANCE_CADENCE` key and the
> bridge-config field that published it. This file is KEPT as the decision
> record — §1/§2 below are the durable lesson (why the "cleared then silent"
> tell is structurally unobservable at this edge), and they are the reason not
> to re-propose it. Cleared traffic is already visible to `rate_outlier` in
> the access log. Current plan: `docs/abuse-defense-master-plan.md` §3 row 8.
>
> **Status (historical):** DESIGN NOTE (pre-code), written after grounding B2 in the actual
> edge config + `cfm.lua`. It exists because the master plan's assumed B2
> mechanism ("cleared then silent — no follow-up asset fetch",
> `docs/challenge-score.md` §1/§4) turns out **not to be cleanly observable at the
> edge Lua**. Read `docs/challenge-score.md` first. Owner: challenge/edge.

## 1. What the edge Lua actually sees for a cleared client (grounded)

The clearance short-circuit is `cfm.lua` **Step 2b** (`configs/lua/cfm.lua:1385`):
a valid-clearance request is waved to origin and the `/nginx/decision` RPC is
skipped — so any per-client measurement/actuation for a cleared abuser must be
**edge-local** (`docs/challenge-score.md` §2). But *which* of that client's
requests even reach `cfm.lua`?

| Request kind | Runs `cfm.lua`? | Where |
|---|---|---|
| Navigations (HTML pages, pretty-URLs, `.php` pages) | **YES** | `location /` + PHP `location` (`openresty.conf:788`, no bypass) |
| Dynamic / AJAX / API (`.php`, `/wp-admin/`, `admin-ajax.php`, `wp-json`) | **YES** | PHP `location` runs the server-level `access_by_lua_file` |
| SVG | **YES** | deliberately excluded from the static bypass (can carry script) |
| **Static assets** (css, js, woff/woff2, ttf, eot, png, jpg, gif, webp, ico, map) | **NO** | static-asset bypass `access_by_lua_block { return; }` (`openresty.conf:846`) streams straight to origin, Lua-free for performance |

So `cfm.lua` sees a cleared client's **navigations and dynamic calls**, but **never
its static-asset fetches**.

## 2. Why the design's "asset-silence" tell does not fit

The design's tell was "a real browser fetches assets after solving; a farm does
not." Two independent problems:

1. **Static assets bypass `cfm.lua` entirely** (table above). If we armed a
   tripwire on a cleared nav and expected to see an asset fetch disarm it, we
   would *never* see the asset — so **every real browser would look "silent"** →
   mass false positives. The signal is structurally invisible at Step 2b.
2. **Even if we instrument the bypass location** with a cheap `ngx.shared` stamp,
   **browser caching** re-breaks it: a real user reading a long page whose CSS/JS
   is already cached refetches *no* assets on the next click, so a genuine browser
   revisiting looks "silent." The discriminator is fragile precisely where we need
   it robust.

Conclusion: asset-silence is the wrong mechanism for this architecture. Drop it.

## 3. Candidate edge-observable post-clearance tells

Assessed against: **observable** at Step 2b? **FP risk**? **novel** vs signals we
already have (Track-1 `rate_outlier`/`facet` log-driven; Stage-1a `challenge_score`
daemon; `cookie_discard`)? **cost/risk** to build?

| Candidate | Observable | FP risk | Novelty | Verdict |
|---|---|---|---|---|
| **A. Post-clearance nav-burst cadence** — cleared client's nav rate per window | YES (navs run `cfm.lua`) | Medium — needs a *sustained, human-implausible* threshold (a cleared human clicking fast is the FP); cache-immune | Overlaps log-driven `rate_outlier`, but **scoped to the cleared subset** + **edge-local** (the enforcement blind spot) | **Lead candidate** |
| B. Nav-to-dynamic ratio — many navs, never an AJAX/API call | YES | **High** — static/brochure/blog sites where real users load pages with zero AJAX look identical to scrapers; app-dependent | High but unusable | Reject |
| C. Edge issuance cadence — same IP pulls many *fresh* challenges/h | YES (at challenge issuance, not Step 2b) | Low–Med | Overlaps `cookie_discard` (already a planned daemon seed for the score) | Defer to the cookie_discard seed |
| D. Per-client faceted-URL expansion among cleared clients | YES | Med | Overlaps Track-1 `facet_expansion` (log-driven, per-vhost) | Redundant |

## 4. The honest tension

The daemon's **log-driven** engine already sees cleared navs (they are in the
access log), so Track-1 `rate_outlier`/`facet` *already score* cleared
scraper traffic. What the daemon **cannot** do is **act in-path** on a cleared
client (Step 2b skips the decision RPC). So B2's genuine, non-redundant value is
**not** "observe something new" — it is **measure the cleared-subset cadence
edge-locally**, which is the groundwork the eventual edge-local actuator (Stage E)
needs and which quantifies "how much cleared traffic is scraper-shaped" for the
burn-in.

## 5. Recommendation

Two viable paths; both are defensible, pick by appetite:

- **B2-lean (recommended): a post-clearance request-cadence shadow counter.**
  At Step 2b, count a cleared client's `cfm.lua`-visible requests (navs + dynamic)
  per rolling window keyed by `(ip[,host])` in a dedicated bounded `ngx.shared`
  dict; when a cleared client sustains a human-implausible rate, emit
  `[cfm_pcw] post_clearance_burst … verdict=would_harden|would_deny` to the edge
  error log (read via `edge_error_tail`). Shadow-only, cache-immune, no asset-path
  change, `pcall`-guarded so it can never break the clearance fast-path, behind a
  config toggle (`[webdetector] POST_CLEARANCE_CADENCE`). It fills the decision-skip
  blind spot edge-locally and is the direct groundwork for the Stage-E edge
  actuator. Small, single-concern.

- **B2-skip → go to B3 (the hybrid seed map).** Since the cadence overlaps
  `rate_outlier`, an alternative is to skip a standalone B2 and invest in **B3**:
  publish the signals we ALREADY have (Stage-1a `challenge_score` + B1
  `WAF_FETCH_METADATA` + `cookie_discard` + `solver_farm`) into an edge-read seed
  map and fuse them edge-locally — the convergence + edge-local scoring the whole
  Stage-1b arc is building toward. Higher value per unit work, but a bigger change.

Either way, the asset-silence tell is retired. `docs/challenge-score.md` §1/§4
should be updated to reflect that the edge post-clearance tell is **cadence**, not
asset-silence, once we choose.

## 6. Decision & as-built (B2-lean)

**Chosen: B2-lean.** Shipped as `configs/lua/cfm_pcw.lua` (pure logic) wired at
`cfm.lua` Step 2b, log-only:

- Counts a cleared identity's **top-level navigations** per fixed 60 s window in a
  dedicated bounded `cfm_pcw` shared dict (declared in both edge confs). `is_nav` =
  GET|HEAD, not prefetch/prerender (`Sec-Purpose`/`Purpose`), and — when
  `Sec-Fetch-Dest` is present — `document` only (same-origin iframes/embeds and
  every asset dest excluded); header absent (older browsers + the headless
  automation we most want to measure) falls back to `Accept: text/html`. AJAX/JSON
  and static assets never count.
- **Keyed `(ip, host, scope)`** — the grain clearance is minted at
  (`HMAC(ip,host,scope)`), so counting is per-IP-per-host and one IP's traffic to
  different hosts does not pool. **Known FP class:** the cookie is not a per-browser
  identity, so a shared egress (CGNAT / office NAT) where many real users are
  cleared for the SAME host still pools into one counter and can exceed the
  thresholds from legitimate traffic — acceptable for a log-only shadow, but **B3
  must make the score NAT-aware** (the §7 `ALLOW_NETS`/`IGNORE_IPS` + NAT guardrail)
  before this gates traffic. It is a per-IP-per-host signal, **not** "per-client".
- Emits `[cfm_pcw] post_clearance_burst ip=… host=… navs=… window=60 verdict=…`
  to the edge error log at ≥30 navs/window (`would_harden`) and ≥60
  (`would_deny`), throttled to one line per `(ip, host, verdict)` per 5 min. Read
  via `edge_error_tail`.
- **Safety:** never blocks/challenges/changes flow; the Step-2b call is
  `pcall`-guarded so a bug can't break the clearance fast-path (an adversarial
  review confirmed no path alters flow or adds latency); the shared dict is bounded
  + short-TTL (self-cleaning); default ON with a config toggle
  (`detectors.conf [webdetector] POST_CLEARANCE_CADENCE = 0` disables it, published
  to the edge via `cfm_bridge_config.lua` on the 10s bridge TTL — no proxy reload).
  Thresholds/window are in-code burn-in constants.
- `docs/challenge-score.md` §1/§4/§10 updated; the asset-silence tell is retired.

**Known blind spot (false-negative).** Because `is_nav` counts only top-level
document navigations, a scraper that pulls page HTML via `fetch()`/XHR
(`Sec-Fetch-Dest: empty`, or a non-`text/html` Accept) is **not** counted — a
common scraping pattern, so a signal-aware farm dodges trivially. This is inherent
to the "count navs, not AJAX, to avoid FP" tradeoff and acceptable for a log-only
burn-in that sizes naive-navigation cadence. The daemon's log-driven `rate_outlier`
still sees such clients (all requests are in the access log); B2's role is the
edge-local per-cleared-identity accumulator, not an evasion-proof detector.

B3 (the hybrid seed map) later fuses this edge accumulator with the daemon seed
(Stage-1a `challenge_score` + B1 `WAF_FETCH_METADATA` + `cookie_discard` +
`solver_farm`) into one edge-local per-client score.
