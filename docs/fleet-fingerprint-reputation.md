# Fleet-shared fingerprint reputation (idea note)

> **⚠️ SUPERSEDED — historical design note, NOT current state.** The canonical,
> as-built reference is the node hub **`docs/traffic-classifier.md`** and the
> central ledger **`cfm-web:docs/fingerprint-reputation.md`**. Kept for
> archaeology; where this note disagrees with the hubs or the code, they win.

> **Status:** IDEA NOTE (cfm-side / node concerns). Captured from a 2026-09-10
> discussion (prompted by BitNinja's JA4H WAF-Pro writeup). The **grounded,
> as-designed implementation now lives in `cfm-web`:
> `chrismfz/cfm-web:docs/fingerprint-reputation.md`** (real schema, ingest,
> Filament, MCP). Read that for the concrete plan; this note is kept for the
> cfm/node-side concerns (what the node publishes) and the reasoning history.
> Owner: challenge/webdetector + cfm-web.
>
> **Two corrections the cfm-web doc supersedes:** (1) §4's "soft, self-healing
> TTL, never permanent" is **wrong for a stable fingerprint** — the record is now
> **durable and never expires**; only a separate, re-armable per-fingerprint
> *policy* carries a TTL (the record keeps the memory, the action expires). (2) The
> node-side prerequisite is spelled out in §5 below: the `challenge_solver_farm`
> finding must reach the durable `detection_history` so cfm-web can PULL it.
>
> Reads first: `docs/solver-farm-fingerprint-concentration.md` (Phase-1, shipped),
> `docs/solver-farm-cross-host-phase2.md` (Phase-2 design), `docs/challenge-score.md`
> (Track-2 seed the fleet already fuses).

---

## 1. The idea

Build a **`fingerprints` model in `cfm-web`** (the central intelligence) and let
the fleet **share "dangerous" client fingerprints — with proof — across servers**,
the same way it already shares the fleet IP blocklist (`check_ip`: "the whole-fleet
list every node pulls"). A node that has never locally seen a given farm can then
**act on its first request**, because another node already convicted the
fingerprint with evidence.

"Fingerprint" here = the client's **TLS ClientHello** id we already stamp
(`c28caa00`, via `X-CFM-TLS` / `tlsfp.Parse` — the JA3/JA4-family sibling), and
later, as a **second independent axis**, its **JA4H** (HTTP-request) fingerprint.

## 2. Why share fingerprints, not just IPs (for this adversary)

The fleet already shares IPs. For the distributed-scraper / solver-farm class,
**fingerprints are the better shared unit**:

- An **IP is ephemeral** — residential/mobile/cloud proxies, one-shot per IP,
  constant rotation. A shared IP verdict has a short useful life.
- A **fingerprint is stable** — it is *why* `c28caa00` works across the farm's
  IP+UA rotation. A shared fingerprint verdict survives the rotation, so it has a
  far longer useful life and reaches farm nodes an IP list never catches in time.

This is the same thesis as the source article ("block the request, not the IP"),
and the same reason cloud-IP blacklisting is a blunt instrument.

## 3. The framing that keeps this honest (propagate verdicts, don't replace detection)

A shared "dangerous fingerprints" list *looks* like the signature-blocklist the
concentration detector deliberately **rejected** ("group-by, never match;
`c28caa00` is a labelled positive, never a value in code"). It is **not** — if
framed as a propagation layer, not a detection layer:

> The **concentration detector produces the proof** (per-node, generalized to any
> single-tool farm by shape). **cfm-web aggregates + shares the verdict.** A second
> node seeing the same fingerprint **acts on the first hit** instead of re-deriving
> concentration locally.

Exactly the existing relationship `local detector → autoblock → shared IP
blocklist`, one layer up. The shared list never *replaces* detection; it
*distributes* a verdict detection already earned. So it does not re-introduce the
brittle "today `c28caa00`, tomorrow another tool" failure — the **detector** still
generalizes; the **reputation table** only remembers what the detector convicted.

## 4. The one catastrophic risk (that the IP list does NOT have)

**A fingerprint is a POPULATION, not an individual.** An IP ≈ one client; a common
iOS/Chrome build's fingerprint = millions of legitimate users. Share a fleet-wide
**block** on a popular-browser fingerprint and you cause a **fleet-wide outage** of
legitimate traffic. This is THE thing to get right, and it is why a fingerprint
reputation list is categorically riskier than an IP one.

Guardrails (all required, not optional):

1. **Only concentration-proof is shareable.** The evidence must be the unforgeable
   farm-vs-shared-browser signal — "this fp spanned N /24 × M countries × ~1
   solve/IP on vhost X at time T" — never "seen doing something once." A bare
   fingerprint is never proof of malice.
2. **Shared action is `challenge`, not `block`.** A challenge is **self-targeting**:
   a legitimate client that happens to share the fingerprint solves it once and
   passes; the farm does not. This neutralises the shared-population risk. A shared
   `block` is the dangerous version — gate it behind far stronger corroboration, if
   ever.
3. **Durable record, re-armable policy** *(corrected — this replaces the original
   "soft, self-healing TTL")*. A fingerprint is **stable**, so forgetting it
   discards its only advantage over an IP: the memory. The **reputation record +
   evidence never expire**; a separate, operator-controlled **per-fingerprint
   policy** carries the action + a TTL (the `blocklists` `ttl`/`expires_at`
   grammar) and is armed/disarmed/**re-armed** without touching the record. "6h"
   becomes one duration *option*, not a mandatory forget. See the cfm-web doc §2.
4. **Corroboration before promote** — a fingerprint reaches shared-enforce only
   after ≥K nodes or ≥N independent evidence rows agree (anti-poisoning: one
   compromised/misconfigured node must not be able to convict a fingerprint
   fleet-wide).
5. **`ALLOW_FPS` operator override**, fail-closed — the auditable escape hatch for a
   known-legitimate shared stack (a monitored synthetic-checker fleet, a corporate
   managed-browser fingerprint).

## 5. Node/edge side (the cfm concerns) — and the one prerequisite

The full data model + ingest + storage + UI + MCP live in the cfm-web doc. What
the **node** owes the pipeline:

```
node   → PERSIST   the challenge_solver_farm FINDING to the durable
                   detection_history as event_type=solver_farm, carrying its
                   evidence in the row's payload_json under normalized,
                   source-agnostic keys (NOT the alert's raw Extra names):
                   fingerprint (the resolved group-by fp — cross-host xh_fp
                   preferred over the per-host top_fp), tracks, solves,
                   distinct_ips, distinct_subnets, distinct_countries,
                   host_share, solves_per_ip, hosts, and ips (a bounded,
                   fingerprint-ACCURATE sample of the client addresses — the
                   fp's own set, never the vhost's whole solver population, so a
                   downstream block can't hit an innocent visitor). host is the
                   row's host column. distinct_ips/subnets/countries describe the
                   FINGERPRINT's own spread (cross-host: node-wide across the
                   dominated vhosts; per-host: the fp on that vhost) so they always
                   satisfy countries≤subnets≤ips — not the vhost-wide totals.
cfm-web ← PULL     that source via the fleet_ingest_cursors / NodeHardFaultIngestor
                   pattern (a new `source` value; no new node API)
...        (cfm-web aggregates → reputation record + policy; see its doc)
nodes  ← PULL      the armed policies, the way each node already pulls the IP blocklist
edge   → MATCH     the request's X-CFM-TLS id (already stamped!) against the armed
                   list → CHALLENGE on match (a new cfm-side check, cheap)
```

**The one cfm-side prerequisite (Phase A):** today the `Challenge/SolverFarm`
finding reaches only `cfm.detector.log` + mail/Slack — **not** the durable,
queryable `detection_history` the PULL ingest reads (that store holds the
underlying `challenge_solved` rows, not the finding). So the node must write the
finding there, as a first-class `solver_farm` event with the evidence above. This
is the only node change Phase A needs; ingest/storage/UI/MCP are all cfm-web.

Two things still make it cheap: **`X-CFM-TLS` stamping already exists** at the edge
(matching a request's fingerprint is nearly free), and the **cursor pull +
blocklist fetch plumbing already exist** — the fingerprint pipeline is a second
collection of the same shape. (Push-to-web was the original sketch; PULL was
chosen — it matches the established pattern and needs no new node API.)

**JA4H as a second axis.** Add the HTTP-request fingerprint (JA4H) alongside the TLS
one. It hashes header structure/order, not the UA string, so it stays stable across
the farm's UA spoofing — two independent fingerprints agreeing makes a shared
verdict materially safer, and gives an L3 fallback if a farm ever randomises its TLS
ClientHello.

**Second source: `challenge_score` (the per-IP shadow scorer).** Beyond the
`solver_farm` finding, the node also PERSISTS its per-IP challenge-abuse verdicts to
the same `detection_history` as `event_type=challenge_score`, so the ledger
accumulates conviction from a second, independent angle (the fingerprint-anchored
per-IP score, not the cross-host concentration proof). To keep the sqlite lean this
is deliberately narrow: only the **`would_deny`** tier is written (the softer
`would_harden` stays log-only, for grep), throttled to **one row per IP per hour**
(a sustained denier is ≤24 rows/day; the fine detail is in the rotated
`cfm.abuse_shadow.log`). The row's `ip` column is the client address; the payload
carries the ingest-contract keys — `fingerprint` (the anchoring TLS fp: the convicted
solver-farm fp when one drove the score, else the fp merely present on the scored
solves, `""` when no `X-CFM-TLS`), `fp_convicted` (which of those it is, so a
convicted-fp row can outweigh a present-fp one), `score`, `verdict`, and the tell
breakdown (`solves`/`fast`/`uaimp`/`farm`/`farmfp`). cfm-web PULLs it through the SAME
cursor machinery as `solver_farm` (a second `source` value) and folds it into the same
per-fingerprint reputation — no new node API, no push. An empty-`fingerprint` row is a
durable, IP-anchored deny that is simply not fingerprint-attributable (same convention
as a subnet-spread-only `solver_farm` row). Implemented node-side in
`challenge_score_history.go`; the cfm-web pull-ingest is the follow-up half.

## 6. Rollout

Shadow-first, same discipline as everything else: shared verdicts land as **`watch`**
(log-only, fleet-wide visibility) first, then **`challenge`** after the numbers prove
clean, and **`block`** only if ever, behind the strongest corroboration. Kicks off
**after** the Phase-1 fp-concentration burn-in confirms the concentration proof
itself is FP-clean — there is no point sharing a verdict we are still validating.

## 7. Open questions / decisions to make when we pick this up

- **Fingerprint coarseness.** TLS fps (JA3/JA4/`c28caa00`) are buckets, not
  identities (GREASE-normalised, so many clients collapse to one value). Prefer the
  **combined** key (TLS fp + JA4H, maybe + ASN-class) before any enforce; carry
  confidence; keep `challenge` the default action precisely because of this.
- **Who may publish, and trust.** Verdicts carry provenance (node + evidence);
  cfm-web decides the corroboration threshold; operators can override. Same
  fail-closed posture as the scoped-auth boundary.
- **Retention / decay** *(resolved — see cfm-web doc §9).* The **record does not
  decay** (a stable fingerprint is worth remembering); the *evidence log* may be
  pruned like `agent_events` (30 days) while the rollup persists, and enforcement
  decays via the *policy* TTL, not the record. "Decay out" was the old
  soft-TTL-forget thinking — corrected.
- **Relationship to Track-2 seed.** This is arguably the fleet-global generalisation
  of the `solver_farm` seed in `docs/challenge-score.md` §4 — decide whether it
  feeds the per-client score or stands beside it.
- **Repo boundary.** Model + ingest + storage + UI + MCP live in
  `chrismfz/cfm-web` (design: `cfm-web:docs/fingerprint-reputation.md`, merged);
  the node-side finding-persist + the edge X-CFM-TLS match live in `cfm` (§5).
