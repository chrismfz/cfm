# Fleet-shared fingerprint reputation (idea note)

> **Status:** IDEA / DESIGN NOTE — pre-code, **Phase 2+**, to revisit **after the
> solver-farm fp-concentration burn-in** settles. Captured from a 2026-09-10
> discussion (prompted by BitNinja's JA4H WAF-Pro writeup). **No code yet, and
> deliberately not touching the `chrismfz/cfm-web` repo yet** — this note lives in
> the `cfm` repo so we don't lose the design while the burn-in runs. Owner:
> challenge/webdetector + cfm-web.
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
3. **Soft, self-healing TTL** (like the 6h autoblock), never `permanent`.
4. **Corroboration before promote** — a fingerprint reaches shared-enforce only
   after ≥K nodes or ≥N independent evidence rows agree (anti-poisoning: one
   compromised/misconfigured node must not be able to convict a fingerprint
   fleet-wide).
5. **`ALLOW_FPS` operator override**, fail-closed — the auditable escape hatch for a
   known-legitimate shared stack (a monitored synthetic-checker fleet, a corporate
   managed-browser fingerprint).

## 5. Architecture sketch (aligned to the existing `check_ip` pattern)

```
cfm-web:  fingerprints model
  { fp, ja4h?, first_seen, last_seen,
    evidence[]{ node, host, subnets, countries, solves_per_ip, ts },
    confidence, verdict: watch | challenge | block, ttl,
    source_nodes[], operator_override }

nodes  → PUBLISH   a conviction (solverfarm concentration verdict + evidence),
                   the same way the detector framework already reports autoblocks
cfm-web → AGGREGATE + promote  (corroboration gate → verdict + soft TTL)
nodes  ← PULL      shared verdicts, the way each node already pulls the IP blocklist
edge   → MATCH     the request's X-CFM-TLS id (already stamped!) against the shared
                   list → CHALLENGE on match (a new cfm-side check, cheap)
```

Two things make this cheap: the **`X-CFM-TLS` stamping already exists** at the edge
(matching an incoming request's fingerprint is nearly free), and the
**publish/aggregate/pull plumbing already exists** for the IP blocklist — this is a
second collection of the same shape.

**JA4H as a second axis.** Add the HTTP-request fingerprint (JA4H) alongside the TLS
one. It hashes header structure/order, not the UA string, so it stays stable across
the farm's UA spoofing — two independent fingerprints agreeing makes a shared
verdict materially safer, and gives an L3 fallback if a farm ever randomises its TLS
ClientHello.

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
- **Retention / decay.** A fingerprint that stops offending should decay out
  (soft TTL + last_seen), so the list tracks live threats, not history.
- **Relationship to Track-2 seed.** This is arguably the fleet-global generalisation
  of the `solver_farm` seed in `docs/challenge-score.md` §4 — decide whether it
  feeds the per-client score or stands beside it.
- **Repo boundary.** The model + aggregation live in `chrismfz/cfm-web`; the
  publish/pull/edge-match live in `cfm`. Not started on either yet — this note is
  the placeholder.
