# `what's_wrong` — from triage to root-cause engine

Single source of truth for where the flagship triage tool is going: the
**contract** every health domain reports through, the **hard constraints** that
keep it cheap and honest, the **root-cause correlation** model, and the
**definition-of-done** matrix that decides when we call it "v1 complete".

Scope is the `cfm` daemon's read-only MCP surface. `what's_wrong` is an
**orchestrator over signals that already exist** — detector-published snapshots
and the allow-listed `/api/v1` read endpoints the other MCP tools use. The next
phase is *synthesis*, not *collection*: we are not adding 20 diagnostic tools,
we are making one tool reason over the raw ones we already have.

Code: `internal/mcpserver/whats_wrong.go` (evaluator + handler),
`internal/mcpserver/whats_wrong_process_health.go` (the first enrichment,
#1278). Design siblings: `docs/webdetector-history-design.md`,
`docs/DETECTORS.md`.

---

## 1. Where we are now (as-built)

`what's_wrong` is already more than a health dump. What ships today:

- **Severity-ranked findings.** `critical | warning | info`, with a stable
  secondary sort by category (`edge, service, process, disk, memory, load,
  network, …`). Most-severe first.
- **Conservative, named thresholds.** Every threshold is a constant grounded in
  a field the source endpoint already computes (disk/inode %, load÷threads,
  mem-available %, conntrack %, MySQL conn %, frozen-queue count, systemd
  `NRestarts`, …). **Under-flagging is deliberate** — routine WAF fires, normal
  firewall blocks and busy top-talkers are NOT findings.
- **`sources` map — the honesty layer.** Each section is reported as `ok`,
  `error`, or `unavailable`; a semantically degraded snapshot (e.g. an
  unreliable process-health scan) is surfaced explicitly. `status: "ok"` means
  **"no findings among the signals we could actually read"**, never "everything
  is fine". This is the seed of the `unknown`-first-class principle below.
- **Bounded + concurrent.** Sections fetch concurrently under a shared
  per-section budget (same shape as `security_overview`), so latency ≈ the
  slowest section, not the sum.
- **Pure, unit-tested evaluator.** `evaluateWhatsWrong(sections) → result` is
  pure; the handler only fetches + marshals. This is what makes the
  definition-of-done matrix (§6) achievable as table tests.
- **First enrichment (#1278).** `evalProcessHealth` maps the classified
  process-health endpoint into findings — threshold policy stays in
  `procstat.EvaluateHealth`, the MCP layer does not re-classify raw counts.

### What the procbaseline series (#1271–#1283) delivered toward this

That run was one vertical, not scattered work — it built the **process /
tenant attribution** row and the **baseline** that a root-cause layer needs:

| PR(s) | Contribution |
|---|---|
| #1271 | `process_list` gains `match` / `details` / `pid` — "high load → *which* process, running *what*" |
| #1272–#1277 | `procstat`: health summary → state→family attribution → conservative anomalies → scan-completeness reporting |
| **#1278** | process health wired **into** `what's_wrong` — the first conditional enrichment |
| #1279–#1282 | `procbaseline`: rolling sample store → reliable sampler → 72h retention → daemon collector |
| #1283 | `Store.FamilyStats` (median / p95 / coverage) — the descriptive baseline that feeds *confidence* |

Net: process/tenant attribution is done (pending fleet deploy of the node
binaries + MCP manifest refresh), and a "vs normal" baseline exists so future
anomalies can be graded, not just thresholded.

---

## 2. The enrichment contract

Every health **domain** contributes to `what's_wrong` through one shape. Most of
it exists; the *italic* fields are the formalization this doc adds.

```
domain report:
  status:      ok | problem | unknown        # unknown is FIRST-CLASS (§3)
  findings[]:  { severity, category, detail, tool, args,
                 confidence,                  # (new) none|low|medium|high
                 evidence[],                  # (new) ≤3 corroborating one-liners
                 sub_signals[] }              # (new) correlated drill-downs already run
  freshness:   age of the snapshot(s) this report is built from   # (new, vitals_at-style)
```

- **`status`** is per-domain, not global. A domain the daemon could not read
  reports `unknown` (with a reason), never contributes to an "ok".
- **`findings`** keep today's `severity`/`category`/`detail`/`tool`/`args`.
- **`confidence`** is earned from corroboration (§4), not asserted. A finding
  with a single weak signal is `low`; a finding backed by two+ independent
  signals pointing at the same culprit is `high`.
- **`evidence[]`** is the "why" — at most three lines, the concrete numbers that
  triggered the finding (anti-bloat, §3).
- **`sub_signals[]`** are the drill-downs the daemon *already ran internally*
  (e.g. the top offending tenant from `lve_cpu`), so the client gets the answer,
  not just "go run `lve_cpu` next".
- **`freshness`** stamps each report with the age of its underlying snapshot, so
  a correlation built on 5-minute-old data is not mistaken for live.

---

## 3. Hard constraints (non-negotiable)

These are the guardrails that keep the tool cheap, safe, and honest. A PR that
violates one is wrong even if it "works".

1. **Enrich from snapshots, not a live re-probe storm.** Internal enrichment
   consumes the **freshest detector-published snapshots** (governor,
   `procbaseline`, `mailmeter`, …). Live fan-out to an exec/`userstat`-hitting
   probe is allowed **only** where no snapshot exists, and then it must be
   **bounded, parallel, and timeout-capped**. A slow sub-probe degrades that
   sub-signal to `unknown/partial` — it **never blocks the triage**. (See the
   task-#33 precedent: mail tools were made detector-published precisely to kill
   per-request exec; same rule here.)
2. **`unknown` is first-class; absence of signal is never "healthy".** If a
   source errored, is disabled, or returned a degraded snapshot, say so. This is
   already how `sources` works — extend it to every enrichment, and let a
   `unknown` domain visibly lower a finding's confidence rather than silently
   vanish. (Mirrors the detector rule: stale-snapshot markers, don't advance the
   heartbeat on failure.)
3. **Under-flag, always.** Over-flagging is the cardinal sin of a triage tool.
   Ambiguous signals stay out until corroborated. Routine attack/WAF/block
   volume is noise, not a finding (§5).
4. **Ranked + evidence-bounded, never a dump.** Most-severe-first, top-N per
   category, ≤3 evidence lines per finding. (The `security_overview` slim-down,
   task #14, is the standing lesson — do not rebuild a dashboard.)
5. **Read-only.** Everything here stays within the read-only MCP boundary. No
   enrichment may mutate state.
6. **Backend/MTA-agnostic, or explicitly `unknown`.** A domain that only knows
   how to read one implementation (e.g. Exim) reports `unknown` on the others,
   never a false `ok`.

---

## 4. Root-cause correlation model

Today each section is evaluated independently. The upgrade is **cross-section
correlation**: a trigger in one domain pulls the already-collected signals that
explain it into a single finding with a culprit and a confidence.

Trigger → internal enrichment (from snapshots) → correlated finding:

| Trigger | Pulls in | Emits |
|---|---|---|
| high load (load÷threads over ratio) | `process_list` top, `procstat` family attribution, `lve_cpu`, `mysql_pressure` if mariadb hot | "high CPU primarily: `<tenant> lsphp 184%`, `mariadbd 73%`; tenant `<x>` at 96% of LVE limit" + confidence |
| MySQL conn > threshold | `mysql_pressure` top offender, `db_web_pressure` | "MySQL 94% of max_connections; top offender account `<x>`" |
| disk I/O / errors | process attribution, `dmesg` if kernel errors | "high I/O on `<dev>`; `<process>`; dmesg: `<error>`" |
| mail runtime saturation | `mail_runtime` (§5, new) | see §5 |
| network operational pressure | conntrack %, nft counter **deltas** | see §5 |
| service down/flapping | `NRestarts`, recent unit reason | "`<svc>` flapping (7 restarts/10m); last: `<reason>`" |

### Confidence rules (so `high` is earned)

- `high` — the trigger AND ≥2 independent signals name the same culprit
  (load↑ *and* a specific process at top *and* that tenant at its LVE cap).
- `medium` — trigger + one corroborating signal.
- `low` — trigger only; enrichment sources were `unknown`/unavailable, so the
  culprit is a guess. Say so.
- Baseline-graded: where `procbaseline`/`FamilyStats` exists, an anomaly "vs
  normal" (p95/median) raises confidence over a bare absolute threshold.

---

## 5. Remaining domains (the gaps)

### 5a. `mail_runtime` — SMTP/spamd saturation (highest priority)

The blind spot a real incident exposed: CPU/RAM ok, Exim active, spamd active,
queue not catastrophic — yet spamd saturated → SMTP sessions pile up → Exim hits
its connection cap → submission (587) unavailable. Today's `what's_wrong` would
miss it.

Build it **staged, like `mailmeter`** (leaf → collector+store → endpoint+MCP →
`what's_wrong` integration), MTA-scoped with explicit `unknown` off-Exim:

- **Signatures** to meter: `too many connections`, `spam acl condition: error
  reading from spamd`, spamd `Connection timed out`, SMTP connection-count
  approaching max.
- **Effective geometry** (the gold): current vs configured maxima —
  Exim connections vs `smtp_accept_max`, spamd active vs `--max-children`,
  recent timeout count over a window → **utilisation %**, so "all active"
  becomes "88% of cap, saturating".
- Lets `what's_wrong` emit: `CRITICAL mail: SMTP saturation — Exim 150/150,
  spamd 10/10, 41 timeouts/5m; likely root cause: SpamAssassin throughput`.

**Status (as-built).** The staged build has landed through the collector:
- *leaf* — `internal/mailruntime` geometry + `sig.go` classifier (PRs 1a…1a-sig),
  grounded in verbatim fleet log lines.
- *endpoint+MCP* — `GET /api/v1/mail/runtime` + the `mail_runtime` tool return the
  current/max geometry (SMTP vs `smtp_accept_max`, spamd vs `--max-children`) as
  utilisation% + saturation class, `unknown` when a cap is unresolved.
- *`what's_wrong` integration* — a `mail` finding already fires on the geometry
  (`warn` ≥80%, `critical` ≥95%).
- *collector v1 (1a-sig)* — the endpoint now also carries a `signals` block: a
  bounded Exim-mainlog tail tallied into `spamd_error` + `inbound_conn_refused`
  counts over `window_seconds`. **Burn-in only** — the counts are exposed to
  observe real fleet rates; no finding fires on them yet. The "N timeouts/5m"
  half of the target emit above waits on that burn-in (a defensible threshold
  needs the observed base rate) and on a second log source for
  `spamd_child_killed` (it lives in the spamd/syslog stream, not exim_mainlog).

### 5b. Network / firewall operational pressure

Signals exist (`nft_counters`, `firewall_blocks`, conntrack). The host-wide
`netfilter_path` source now contributes only actionable hook-order findings:
equal-priority ambiguity and CFM runtime/config priority drift. Intentional
ordered Imunify/CFM overlap remains visibility-only. Remaining correlation:
surface **only** when it is an operational problem, never routine.

- conntrack near cap → warn/crit (absolute %, easy).
- SYN flood / portflood → **rate of change**, not absolutes: keep a previous
  counter snapshot + timestamp and compute the delta ("18k SYN/s, firewall
  dropping"). A bare "7,000 blocked IPs" is noise and must stay out.

### 5c. Formalize the correlation layer

Promote the ad-hoc #1278 pattern into the §2 contract (confidence, evidence,
sub_signals, freshness, `unknown`) so 5a/5b plug in rather than bolt on.

---

## 6. Definition of done (v1 = complete)

`what's_wrong` is "v1 complete" when, **on its own**, it answers each class
below with the right culprit — or an explicit `unknown` — and a regression
fixture proves it. Each row is a table-test against `evaluateWhatsWrong`.

| Class | Must resolve to |
|---|---|
| server high load | who/what (process + tenant) |
| memory/swap pressure | who/what |
| disk / inode / I/O | which disk / kernel evidence |
| service down/flapping | service + recent reason |
| MySQL saturation | offending account/user |
| web traffic overload | vhost / IP / path |
| LVE tenant overload | account |
| mail queue / outbound abuse | sender / account / reason |
| SMTP / spamd saturation | connections / workers / timeouts (§5a) |
| network / L3 flood | type / port / rate (§5b) |
| edge / WAF operational issue | host / rule / client class |
| **source unavailable** | **explicitly `unknown`, never `healthy`** |

---

## 7. Sequencing

1. **Contract first** (this doc) — the §2 schema + §3 constraints + §4
   confidence rules are the agreement `mail_runtime` and the retrofit build
   against.
2. **`mail_runtime`** (§5a) — the first consumer of the formalized contract and
   a walking skeleton for the whole path, validated on a real incident.
3. **Retrofit existing domains** into correlated findings (load→process/lve/
   mysql, network deltas), then close out the §6 matrix.

Each step is its own small PR with its own tests, per repo convention. The raw
tools are almost all already here — the remaining work is making `what's_wrong`
the smart orchestrator of them.
