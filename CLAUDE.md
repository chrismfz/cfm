# CLAUDE.md

Guidance for AI agents (and humans) working in this repository. Keep it
current: when a build step, guardrail, or hard-won lesson changes, update
the relevant section here so we don't relearn it the hard way.

---

## 1. What CFM is

CFM (Configurable Firewall Manager) is a **single Go daemon** providing
defence-in-depth across five layers, from the HTTP edge down to the kernel:

| Layer | What it does | Code |
|---|---|---|
| **Challenge engine** | interactive proof-of-work / JS challenge | `internal/webdetector`, `configs/lua/cfm_clearance.lua` |
| **WAF** | OWASP-inspired request filtering, in-path via edge proxy | `configs/lua/cfm_waf.lua`, `internal/webdetector` |
| **Web detector** | log-driven L7 behavioural scoring → block/challenge | `internal/webdetector`, `internal/detectors` |
| **nftables firewall** | L3/L4 enforcement, autoblock, rate/conn limits | `internal/firewall` (`nft/` exec + `nftlib/` netlink) |
| **cfm-lsm** | CO-RE BPF LSM behavioural detection at syscall boundary | `internal/lsm` |
| **kernsec** | KSPP-grade kernel-surface hardening (sysctls, boot args, modules) | `internal/kernsec` |

The in-path edge proxy is **OpenResty** (default) or **Angie**; the daemon,
Lua decision files, and sslcollector socket are identical for both.

Authoritative reference: `README.md` (large; use its Table of Contents to
jump). Deep-dive docs live under `docs/`.

---

## 2. Build / test / run

```bash
make setup          # first-time: go mod tidy
make build          # builds ./bin/cfm  (runs verify-bpf-bindings first)
make run            # build + run
make lua            # syntax-check configs/lua/*.lua
make test-lua       # Lua unit tests under scripts/tests/*_test.lua
make release        # bpf + deb + rpm (contributors; needs clang + libbpf-dev for `bpf`)
```

There is no monolithic `make test`. Run the Go suite directly:

```bash
go test -race ./...
```

Firewall backend is selectable at runtime: `CFM_FIREWALL_ENGINE=nft`
(default, exec-based) or `nftlib` (netlink, zero-fork).

---

## 3. CI gates — these MUST pass before pushing

CI (`.github/workflows/security.yml`) is the source of truth. Mirror it
locally before you push; a green diff that fails one of these wastes a round-trip:

```bash
go vet ./...
go build ./...
go test -race ./...
make lua
make test-lua
./scripts/tests/check_cli_transport.sh          # CLI transport guardrail (see §5)
./scripts/tests/check_cfm_clearance_require.sh   # Lua clearance module load check
./scripts/tests/check_bypass_list.sh             # challenge_waf_bypass.conf bounds + generator tests
```

Additional scanners run in CI: **CodeQL** (`codeql.yml`), **Semgrep**
(`semgrep.yml`), **govulncheck**. CodeQL has flagged real issues before
(e.g. reflected XSS on the challenge page) — treat its alerts as real.

---

## 4. Repository map

```
cmd/cfm/            # binary entrypoint (main.go) + auth CLI
internal/           # all daemon logic, one package per concern:
  firewall/         #   nft/ (exec) · nftlib/ (netlink) · autoblock/ · selfip/
  webdetector/      #   L7 detection, challenge, WAF wiring, history
  detectors/        #   ssh/exim/dovecot/ftp/mysql/cpanel/modsec/health/...
  lsm/              #   cfm-lsm BPF LSM subsystem
  kernsec/          #   kernel hardening (KSPP sysctls, modules, boot args)
  apiserver/        #   HTTP API server
  webui/            #   embedded /cfm-admin UI (embed.go + static/)
  panelauth/        #   cPanel/WHM auth broker (scoped tokens) — see §6
  authstore/        #   auth/session/token storage
  clihttp/          #   the ONLY sanctioned HTTP transport for CLI runtime (§5)
  config/ detectorscfg/ ...  # config parsing
  sslcollector/     #   cert discovery + unix-socket API for the edge proxy
  ... (~45 packages total; `ls internal/` for the full list)
configs/            # REFERENCE configs (packaged to /usr/share/cfm/configs/)
  lua/              #   in-path Lua: cfm_clearance, cfm_waf, cfm_rules, cfm_panel, ...
  openresty.conf / angie.conf
plugins/cfm-plugin-cpanel/   # cPanel plugin (install/uninstall, templates, lib)
packaging/          # debian/ + rpm/ build assets
docs/               # design docs, runbooks, checklists (see §7)
scripts/tests/      # CI guardrail scripts + Lua tests
```

Config model: **reference** configs ship under `configs/` →
`/usr/share/cfm/configs/`; **live** configs are edited under `/etc/cfm/`.
Runtime/generated artifacts (incl. rendered Lua) live under `/var/lib/cfm/`.

---

## 5. Conventions & guardrails (enforced)

- **CLI HTTP goes through `internal/clihttp`.** Direct `net/http` calls in
  CLI runtime code are rejected by `check_cli_transport.sh`. The only escape
  is an inline `clihttp-exception: <reason>` comment on the same line — use
  it sparingly and justify it.
- **Lua validation gate before reloading the edge proxy.** Any change to
  `configs/lua/*` must pass `luac -p` and a LuaJIT `require` smoke-test of all
  modules. Follow `docs/challenge-waf-release-checklist.md` to the letter —
  shipping a Lua file that fails to load takes the WAF/challenge layer down.
- **Generated Lua token files have enforced ownership/mode** (`root:cfm`,
  `0640`). Don't loosen this; post-deploy checks assert it.
- **Scoped vs admin auth is a hard security boundary** (cPanel users get
  scoped viewer tokens, never admin tokens). Validators live centrally;
  out-of-scope access must fail-closed (403). See §6.
- **Code is the source of truth — keep doc-comments and docs in sync.**
  Stale comments/docs have bitten us repeatedly: `governor_api.go` said
  "Guard 3 (admin-only) for now" long after the endpoints were wired scoped;
  `docs/endpoint_scope_inventory.md` listed scope-validated endpoints
  (`waf/engine/summary`, `{challenge,waf}/exclude/*`) as admin-only and misled
  a scope audit; a divergent fallback list in `ui-scope.js` disagreed with the
  real nav matcher. So: when you change an endpoint's auth/scope (or any
  behaviour a comment/doc describes), update the handler doc-comment **and**
  `docs/endpoint_scope_inventory.md` **in the same change**, delete "for now /
  TODO" guard comments once the work lands, and never keep a second copy of a
  list/matcher that can drift. When a comment and the code disagree, trust the
  code and fix the comment.
- **Match surrounding style.** Go packages are small and single-purpose;
  keep new code in the right package rather than widening `main.go`.
- **`detectors.conf` scalar readers now tolerate an inline `;`/`#` comment.**
  `kvInt`/`kvBool`/`kvDur` (`internal/detectors/registry.go`) strip inline
  comments via `cleanScalar` (as the string/float readers already did). Before
  that fix they parsed the raw stored value, so `KEY = 5 ; note` became `"5 ;
  note"`, failed, and **silently fell back to the built-in default** — a
  fleet-wide latent trap that masked configured values (`waf_security`'s
  `DRY_RUN`, the `/tmp` cleanup gate, the suspicious-vhost challenge thresholds).
  Fixing it was itself a behaviour change (those values finally apply), so it
  shipped as its own reviewed PR. Note `cleanScalar` cuts at the first `;`/`#`
  and does NOT do quote-aware scanning (the section parser leaves an embedded
  quote on a quoted value with an inline comment). Prefer comments on their own
  line anyway; scalars must never legitimately contain `;`/`#`.

---

## 6. Where we historically lost the ball (read before touching these)

Distilled from ~1000 PRs (Mar–Jun 2026). These areas generated the most
rework, follow-ups, and "harden"/"fix-the-fix" churn. Move carefully here.

### cPanel / panel-auth integration — the single most painful area
~85 PRs spanning April→June. The iframe + token transport flow is subtle
and easy to regress. Before changing it, read
`docs/cpanel-plugin-token-transport.md` and
`docs/scoped-postdeploy-verification.md`. Specifically:
- Token delivery is **postMessage-first** (with `cfmTokenAck`); URL-token
  fallback is deliberately *not* used when ACK times out.
- `cfmExpectedOrigin` is injected into the iframe URL and is the
  highest-priority expected `postMessage` origin — always validate origin
  AND source.
- Avoid assertion **nonce reuse**; watch for `token_replay`.
- `panelauth` mints scoped viewer tokens; the plugin must not use admin
  tokens.
- Separately, cPanel **account transfers** (DNAT/rsync `/acctxfer*`,
  WHM live-transfer) need challenge/WAF bypass and generous timeouts —
  several incidents traced to hangs around these endpoints.

### WAF false positives — never "done"
The WAF needs continuous tuning against real apps. Recurring offenders:
Joomla K2 / elFinder (`cmd=<verb>` misread as command injection),
`/.well-known/` (breaks AutoSSL/CA HTTP DCV). When adding/strengthening a
rule, check it doesn't trip legitimate panel/app traffic, and prefer
`logonly` → `challenge` → `block` promotion over going straight to block.
Reference: `docs/waf.md`, `docs/waf-analysis-2026-05-08.md`,
`docs/challenge-waf-release-checklist.md`.

### Challenge excludes & scoping
Exclude/bypass matching must be scope-aware for scoped users, and excludes
are increasingly **file-presence based** rather than config flags. Pre-auth
login challenge behaviour differs between DNAT and OpenResty modes — verify
both. `/.well-known/` needs **two** carve-outs, not one: the in-path serving
carve-out (`cfm.lua` Step 0a1) only stops *serving* a challenge in OpenResty
mode; the log-driven decision engine must **also** exclude the prefix from
per-IP scoring (`isWellKnownChallengeExempt` in `engine.go`), or a CA's
ACME/DCV validator (hits many domains + many one-time token paths) trips the
scanner heuristics and gets flagged — which breaks SSL issuance outright in
DNAT mode, where the flagged IP is redirected before the in-path carve-out
runs. Any path-based challenge exemption likely needs the same both-sides
treatment.

### cfm-lsm — signal, then noise
Built in a one-week May burst (~55 PRs) and immediately needed extensive
false-positive silencing (CRED/OBS/FS noise from systemd-per-user, bwrap,
crontab/at, setuid-root contexts, CONFIG-gated tracepoints). New LSM rules
ship noisy — budget for a tuning pass and honour prior LSM decisions.
Also: BPF bytecode can go stale — `make build` runs `verify-bpf-bindings`
and `make release` regenerates objects; don't bypass these.
Reference: `docs/cfm-lsm.md`, `docs/kernsec.md`.

### WAF → autoblock (`waf_security`) — new Jul 2026, move carefully
Turns in-path WAF hits into a persistent nft block via the detector framework
(`internal/detectors/wafsec/` + `waf_security_register.go`, published from
`webdetector.RecordWAFTrigger` via `SubscribeWAFHitEvents`). Design:
`docs/waf-autoblock-design.md`. Hard-won points:
- **Phase 1 feeds edge-`block` hits ONLY** (the subscribe callback drops any
  hit whose action != `block`). Do **not** key autoblock on reason-family
  alone: a family spans edge tiers — `WAF_BACKDOOR` (430-438) has **no**
  block-tier rule, and `WAF_RCE` mixes block 320 with logonly 322-327, so
  family-only keying autoblocks logonly recon. Families with an edge-`block`
  rule today: `WAF_SQLI`/`WAF_RCE`/`WAF_UPLOAD_FNAME`/`WAF_UPLOAD_CONTENT`, plus
  `WAF_WEBSHELL` since 2026-07-03 (rule 413, the proper-noun drop-path subset) and
  `WAF_CVE` (rule 10001) — all armed to 1 — those are the only ones that can fire
  in Phase 1.
- **Adding a block-tier rule to a family SILENTLY arms its autoblock** — the
  default is `1 iff WAFFamilyHasBlockRule(fam)` (`waf_security_register.go`), and
  existing `/etc/cfm/detectors.conf` files don't list the family, so they inherit
  the armed default on the next binary upgrade. When you promote a rule to
  `block`, decide the autoblock intent in the SAME change. `WAF_WEBSHELL` was held
  at `0` through burn-in — auto-arming nft-bans a source that GETs `/c99.php`,
  which includes benign internet scanners (Shodan, Censys, uptime monitors,
  researchers) — but as of **2026-07-18 it is armed by default** (code + reference
  config): the operator runs it fleet-wide and confirms it cleanly bans malicious
  scanners/scrapers/bots with acceptable collateral. Exempt a benign scanner with
  `ALLOW_UA_CONTAINS`/`ALLOW_NETS` or hold rule 413 with `RULE_413 = 0` rather
  than un-arming the family. Arming a *newly* block-promoted family is still a
  deliberate opt-in decision, after its own burn-in.
- **The Lua edge de-dups pushes per `(ip, reason)`** within `push_cooldown`
  (`cfm_waf.lua should_push`). Harmless at threshold 1 (first hit is what
  counts), but an accumulate threshold (e.g. 40) counts distinct cooldown
  windows, not raw hits — retune when Phase 2 turns on challenge-tier families.
- **The detector only emits `core.Alert`.** Blocking, leniency (GR/CY temp-ban),
  API reporting and email are the section sink's job (`autoblock_sink.go`) —
  don't reimplement them. A plain alert blocks per the section `BLOCK` policy;
  `Extra["enforcement"]="dryrun"` logs-without-blocking.
- Ships a **soft TTL block** (`BLOCK = "6h"`, self-healing), not `permanent`;
  `DRY_RUN = 1` is available for a watch-first burn-in. Every WAF family is a
  config knob (key = family minus `WAF_`); coverage of the full registry is
  asserted by `TestWAFSecurityFamilyCoverage`.

### WAF CVE detectors (`WAF_CVE`) — named-vulnerability rules
Per-CVE in-path detectors live in the `10000+` rule-id band and emit the
`WAF_CVE` reason family (`WAF_CVE:CVE_<year>_<suffix>:PRODUCT:TAG`), which the
autoblock notifier turns into a `WAF/CVE-YYYY-NNNN` alert automatically
(`cveFromReason` in `wafsec/detector.go`). **Read `WAF_CVE.md` before adding
one** — it carries the as-built reference and a step-by-step "CVE hunting"
recipe; `WAF_CVE_PLAN.md` is the original design + candidate backlog. Hard-won
points:
- **Never write a CVE signature from memory.** The assistant's knowledge cutoff
  predates most target CVEs — get the exact method/endpoint/marker from a public
  PoC, the vendor patch, NVD references, or operator-supplied logs/captures. A
  param *name* legit traffic also sends is not exact enough.
- **`WAF_CVE` is armed by default** (`CVE = 1`) because it has an edge-`block`
  rule (10001, Simple File List) and the operator wants CVE hits to *both*
  nft-ban *and* alert on Slack/mail — an un-armed family is dropped by `wafsec`
  before the sink, so `CVE = 0` would notify nothing. The family is
  heterogeneous (many CVEs, varying FP confidence), so a **lower-confidence CVE
  rule ships with a per-rule `RULE_<id> = 0`** (hold the rule, not the family);
  `DRY_RUN = 1` gives a watch-first burn-in. `TestWAFSecurityFamilyCoverage`
  asserts `WAF_CVE` defaults to `1`. (As of 2026-07-18 `WAF_WEBSHELL` is also
  armed by default — every family with an edge-`block` rule now arms to `1`, no
  exceptions; exempt a benign `/c99.php` scanner with `ALLOW_UA_CONTAINS`/
  `ALLOW_NETS` or hold rule 413 with `RULE_413 = 0`.)
- **Lua↔Go id parity is enforced.** A new `10xxx` id needs matching entries in
  `configs/lua/cfm_waf.lua` `RULE_IDS` **and** `internal/webdetector/waf_rule_ids.go`
  (`TestWAFRuleIDs_LuaParity`), plus positive+negative Lua tests. Key the
  detector on the exact endpoint/marker, reuse hardened helpers
  (`detect_upload_content`, not a raw `<?php` scan), and decide autoblock intent
  in the same change.

### Concurrency / process lifecycle
Early bugs included zombie/unreaped detector tailer subprocesses, panics,
and snapshot-refresh races. When spawning subprocesses or background
refreshers, ensure reaping, bounded backoff, and stale-snapshot markers
rather than advancing heartbeats on failure.

---

## 7. Key docs (pointers, not duplication)

| Topic | Doc |
|---|---|
| WAF behaviour & tuning | `docs/waf.md`, `docs/waf-analysis-2026-05-08.md` |
| Challenge/WAF release gate | `docs/challenge-waf-release-checklist.md` |
| cPanel token transport | `docs/cpanel-plugin-token-transport.md` |
| Scoped-mode post-deploy checks | `docs/scoped-postdeploy-verification.md` |
| MFA rollout | `docs/mfa_rollout_regression_checklist.md` |
| BPF LSM | `docs/cfm-lsm.md` · Kernel hardening: `docs/kernsec.md` |
| Detectors | `docs/DETECTORS.md`, `docs/Detectors.Leniency.md` |
| Web detector history design | `docs/webdetector-history-design.md` |
| WAF → autoblock (`waf_security`) | `docs/waf-autoblock-design.md` |
| WAF CVE detectors (`WAF_CVE`) | `WAF_CVE.md` (as-built + "CVE hunting" recipe) · `WAF_CVE_PLAN.md` (design + backlog) |
| Admin/WebUI API | `docs/webui-api-curl-recipes.md`, `docs/webui-api-sample-responses.md` |
| DNAT bypass | `docs/dnat-bypass.md` · Debug capture: `docs/debug-capture-runbook.md` |
| Proxy latency: measuring & origin keepalive | `docs/proxy-performance.md` |
| Endpoint scope inventory | `docs/endpoint_scope_inventory.md` |

---

## 8. Releasing & CHANGELOG

**The version IS the date.** The Makefile sets `VERSION ?= $(date +%Y.%m.%d)`
(the `.deb` adds an `-HHMMSS` suffix; the git tag is `vYYYY.MM.DD`). There is
no separate semver to bump — building on a given day produces that day's
version. The normal release is just:

```bash
make release    # builds bin/cfm, then the .deb and .rpm stamped with today's date
make sync       # rsyncs today's .deb/.rpm (+ checksums) to the remote repo
```

`make release` runs `bpf deb rpm`, so it also regenerates BPF objects — needs
`clang` + `libbpf-dev` on the build host.

### CHANGELOG discipline (do this — it's not automated)

`CHANGELOG.md` is maintained **by hand** (no Makefile hook). Because version ==
date, every released package should be reflected by a dated section.

1. **While working:** add a bullet under `## [Unreleased]`, grouped by
   **Added / Changed / Fixed / Security / Removed**. Keep entries
   operator-facing (what changed, why it matters) — not "fixed typo".
2. **On release day**, before/with `make release`: rename `## [Unreleased]`
   to `## YYYY.MM.DD` using **today's date — the same date `make release`
   stamps** (`date +%Y.%m.%d`). Then add a fresh empty
   `## [Unreleased]\n\n_Nothing yet._` block at the top for the next cycle.
3. If you ship more than one build in a single day, keep one dated section for
   that day and keep appending — the date is the unit of release.

So the steady-state release ritual is: _move Unreleased → today's date in
`CHANGELOG.md`_, then `make release ; make sync`.

## 9. Workflow

- Develop on the feature branch you were assigned; create it from `main` if
  missing. Don't push to `main` directly.
- Keep PRs focused — this repo favours many small, single-concern PRs.
- After edge-affecting changes, run the relevant runbook/checklist in `docs/`
  before considering the change done.
- Update `CHANGELOG.md` (`[Unreleased]`) as part of the change, per §8.
- Don't create a PR unless explicitly asked.
