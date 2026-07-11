# WAF CVE Detection Plan

## Purpose

This document describes a safe, scalable plan for adding CVE-specific WAF coverage to CFM without turning CMS/plugin reconnaissance into broad blocking rules.

The immediate driver is the July 2026 ACSC-reported campaign against vulnerable CMS platforms and plugins, including WordPress plugins, Craft CMS, MaxSite CMS, MetInfo CMS, and Joomla JCE. The design below is intentionally broader than that single campaign: it defines a reusable CVE rule model that can grow beyond the current three-digit WAF rule space.

## Goals

- Detect concrete CVE exploit attempts, not generic CMS, plugin, or product presence.
- Keep false positives low by requiring exact exploit request shapes.
- Make CVEs first-class metadata and operator-facing aliases.
- Preserve stable internal WAF rule IDs and backwards compatibility for existing rules.
- Allow per-CVE and per-rule rollout from `logonly` to `challenge` to `block`.
- Feed the existing `waf_security` autoblock path only when the edge WAF action is `block`.
- Surface CVE names in WAF logs, summaries, notifiers, and later statistics.
- Avoid silently autoblocking benign scanners, researchers, monitors, or passive version probes.

## Non-goals

- Do not build a generic CMS/plugin blacklist.
- Do not block requests merely because they mention WordPress, Joomla, Craft, MaxSite, MetInfo, or a plugin slug.
- Do not make internal rule IDs equal to CVE numbers.
- Do not mass-enable autoblock for a broad CVE family before per-rule burn-in.
- Do not replace existing generic protections such as upload, RCE, SQLi, traversal, webshell, and header vulnerability rules.

## Why a dedicated CVE model is needed

The current WAF rule ID model uses compact numeric IDs grouped by hundreds, with `9xx` reserved for future CVE or behavioural rules. That is not enough for long-term CVE coverage: `9xx` provides fewer than one hundred practical slots, while named vulnerability coverage can quickly exceed that.

CVE identifiers are also not a good primary internal ID format. For example, `CVE-2026-0740` could be encoded as `20260740`, but that approach has several problems:

- A single WAF fingerprint can intentionally cover multiple CVEs.
- A single CVE can need multiple fingerprints with different false-positive risk.
- CVE suffix lengths vary and are not designed as local rule handles.
- Operators need compact stable rule IDs for existing config and dashboards.
- CVEs are external taxonomy; CFM rule IDs are internal compatibility contracts.

Therefore, CVEs should be first-class metadata and config aliases, while CFM keeps separate stable internal numeric rule IDs.

## Proposed rule identity model

Use three separate concepts:

| Concept | Example | Purpose |
| --- | --- | --- |
| Internal WAF rule ID | `10001` | Stable CFM handle used in logs, APIs, dashboards, and `RULE_<id>` overrides. |
| CVE identifier | `CVE-2026-0740` | External vulnerability identifier exposed as metadata and config alias. |
| WAF reason | `WAF_CVE:CVE_2026_0740:NINJA_FORMS:EXACT_ACTION_PAYLOAD` | Runtime detection reason emitted by Lua and recorded by the edge. |

### Internal ID range

Reserve a scalable numeric range for named vulnerability rules:

```text
10000+  CVE / named vulnerability WAF rules
```

Existing `1xx` through `8xx` IDs remain unchanged. The old `9xx` reserved range can remain unused or serve only as a short transitional reserve, but new CVE work should use `10000+`.

### Registry metadata

Extend the Go WAF rule registry with optional CVE metadata:

```go
type WAFRule struct {
    ID            int      `json:"id"`
    Name          string   `json:"name"`
    Group         int      `json:"group"`
    GroupName     string   `json:"group_name"`
    ReasonFamily  string   `json:"reason_family"`
    DefaultMode   string   `json:"default_mode"`

    CVEs          []string `json:"cves,omitempty"`
    Product       string   `json:"product,omitempty"`
    Vendor        string   `json:"vendor,omitempty"`
    ExploitClass  string   `json:"exploit_class,omitempty"`
}
```

Example entry:

```go
{
    ID:           10001,
    Name:         "rule_cve_2026_0740_ninja_forms",
    GroupName:    "cve",
    ReasonFamily: "WAF_CVE",
    DefaultMode:  "logonly",
    CVEs:         []string{"CVE-2026-0740"},
    Product:      "Ninja Forms",
    Vendor:       "WordPress plugin",
    ExploitClass: "cms_plugin_exploit",
}
```

The existing Lua `RULE_IDS` table should remain the source of numeric IDs for Lua checks. CVE metadata can be mirrored in a separate Lua table if needed by tests or runtime exports:

```lua
local RULE_META = {
  rule_cve_2026_0740_ninja_forms = {
    cves = { "CVE-2026-0740" },
    product = "Ninja Forms",
    vendor = "WordPress plugin",
    exploit_class = "cms_plugin_exploit",
  },
}
```

## Reason family and runtime reason format

Use a dedicated reason family for CVE-specific fingerprints:

```text
WAF_CVE
```

Runtime reasons should include the normalized CVE and product tag:

```text
WAF_CVE:CVE_2026_0740:NINJA_FORMS:EXACT_ACTION_PAYLOAD
WAF_CVE:CVE_2026_48907:JOOMLA_JCE:PHP_UPLOAD_VECTOR
WAF_CVE:CVE_2025_32432:CRAFT_CMS:TEMPLATE_RCE
```

This keeps dashboards and logs searchable by family, CVE, product, and detection tag.

A narrower `WAF_CMS_CVE` family is possible, but a single `WAF_CVE` family with metadata is simpler and can cover non-CMS CVEs later. If autoblock risk becomes too broad, per-rule and per-CVE thresholds should be used instead of splitting families prematurely.

## CVE observability in logs, summaries, and notifiers

CVE identity must not be useful only at rule-authoring time. If the WAF blocks, challenges, or logs a CVE-specific hit, every downstream path should preserve the normalized CVE name so operators can answer:

- Which CVEs are being probed most often?
- Which CVEs are actually reaching `block` mode?
- Which hosts and IPs are most exposed to a specific CVE attempt?
- Which candidate CVE rules are worth promoting after burn-in?
- Which notifiers should include an actionable `CVE: CVE-YYYY-NNNN` field?

### Event fields

The edge should continue emitting the existing WAF reason string, but CVE-aware code should also derive structured fields from either the rule registry metadata or the `WAF_CVE:*` reason:

| Field | Example | Notes |
| --- | --- | --- |
| `reason_family` | `WAF_CVE` | Existing family-level grouping remains useful. |
| `reason` | `WAF_CVE:CVE_2026_0740:NINJA_FORMS:EXACT_ACTION_PAYLOAD` | Full existing reason string, unchanged for backwards compatibility. |
| `rule_id` | `10001` | Existing stable internal rule ID. |
| `cves` | `["CVE-2026-0740"]` | Prefer registry metadata; fall back to parsing `CVE_2026_0740` from the reason. |
| `primary_cve` | `CVE-2026-0740` | First CVE for compact CLI/notifier display. Empty for non-CVE rules. |
| `product` | `Ninja Forms` | Optional rule metadata. |
| `exploit_class` | `cms_plugin_exploit` | Optional rule metadata. |
| `waf_action` | `block` | The edge action: `logonly`, `challenge`, or `block`. |

If a single internal rule maps to multiple CVEs, logs and API responses should keep the full `cves` array. Compact CLI and notifier output can display the first CVE plus a count, for example `CVE: CVE-2025-34085 (+1)`.

### CLI summaries

The current `cfm webtop waf engine --top 10` output already groups by WAF family, full rule reason, hosts, IPs, and recent events. CVE support should add optional CVE-aware summaries without removing the existing views:

```text
Top CVEs:
   1) CVE-2026-0740  Ninja Forms                     42
   2) CVE-2026-48907 Joomla JCE                      17
   3) CVE-2025-32432 Craft CMS                       8

Top blocked CVEs:
   1) CVE-2026-48907 Joomla JCE                      17
   2) CVE-2026-0740  Ninja Forms                     9

Recent WAF events:
TIME                HOST              IP             METHOD ST   CVE             RULE
2026-07-11 19:07:20 example.gr        188.119.4.178  post   403  CVE-2026-48907 WAF_CVE:CVE_2026_48907:JOOMLA_JCE:PHP_UPLOAD_VECTOR
```

Recommended views:

- `Top CVEs`: all actions, useful during `logonly` burn-in.
- `Top blocked CVEs`: edge status/action `block`, useful for `waf_security` and notifier review.
- `Top CVEs by host`: identify customers/domains being targeted.
- `Top CVEs by source IP`: identify scanners or attack infrastructure.
- `Recent WAF events`: include a compact `CVE` column when present.

These summaries should count by normalized CVE identifier, not by the full reason string. The full reason remains useful for per-fingerprint detail.

### Notifiers and autoblock alerts

Notifier payloads for WAF-originated blocks should include CVE fields when available:

```text
WAF block
Host: example.gr
IP: 188.119.4.178
Rule: WAF_CVE:CVE_2026_48907:JOOMLA_JCE:PHP_UPLOAD_VECTOR
CVE: CVE-2026-48907
Product: Joomla JCE
Action: block
URI: /index.php?option=com_jce&...
```

For `waf_security` alerts, the detector should not reimplement CVE parsing if the WAF hit event already carries structured CVE metadata. The preferred flow is:

```text
Lua reason + rule_id
  -> Go WAF hit event
  -> registry metadata enrichment
  -> WAF logs / API summaries / CLI
  -> waf_security alert Extra fields
  -> section sink notifiers and API reporting
```

Recommended `core.Alert.Extra` keys for CVE-aware `waf_security` alerts:

```text
waf_rule_id=10001
waf_reason=WAF_CVE:CVE_2026_48907:JOOMLA_JCE:PHP_UPLOAD_VECTOR
waf_family=WAF_CVE
cve=CVE-2026-48907
cves=CVE-2026-48907
product=Joomla JCE
exploit_class=cms_plugin_exploit
```

This gives email/API/notifier sinks enough data to display `CVE: CVE-YYYY-NNNN` and allows later statistics without scraping free-form message text.

### Statistics and promotion decisions

The CVE pipeline should preserve enough counters to decide whether a candidate rule is worth the implementation and rollout cost:

| Statistic | Why it matters |
| --- | --- |
| hits by CVE | Shows whether a CVE rule is seeing real traffic. |
| blocked hits by CVE | Shows which CVEs are already in enforce mode. |
| unique source IPs by CVE | Distinguishes one noisy scanner from broad exploitation. |
| unique hosts by CVE | Shows customer/domain exposure. |
| action split by CVE | Shows `logonly`/`challenge`/`block` burn-in state. |
| top reason tags per CVE | Shows which exploit fingerprint is active. |
| false-positive review state | Prevents premature promotion. |

Promotion from `logonly` should be based on both source intelligence and local CFM observations. A CVE with strong external sources but zero local hits may still be worth keeping as a dormant detector, while a noisy local `logonly` CVE candidate should not be promoted until recent events and host/IP distributions are reviewed.

## Detection requirements

Every CVE detector must match a concrete exploit request shape. A detector should require as many of these as practical:

- Exact vulnerable endpoint path.
- Exact HTTP method.
- Exact query/body parameter names or action names.
- Product-specific plugin/module slug only as one of several constraints.
- Exploit-specific payload markers.
- Upload filename/content constraints where applicable.
- Required headers or content type where applicable.
- Negative checks for known legitimate flows where applicable.

### Do not block passive reconnaissance

The following should not be enough to emit a blocking CVE hit:

- `GET /wp-content/plugins/<plugin>/`
- `GET /wp-content/plugins/<plugin>/readme.txt`
- `GET /administrator/components/...`
- `GET /vendor/...`
- CMS login page access.
- Generic `admin-ajax.php` access.
- Generic multipart upload without CVE-specific endpoint and payload constraints.

Passive probes may be logged by another detector family in the future, but they should not feed `waf_security` autoblock by default.

### Block candidates

A CVE detector can be considered for `block` only when the request shape is near-zero false positive, such as:

- Exact unauthenticated exploit endpoint plus exact vulnerable action parameter.
- Upload to exact vulnerable endpoint with `.php`, `.phtml`, or webshell archive content.
- Exact template injection or RCE payload to the vulnerable route.
- Exact serialized/deserialization payload marker to the vulnerable route.
- Exact exploit-specific header set that has no legitimate browser or CMS use.

Weak or incomplete fingerprints must start in `logonly`.

## Rollout modes

Default rollout should be conservative:

| Confidence | Default mode | Promotion condition |
| --- | --- | --- |
| Incomplete or source-only fingerprint | `logonly` | Field data confirms no legitimate traffic and public PoC shape is validated. |
| Strong but not fleet-validated fingerprint | `challenge` | Burn-in shows true positives only and replay/challenge behavior is safe. |
| Exact exploit request with near-zero FP | `block` | Signature is constrained to impossible legitimate behavior. |

Promotion should generally follow:

```text
logonly -> challenge -> block
```

Direct-to-block is allowed only for exact exploit shapes where blocking the single request is safer than allowing it through.

## waf_security autoblock integration

The existing `waf_security` detector should remain edge-block gated: only WAF hits whose edge action is `block` are eligible for persistent nft blocking.

Recommended defaults:

```ini
[waf_security]
CVE = 0

; Optional after burn-in:
; CVE_2026_0740 = 1
; CVE_2026_48907 = 1
; RULE_10001 = 1
```

### Per-CVE aliases

Add optional config aliases that map CVE names to one or more internal rule IDs:

```ini
CVE_2026_0740 = 1
CVE_2026_48907 = 0
```

Rules:

- `RULE_<id>` remains supported.
- `RULE_<id>` should override `CVE_<year>_<suffix>` when both are present.
- A CVE alias applies to every internal rule mapped to that CVE.
- If a rule maps to multiple CVEs, the most specific `RULE_<id>` wins; otherwise any explicitly enabled CVE alias may enable that rule.

### Avoid broad family auto-arming

Do not set the whole `WAF_CVE` family to autoblock by default. CVE rules vary widely in confidence and false-positive risk. Autoblock should be opt-in per CVE or per rule after burn-in.

## CVE intelligence sources and candidate pipeline

News articles are useful as an early signal, but they should not be the only source for rule creation or promotion. CVE candidates should carry source links and source confidence so later reviews can explain why a rule exists and whether it should remain active.

### Recommended sources

| Source | Use | Notes |
| --- | --- | --- |
| [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited-in-the-wild signal. | Best first filter for “hot” CVEs; available as catalog data and should heavily boost priority. |
| [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) | CVSS, CWE, descriptions, references, CPEs, dates, enrichment. | Useful canonical enrichment, but CPE coverage can be weak for CMS plugin ecosystems. |
| [CVEProject cvelistV5](https://github.com/CVEProject/cvelistV5) | Local bulk mirror of official CVE records. | Good for diffing new CVEs without relying only on NVD queries. |
| [WPScan API](https://wpscan.com/api/) | WordPress core, plugin, and theme vulnerabilities. | Strong source for WordPress plugin slug-based matching. |
| [Wordfence Intelligence](https://www.wordfence.com/threat-intel/vulnerabilities) | WordPress vulnerability intelligence. | Good cross-check source for WordPress core/plugin/theme issues. |
| [Patchstack Database](https://patchstack.com/database) | WordPress and open-source ecosystem vulnerability data. | Useful for exploited/mitigation context and WordPress ecosystem triage. |
| [Joomla Security Centre](https://developer.joomla.org/security-centre.html) | Joomla core and extension advisories. | Prefer vendor advisories for affected versions and official mitigation. |
| [Craft CMS security advisories](https://github.com/craftcms/cms/security/advisories) | Craft CMS advisories. | Use for exact affected versions and official context. |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit likelihood prioritization. | Priority signal only; high EPSS does not imply WAF-safe. |
| [GitHub Advisory Database](https://github.com/advisories) and [OSV](https://osv.dev/) | PHP/Composer and open-source package advisories. | Useful for framework/package CVEs outside CMS plugin databases. |

### Source confidence tiers

| Tier | Sources | Rule implication |
| --- | --- | --- |
| Tier 1 | CISA KEV, vendor advisories, official CVE records, NVD enrichment. | Strong evidence that the CVE exists and is important. |
| Tier 2 | WPScan, Wordfence, Patchstack, GitHub Advisory, OSV. | Strong ecosystem-specific evidence, especially for WordPress/PHP. |
| Tier 3 | CERT/CSIRT advisories, reputable security vendor writeups, manually reviewed PoCs. | Candidate evidence; verify against Tier 1/2 when possible. |
| Tier 4 | News articles, social posts, scanner observations. | Signal only; never enough for direct-to-block. |

### Candidate pipeline

```text
collect sources
  -> normalize CVE/product/ecosystem/slug/affected versions
  -> enrich with KEV/NVD/EPSS/vendor references
  -> prioritize by exploitation, reachability, popularity, and impact
  -> classify WAF feasibility
  -> create logonly candidate with source links
  -> review local WAF stats
  -> promote to challenge/block only after burn-in
```

### Suggested priority signals

| Signal | Priority impact |
| --- | --- |
| CISA KEV listed | Very high. |
| Unauthenticated remote exploit | Very high. |
| RCE, arbitrary file upload, arbitrary file write, auth bypass, SQLi, deserialization, template injection | High. |
| Public PoC or observed exploit traffic | High. |
| Top CMS/plugin/package by installed base or local exposure | High. |
| High EPSS | Medium/high, depending on exploit class. |
| Authenticated admin-only issue | Usually lower for edge WAF. |
| No stable request fingerprint | Do not implement as blocking WAF rule. |

### WAF feasibility states

| State | Meaning | Default action |
| --- | --- | --- |
| `source_only` | CVE exists, but no safe request fingerprint yet. | Track only; no Lua rule. |
| `candidate_logonly` | Has plausible endpoint/payload markers, but needs field data. | Add `logonly` rule and stats. |
| `candidate_challenge` | Strong fingerprint with low expected FP but not enough block confidence. | Consider `challenge` after burn-in. |
| `block_ready` | Exact exploit shape with near-zero legitimate use. | Consider `block`; opt into `waf_security` per CVE/rule. |
| `not_waf_suitable` | Too broad, authenticated-only, no stable edge signal, or high FP risk. | Do not implement in WAF. |

### Candidate record shape

Each CVE candidate should be representable as structured data before it becomes Lua code:

```json
{
  "cve": "CVE-2026-0740",
  "ecosystem": "wordpress_plugin",
  "product": "Ninja Forms",
  "slug": "ninja-forms",
  "sources": [
    "https://wpscan.com/...",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-0740",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
  ],
  "kev": true,
  "epss": 0.91,
  "cvss": 9.8,
  "exploit_classes": ["unauthenticated_upload"],
  "waf_feasibility": "candidate_logonly",
  "suggested_mode": "logonly",
  "needs": [
    "exact endpoint",
    "exact action parameter",
    "positive PoC request",
    "negative legitimate form submission test"
  ]
}
```

## Initial ACSC CMS campaign candidates

The following products/CVEs should be evaluated for concrete request fingerprints before any blocking mode is selected:

| Product | CVE(s) | Initial mode | Notes |
| --- | --- | --- | --- |
| Simple File List WordPress plugin | `CVE-2025-34085`, `CVE-2020-36847` | `logonly` | May share one detector if exploit shape is identical. |
| WavePlayer WordPress plugin | `CVE-2025-12057` | `logonly` | Require exact endpoint/action/payload. |
| BerqWP WordPress plugin | `CVE-2025-7443` | `logonly` | Require exact endpoint/action/payload. |
| WPBookit WordPress plugin | `CVE-2025-7852` | `logonly` | Require exact endpoint/action/payload. |
| Ninja Forms WordPress plugin | `CVE-2026-0740` | `logonly` | Generic `admin-ajax.php` must not be enough. |
| ThemeREX Addons WordPress plugin | `CVE-2026-1969` | `logonly` | Require exact vulnerable action. |
| Breeze Cache WordPress plugin | `CVE-2026-3844` | `logonly` | Cache/admin endpoints need careful FP review. |
| pay-uz WordPress plugin | `CVE-2026-31843` | `logonly` | Require exact exploit route. |
| ACF Extended WordPress plugin | `CVE-2025-13486` | `logonly` | ACF-related legitimate admin traffic is common. |
| Sneeit Framework | `CVE-2025-6389` | `logonly` | Require exact framework endpoint. |
| WPvivid Backup WordPress plugin | `CVE-2026-1357` | `logonly` | Backup/restore endpoints are high FP risk unless exact exploit shape is known. |
| Gravity Forms WordPress plugin | `CVE-2025-12352` | `logonly` | Form submissions are common; require exploit-specific payload. |
| GutenKit / Hunk Companion WordPress plugin | likely `CVE-2024-9234` | `logonly` | Confirm CVE mapping before enabling. |
| Craft CMS | `CVE-2025-32432` | `logonly` | Promote only for exact RCE/template exploit shape. |
| MaxSite CMS | `CVE-2026-3395` | `logonly` | Require exact endpoint and payload. |
| MetInfo CMS | `CVE-2026-29014` | `logonly` | Require exact endpoint and payload. |
| Joomla JCE | `CVE-2026-48907` | `logonly` | Upload vectors may become block candidates if endpoint and PHP payload are exact. |

## Implementation phases

### Phase 1: Registry and config plumbing

- Reserve `10000+` IDs for CVE rules.
- Add `WAF_CVE` as a reason family.
- Extend Go rule metadata with optional CVE/product fields.
- Add support for explicit `GroupName = "cve"` rather than deriving all groups from `id / 100`.
- Add optional `CVE_<year>_<suffix>` aliases for `waf_security` thresholds.
- Keep `RULE_<id>` overrides backwards-compatible.
- Ensure WAF hit events can carry CVE metadata derived from rule registry entries.

### Phase 2: Lua detector framework

- Add CVE detector call sites in `configs/lua/cfm_waf.lua`.
- Add detector helpers in `configs/lua/cfm_waf_detectors.lua`.
- Emit `WAF_CVE:CVE_YYYY_NNNN:PRODUCT:TAG` reasons.
- Start all ACSC CMS CVE rules in `logonly` unless the exploit shape is exact and near-zero FP.

### Phase 3: Tests and parity checks

- Update Lua/Go rule ID parity tests for `10000+` IDs.
- Add unit tests for CVE alias parsing.
- Add Lua tests for representative positive and negative request shapes.
- Add negative tests for passive plugin probes and legitimate CMS/admin requests.

### Phase 4: Burn-in and promotion

- Deploy in `logonly`.
- Review hit samples across production traffic.
- Promote exact high-confidence rules to `challenge` or `block` individually.
- Enable `CVE_<year>_<suffix> = 1` or `RULE_<id> = 1` in `waf_security` only after confirming low FP risk.

### Phase 5: Observability and reporting

- Add top-CVE and top-blocked-CVE summaries to WAF engine reporting.
- Add compact `CVE` display for recent WAF events when the event maps to a CVE rule.
- Add CVE/product/exploit-class fields to WAF-originated notifier payloads.
- Add CVE fields to `waf_security` alert `Extra` metadata so sinks do not parse free-form messages.
- Track enough per-CVE counters to compare source intelligence against local hit volume and promotion value.

## Example Lua skeleton

```lua
-- CFG
rule_cve_2026_0740_ninja_forms = "logonly"

-- RULE_IDS
rule_cve_2026_0740_ninja_forms = 10001

-- check(ctx)
do
  local mode = rule_mode(CFG.rule_cve_2026_0740_ninja_forms, "logonly")
  if mode ~= "disabled" then
    local hit, tag = det.detect_cve_2026_0740_ninja_forms(ctx)
    if hit then
      if record(
        "WAF_CVE:CVE_2026_0740:NINJA_FORMS:" .. tag,
        ttl,
        mode,
        RULE_IDS.rule_cve_2026_0740_ninja_forms
      ) then
        goto done
      end
    end
  end
end
```

Detector skeleton:

```lua
function _M.detect_cve_2026_0740_ninja_forms(ctx)
  local uri = lower(ctx.uri or "")
  local method = upper(ctx.method or "")

  if method ~= "POST" then return false end
  if uri ~= "/wp-admin/admin-ajax.php" then return false end

  local args = lower(ctx.args or "")
  local body = lower(ctx.body or "")
  local joined = args .. "&" .. body

  -- Replace placeholders with exact public exploit shape after validation.
  if has(joined, "action=<exact_vulnerable_action>") and
     has(joined, "<exact_exploit_marker>") then
    return true, "EXACT_ACTION_PAYLOAD"
  end

  return false
end
```

## Open questions

- Should all named vulnerabilities use one `WAF_CVE` family, or should CMS-specific rules use `WAF_CMS_CVE`?
- Should CVE aliases live only in `waf_security`, or should the WAF rule override layer also accept CVE aliases?
- How should the UI present one rule mapped to multiple CVEs?
- Should passive CVE reconnaissance become a separate non-blocking family later, such as `WAF_CVE_RECON`?
- What is the minimum sample size and deployment window before promoting a CVE rule from `logonly` to `challenge` or `block`?
- Should CVE statistics be stored only in the existing WAF event summary path, or also in a dedicated long-retention per-CVE rollup?

## Safety checklist for every new CVE rule

Before merging a new CVE detector:

- [ ] The detector requires exact method and endpoint constraints.
- [ ] The detector requires exploit-specific request markers.
- [ ] Passive version/plugin probes are negative tests.
- [ ] Legitimate CMS/admin/form traffic is considered in negative tests.
- [ ] Default mode is justified in comments or docs.
- [ ] Rule ID is stable and in the CVE range.
- [ ] Go registry mirrors Lua ID and metadata.
- [ ] Logs, summaries, and notifiers can display `CVE: CVE-YYYY-NNNN` for the rule.
- [ ] Source links and source confidence are recorded for the candidate.
- [ ] `waf_security` autoblock behavior is explicit and not accidentally family-armed.
- [ ] Lua syntax and Lua test suite pass.
- [ ] Go tests covering registry/parity/config pass.
