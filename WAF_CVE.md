# WAF CVE Detection — implemented state & "CVE hunting" workflow

Companion to [`WAF_CVE_PLAN.md`](WAF_CVE_PLAN.md). The plan is the *design*;
this doc is the **as-built reference** (what actually ships today) plus the
step-by-step recipe for adding the next CVE detector. When the two disagree,
this doc and the code win — update this doc in the same change that lands new
CVE work.

---

## 1. What is implemented today

The CVE framework is live end-to-end. A single-request, near-zero-FP CVE
can be detected in-path, attributed to its CVE id, and (opt-in) turned into a
persistent nft block with a CVE-named notification.

### 1.1 Rule identity — the `10000+` band

CVE detectors use stable numeric IDs in the **`10000–99999`** band, kept out
of the legacy `1xx–9xx` families (the `9xx` band is reserved for behavioural
rules and is too small for long-term CVE coverage).

- **Source of truth:** the `RULE_IDS` table in
  `configs/lua/cfm_waf.lua` (Lua is canonical).
- **Go mirror:** `wafRuleIDs` in `internal/webdetector/waf_rule_ids.go`.
  Every Lua id has a matching Go entry with `ReasonFamily: "WAF_CVE"`.
- **Parity guard:** `TestWAFRuleIDs_LuaParity` parses the Lua table at test
  time and diffs it against the Go mirror — drift fails CI.
- **Grouping:** `wafRuleGroupNames[100] = "cve"` labels the whole `10000+`
  band (`id/100` for a `100xx` id lands in group `100`). `TestWAFRuleIDs_GroupingDigits`
  accepts `100–999` **or** `10000–99999`.

> **Historical note:** `rule_log4shell` (id `328`) predates this framework and
> keeps its legacy id, but *already* reports the `WAF_CVE` reason family. So
> `WAF_CVE` is not brand-new — the `10000+` band and the notification plumbing
> are.

### 1.2 Reason family & runtime reason format

All CVE rules emit the **`WAF_CVE`** reason family. The full runtime reason is:

```
WAF_CVE:CVE_<year>_<suffix>:<PRODUCT>:<TAG>
```

e.g. `WAF_CVE:CVE_2025_34085:SIMPLE_FILE_LIST:RENAME_TO_PHP`. The `<TAG>`
distinguishes exploit legs of the same CVE (see the Simple File List detector,
which tags `RENAME_TO_PHP` vs `UPLOAD_PHP`).

The `CVE_<year>_<suffix>` segment uses **underscores** in the reason (Lua/log
friendly) and is converted to the canonical dashed id for display.

### 1.3 CVE-named notifications

`internal/detectors/wafsec/detector.go` turns a `WAF_CVE` autoblock into a
notification whose `Kind` names the concrete CVE, not the generic family:

- `cveFromReason(reason)` pulls the second colon-segment and dash-converts it:
  `WAF_CVE:CVE_2025_34085:… → CVE-2025-34085`. It returns `""` for a
  `WAF_CVE` reason with no `CVE_*` token (e.g. a future `WAF_CVE:LOG4SHELL:…`),
  so the caller falls back to the plain `WAF/CVE` label.
- The alert `Kind` becomes `WAF/CVE-2025-34085`; `Extra["cve"]` carries the id
  for sinks so they never parse free-form message text. `Extra["rule_id"]`
  cross-references the Lua/Go registry.

So a Slack/mail line reads e.g. `WAF/CVE-2025-34085` — exactly the format the
operator asked for when scoping this work.

### 1.4 waf_security autoblock — **armed by default, held per-rule**

`WAF_CVE` follows the normal block-rule rule: it has an edge-`block` rule
(10001) so it **arms to 1 by default**, exactly like `WAF_SQLI`/`WAF_RCE`/etc.
The reason is deliberate — the operator wants CVE hits to *both* nft-ban the
source *and* surface on Slack/mail, and an **un-armed family notifies nothing**
(`wafsec` drops a family whose threshold is `0` before it ever reaches the
sink). So `CVE = 0` would silence the very alerts the `block` tier exists to
produce.

- `wafSecurityFamilies` (`internal/detectors/waf_security_register.go`) arms a
  family by default *iff* it has an edge-`block` rule (plus `WAF_BACKDOOR`,
  armed ahead of its first block rule):

  ```go
  if webdetector.WAFFamilyHasBlockRule(fam) || fam == "WAF_BACKDOOR" {
      def = 1
  }
  ```

  (`WAF_WEBSHELL` was held at `0` through burn-in — arming it nft-bans a source
  that GETs `/c99.php`, which includes benign scanners — but as of 2026-07-18 the
  operator runs it armed fleet-wide with acceptable collateral, so it now arms to
  `1` like the rest; exempt a scanner with `ALLOW_UA_CONTAINS`/`ALLOW_NETS` or
  hold rule 413 with `RULE_413 = 0` if needed.)
  `TestWAFSecurityFamilyCoverage` asserts `WAF_CVE` **and** `WAF_WEBSHELL`
  default to `1`.

- **`WAF_CVE` is heterogeneous** — it collects many CVEs of varying FP
  confidence under one family. Because the family is armed, a
  **lower-confidence CVE rule must ship with a per-rule `RULE_<id> = 0`
  override in the SAME change that adds it** (the per-rule override wins over
  the family threshold), holding just that rule while the family stays armed
  for the high-confidence ones. This is the inverse of the old "family opt-in"
  stance: arm the family, hold the doubtful rules.

- **Watch-first burn-in without real bans:** `DRY_RUN = 1` in `[waf_security]`
  still emits the Slack/mail alerts (`Extra["enforcement"]="dryrun"`) but skips
  the nft ban. Flip it off once the stats look clean.

- The edge action (`disabled`/`logonly`/`challenge`/`block`) is independent of
  autoblock arming and is controlled per rule via the CFG key
  (`rule_cve_… = "block"`) or a per-vhost override.

### 1.5 Worked example — the Simple File List detector (rule 10001)

**Simple File List (WordPress) — `CVE-2025-34085` / `CVE-2020-36847`**
(unauthenticated upload → rename → RCE). One detector covers **both** CVEs
(same plugin, same endpoints, same exploit); the reason carries the
campaign-primary `CVE-2025-34085`.

| Field | Value |
| --- | --- |
| Rule name | `rule_cve_simple_file_list_upload` |
| Rule id | `10001` |
| Edge default | `block` (both exploit legs are exact, near-zero FP) |
| Autoblock | **armed** (`WAF_CVE` family default `1`) → 6h nft ban + `WAF/CVE-2025-34085` Slack/mail |
| Detector | `_M.detect_cve_simple_file_list_upload(uri, method, args, body, headers)` in `configs/lua/cfm_waf_detectors.lua` |
| Tests | `scripts/tests/cfm_waf_cve_simple_file_list_test.lua` |

Two legs, keyed on the **exact plugin endpoints** (not on guessable param
names):

- `…/simple-file-list/ee-file-engine.php` renaming a stored upload **to** a
  PHP-executable extension → tag `RENAME_TO_PHP`. Extension match
  (`_cve_sfl_has_exec_ext`) covers `.php[0-9]?`, `.pht`, `.phtm`, `.phtml`,
  `.phar` at a value boundary — kept in step with `bad_fname()` (rule 401).
- `…/simple-file-list/ee-upload-engine.php` carrying PHP content → tag
  `UPLOAD_PHP`. This leg **delegates to the hardened rule-402 scanner**
  `_M.detect_upload_content(body, headers)` (requires `multipart/form-data`
  and a binary-safe short-echo check) rather than a naive `<?php` substring,
  which would reintroduce the documented rule-402 image-body false positive.

Both PoCs were sourced from public exploit code
(`0xGunrunner/CVE-2025-34085`, and the CVE-2020-36847 upload/rename PoC), not
from memory — see §3.

---

## 2. Candidate status (the ACSC campaign shortlist — WordPress/Joomla only)

**Scope: WordPress and Joomla only.** The fleet this WAF protects hosts
WordPress and Joomla sites, so CVEs for other/standalone CMSs are **out of
scope** — a detector for software nobody runs is pure FP surface and
maintenance cost for zero protection. The ACSC shortlist's non-WP/Joomla
entries are dropped: **Craft CMS** (`CVE-2025-32432`), **MaxSite CMS**
(`CVE-2026-3395`), **MetInfo CMS** (`CVE-2026-29014`). Revisit only if the
hosting mix changes.

Sixteen implemented; the rest are WordPress/Joomla candidates awaiting a
validated exact request shape:

| Product / CVE | Status |
| --- | --- |
| Simple File List (`CVE-2025-34085` / `CVE-2020-36847`) | ✅ **implemented** (rule 10001) |
| Joomla JCE (`CVE-2026-48907`) | ✅ **implemented** (rule 10002) — `option=com_jce` + `profiles.import` + php-exec upload |
| Ninja Forms (`CVE-2026-0740`) | ✅ **implemented** (rule 10003) — `action=nf_fu_upload` + (php-exec upload OR `image_jpg` traversal) |
| LiteSpeed Cache (`CVE-2024-28000`) | ✅ **implemented** (rule 10004) — `litespeed_hash`/`litespeed_role` cookie (unauth privesc brute-force) |
| Slider Revolution (`CVE-2015-1579` + classic upload RCE) | ✅ **implemented** (rule 10005) — behavioural virtual-patch: `revslider_show_image`+`../` LFI, `revslider_ajax_action`+`update_plugin` unauth upload |
| W3 Total Cache (`CVE-2026-5032` + `CVE-2025-9501`) | ✅ **implemented** (rule 10006) — `User-Agent: W3 Total Cache` token-leak + `mfunc`/`mclude` in a comment POST (mfunc eval RCE) |
| Post SMTP (`CVE-2025-11833` + `CVE-2023-6875`) | ✅ **implemented** (rule 10007) — unauth `/wp-json/post-smtp/` (get-log/connect-app) or `postman_email_log` page → email-log/reset-link disclosure |
| Avada / Fusion Builder (`CVE-2026-6279` + `CVE-2026-8713`) | ✅ **implemented** (rule 10008) — `fusion_get_widget_markup` + `render_logics` base64→dangerous callable (RCE); `fusion_form_submit_ajax` + `privacy_expiration_action` (file delete) |
| Kirki (`CVE-2026-8206`) | ✅ **implemented** (rule 10009) — unauth `POST /wp-json/KirkiComponentLibrary/v1/kirki-forgot-password` + `username`&`email` → account takeover (reset link to attacker) |
| Multi Uploader for Gravity Forms (`CVE-2025-23921`) | ✅ **implemented** (rule 10010) — `gf_page=upload` + `gform_unique_id` traversal→`.phtml` (php-exec in field value, not `filename=`, so rule 401 misses it) |
| WordPress **core** "wp2shell" (`CVE-2026-63030` + `CVE-2026-60137`) | ✅ **implemented** (rule 10011) — batch-endpoint (`batch/v1`) POST; `"///"` desync primer (63030 route confusion) → `BATCH_DESYNC`, and SQL breakout in the integer-only `author_exclude`/`author_not_in` param (60137 core SQLi) → `BATCH_SQLI`. Two CVE ids, one rule. Affects 6.9–6.9.4 / 7.0–7.0.1; public PoC, actively exploited |
| WooCommerce Payments (`CVE-2023-28121`) | ✅ **implemented** (rule 10012) — `X-WCPAY-Platform-Checkout-User` request header trusted as the current user id (unauth auth-bypass→privesc); keyed on header presence, all methods. Server-set by WooPay only, so near-zero FP; exempt genuine WooPay nets via `ALLOW_NETS` |
| Gravity SMTP (`CVE-2026-4020`) | ✅ **implemented** (rule 10013) — unauth REST route `/gravitysmtp/v1/tests/mock-data` (`permission_callback=true`) dumps the full System Report (versions/paths/plugins/API keys). Keyed on the plugin-unique route (both permalink forms) + UNAUTH gate (only legit caller is the wp-admin settings screen) |
| SP Page Builder (Joomla, `CVE-2026-48908`) | ✅ **implemented** (rule 10014) — `com_sppagebuilder` + `task=asset.upload*` (uploadCustomIcon/uploadImage/uploadFont) unauth arbitrary upload→RCE ("ANTONKILL"). Runs before rules 401/414 for CVE attribution; keyed on component+task + a php-exec payload (direct filename / php-in-zip / php content), reusing the hardened upload detectors. Body-budget caveat: a php entry past `waf_body_max_len` is ClamAV's backstop |
| Elementor Pro Forms (`CVE-2026-32475`) | ✅ **implemented** (rule 10016) — Elementor Pro <4.2.2 File Upload field: `validation()` `return`s (vs `continue`) on an empty (`UPLOAD_ERR_NO_FILE`) first part, skipping the extension blocklist for a following `.php` part that `process_field()` still moves into public `wp-content/uploads/elementor/forms/`. POST `admin-ajax.php` `action=elementor_pro_forms_send_form` (nopriv) + a php-exec upload filename — the surviving file *extension* is the vuln (`process_field()` keeps `pathinfo($name, EXTENSION)`), so a content leg is intentionally omitted (it would mis-attribute benign php-text field pastes / non-PHP payloads; raw php content is already covered by the armed generic rule 402). Runs before rule 401 for CVE attribution; reuses the hardened rule-401 detector. Near-zero FP (a legit Elementor form upload never carries a php-executable file). The generic rule 401 already blocks the straightforward `.php` upload fleet-wide; this rule adds CVE attribution. Note: id **10015 is skipped** (the removed vBulletin rule below) |
| WordPress **core** page-template traversal (`CVE-2026-87902`, GHSA-7hp8-65ch-5whp) | ✅ **implemented** (rule 10017, + rule 103) — WordPress 4.7.0–7.1.1 (fixed 7.1.2 and every branch back to 4.7.37): `get_page_template()` builds `page-{$pagename}.php` from the url-decoded `pagename` query var without the `..` check, so a readable local `.php` outside the theme is included (RCE with `pearcmd.php` when `register_argc_argv=On`; needs a top-level `page-*` theme dir — Twenty Twelve/Fourteen, Neve, Hestia, Sydney). Source: the WordPress advisory + Wordfence entry (operator-supplied; no public PoC at release). **10017** fires on a `pagename` value — query string, urlencoded or multipart POST (WP reads `$_POST` first), keys decoded, every duplicate checked — holding a `..` segment; a real pagename is a slug path, never one. Armed: 6h ban + `WAF/CVE-2026-87902` alert. The pretty-permalink route (the path itself becomes `pagename`) was **invisible** to the WAF: `ctx.uri` is `ngx.var.uri`, already decoded and dot-segment-resolved by nginx, while the origin gets the raw path. **Rule 103** (`rule_traversal_raw_path`, `WAF_TRAVERSAL`, block) closes that blind spot generically from `ctx.raw_uri` — named as traversal, not as this CVE, because it also catches every other raw-path sweep; the family's autoblock is held, so it is a 403 without an alert. Web edge only (the panel gate passes no `raw_uri`). |
| vBulletin (`CVE-2026-61511`) | ⛔ **block rule REMOVED** (was rule 10015) — see the "Removed" note below. Only a **logonly** technique-level phpfuck detector (rule 439, `WAF_BACKDOOR`) remains; there is no CVE-attributed block/ban for this vector. |
| WavePlayer, BerqWP, WPBookit, ThemeREX, Breeze, pay-uz, ACF Extended, Sneeit, WPvivid, Gravity Forms, GutenKit/Hunk (all WordPress plugins) | candidate — need exact endpoint/action/payload before any mode above `logonly` |

Keep the plan doc's candidate table as the backlog; update the ✅ column here
as detectors land.

**Removed — vBulletin `runMaths()` (CVE-2026-61511), block rule 10015.** A
route-anchored, block-tier phpfuck detector was prototyped and, over three
adversarial review rounds, **removed** as too dangerous for a forum-hosting
fleet. The signature scores a "phpfuck" blob — a dense run of parenthesised
digit literals joined by `.` and XORed with `^`. The fatal flaw was a
false-positive **ban**: an ordinary *spaced* math forum post
(`(1.5)^2 + (2.5)^2 + …`) is sent by the browser as `application/x-www-form-
urlencoded`, where each space becomes `+`; `normalize` does not turn `+` back
into a space, so with `+` in the run charset the whole expression bridged into
one qualifying run → `block` → `WAF_CVE` 6h nft ban of a real user on the
`ajax/render` preview route. Removing `+` from the charset (to fix the FP)
re-opens a no-op-operator bypass, and projecting the payload the way the sink
does re-merges legit code — the defences collide. Since the endpoint gate
cannot separate a benign math post from the attack at request time, an
enforcement rule here bans real users; the correct fix is **patching vBulletin
(≥6.2.2)**. What remains is the logonly rule 439 (below), for visibility only.
It is best-effort: body-only (misses GET-args delivery), tight-charset (no-op /
strip-char interspersing evades), and never to be promoted above logonly.

**Fleet-driven priority (2026-07):** the operator's own plugin scan (1,473
critical-unauth installs across 495 sites) produced a ranked WAF-rule worklist
(rule groups R1–R9). Tier-1 net-new detectors from it, in rollout order:
**R6 LiteSpeed** (✅ 10004) → **R1 W3TC** (✅ 10006) → **R7 post-smtp**
(✅ 10007) → **R4 Fusion Builder** (✅ 10008 — `fusion_*` nopriv ajax). That
completes every "block now" net-new detector in the rollout. R3 upload / R5
`wp-config` traversal are covered by the generic rules (401 / 101).

**R2 (object injection) → rule 329** (`WAF_RCE:PHP_OBJECT_INJECTION`, armed
block): rather than promote the broad rule 306 (`WAF_SERIALIZE`, challenge,
**args-only**) — which would block/ban legit *authenticated* serialized blobs
(WooCommerce/Elementor/WPML) — a dedicated **unauth-gated** detector fires on an
`O:N:"…"`/`C:N:"…"` object marker in args OR body (incl. base64, closing rule
304's logonly gap) and emits `WAF_RCE` (already armed). Covers the ~153-site
object-injection exposure in one detector; rule 306 keeps the authenticated case
at challenge. It is **not** a `10xxx` WAF_CVE rule because it's a vuln *class*,
not one named CVE.

**R8 (jet SQLi) → skipped.** Generic rule 301 (`WAF_SQLI`, armed block) already
catches+bans the keyword markers globally; JetEngine's novel injections are
keyword-less operator/blind SQLi that can't be signatured without FPing legit
filter traffic (the fleet spec's own note). Fix = upgrade JetEngine on the
affected sites.

**Behavioural virtual-patch (a valid WAF_CVE flavour):** rule 10005
(Slider Revolution) is not a version match — it keys on the known-malicious
*request shapes* (`revslider_show_image` + `../`, and unauth
`revslider_ajax_action` + `update_plugin`). Those shapes are malicious on **any**
version, so this protects the whole fleet spread rather than only the one install
a version check would flag, and it fills a real gap (a revslider `update_plugin`
ZIP-with-PHP upload is not caught by the generic upload rules). Use this pattern
when a plugin has a long history of the same abused endpoints and version-specific
CVE matching would under-protect. Gate any leg whose action is also legitimate for
an admin on UNAUTH (absence of a `wordpress_logged_in_*` cookie) — a forgeable
FP-reduction heuristic, not a security control.

---

## 3. "CVE hunting!" — adding a new CVE detector

The repeatable recipe. Treat every step as required; the safety checklist at
the end mirrors `WAF_CVE_PLAN.md` and CI.

### Step 0 — Get the *exact* exploit shape (never from memory)

My (assistant) knowledge cutoff means 2025–2026 CVEs are **not** reliably in
training data. **Do not invent signatures.** Obtain the request shape from a
primary source, in rough order of confidence:

1. A **public PoC / exploit script** (GitHub, exploit-db) — read the actual
   HTTP request it builds: method, path, param/field names, marker payload.
2. The **vendor patch / diff** — shows the vulnerable endpoint and the input
   that reaches the sink.
3. **NVD → references** for the CVE, then follow to advisory/PoC.
4. **Operator-supplied** PoC, packet capture, or `cfm.waf.log` samples of the
   real attack.

Pin the exact: **HTTP method**, **endpoint path** (prefer a
plugin/product-unique path segment), and a **request-body/param marker** that
only the exploit carries. If you can only get a param *name* that legitimate
traffic also uses, the shape is not exact enough — keep it `logonly` or don't
ship it.

### Step 1 — Pick a stable id in the `10000+` band

Next free id ≥ `10001`. **Never renumber** an existing one (operators
reference ids in exclusions, dashboards, tickets).

### Step 2 — Lua detector (`configs/lua/cfm_waf_detectors.lua`)

Write `_M.detect_cve_<slug>(uri, method, args, body, headers)` that returns a
`<TAG>` string on a hit or `nil` otherwise. Rules:

- Gate on **method** and the **exact endpoint** first (cheap, and the main FP
  guard). Key on the endpoint/marker, **not** on param names alone.
- **Reuse hardened helpers** — `_M.detect_upload_content`, `has_php_short_echo`,
  `bad_fname`, etc. — instead of re-rolling body scans. A naive `<?php`
  substring on a raw body is a known FP source (large images).
- Use `cap(…, CFG.max_scan_len)` before lowercasing large bodies; use
  `%f[%W]` value-boundary frontier patterns for extension matches.
- Must parse under **LuaJIT** (`goto` is used elsewhere): `make lua`.

### Step 3 — Wire the check site (`configs/lua/cfm_waf.lua`)

Add the CFG default and the `RULE_IDS` entry, then a `check()` call site:

```lua
-- CFG
rule_cve_<slug> = "block",   -- or "logonly"/"challenge"; justify in a comment

-- RULE_IDS  (10xxx band)
rule_cve_<slug> = 10002,

-- check(ctx)  (order matters: first match wins via `goto done`)
do
  local mode = rule_mode(CFG.rule_cve_<slug>, "block")
  if mode ~= "disabled" and body_inspect_ok then
    local tag = det.detect_cve_<slug>(uri, m_lower, args, body, headers)
    if tag then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      if record("WAF_CVE:CVE_<year>_<suffix>:<PRODUCT>:" .. tag, ttl, mode, RULE_IDS.rule_cve_<slug>) then goto done end
    end
  end
end
```

Place the call site with rule-order in mind — an earlier matching rule wins
attribution. For upload/RCE CVEs, put it before the generic upload rules so the
hit is attributed to the CVE.

### Step 4 — Go registry mirror (`internal/webdetector/waf_rule_ids.go`)

Add the matching entry (parity test requires it):

```go
{ID: 10002, Name: "rule_cve_<slug>", ReasonFamily: "WAF_CVE", DefaultMode: "block"},
```

### Step 5 — Decide autoblock intent **in the same change**

`WAF_CVE` is **armed by default** (family threshold `1`), so a new `block`-tier
CVE rule autoblocks the moment it lands. Decide, per new rule:

- **High-confidence, exact shape** (like 10001) → leave it armed. Hits get a 6h
  nft ban + `WAF/CVE-YYYY-NNNN` Slack/mail. This is the common case.
- **Lower-confidence** → ship a per-rule `RULE_<id> = 0` in the reference
  `configs/detectors.conf` in the SAME change (the per-rule override wins over
  the family threshold), holding just that rule while the family stays armed for
  the good ones. Note it in `[waf_security]`.
- Operators can burn-in the whole family with `DRY_RUN = 1` (alerts, no bans).

Do **not** un-arm the whole `WAF_CVE` family for one doubtful rule — that
silences the alerts for every other CVE. Hold the rule, not the family.

### Step 6 — Tests

- **Lua** (`scripts/tests/cfm_waf_cve_<slug>_test.lua`): positive cases for
  every exploit leg/`<TAG>`, plus negatives — wrong method, wrong endpoint,
  near-miss extensions, legit traffic to the same product (passive version
  probes, normal uploads). Run `make test-lua`.
- **Go**: `TestWAFRuleIDs_LuaParity`, `TestWAFRuleIDs_GroupingDigits`,
  `TestWAFSecurityFamilyCoverage` must stay green. If the new rule ships at
  `block`, the coverage test already expects `WAF_CVE` to stay at default `0`
  — no change needed there.

### Step 7 — Notification

No code needed for the CVE name to appear — `cveFromReason` derives
`WAF/CVE-YYYY-NNNN` from the reason automatically, provided the reason is
`WAF_CVE:CVE_<year>_<suffix>:…`. Just get the reason format right in Step 3.

### Step 8 — Docs & changelog

- Flip the candidate to ✅ in §2 here and note the rule id.
- Add a `CHANGELOG.md` `[Unreleased] → Added` bullet (operator-facing).
- Follow `docs/challenge-waf-release-checklist.md` for the edge reload gate.

### Safety checklist (every new CVE rule)

- [ ] Exact method **and** endpoint constraints.
- [ ] Exploit-specific request marker (not a param name legit traffic shares).
- [ ] Passive version/plugin probes are **negative** tests.
- [ ] Legit CMS/admin/form/upload traffic considered in negative tests.
- [ ] Default edge mode justified in a comment.
- [ ] Id stable and in the `10000+` band; Go mirrors Lua id + metadata.
- [ ] Reason is `WAF_CVE:CVE_YYYY_NNNN:PRODUCT:TAG` so the notifier names it.
- [ ] `waf_security` autoblock is explicit: `WAF_CVE` is armed by default, so a
      high-confidence rule stays armed and a lower-confidence one ships with a
      per-rule `RULE_<id> = 0` (hold the rule, not the family).
- [ ] `make lua`, `make test-lua`, and `go test ./internal/...` pass.
- [ ] PoC/patch source link recorded; **no signatures written from memory**.
