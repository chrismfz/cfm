# CFM WAF and Challenge-Clearance Boundary

## Status

The WAF rebuild is complete. **53 detectors across 9 rule-ID groups** (1xx-9xx)
inspect every dynamic request before it reaches origin. Severity-aggregation
returns the strongest rule's action; per-vhost exclusions let operators
whitelist specific rules on noisy hosts; hit-rate counters and the per-
trigger JSON hit log (`cfm.waf.log`) give operators data-driven evidence
before promoting any rule from `logonly` to `challenge` to `block`.

Open follow-ups (none blocking):

- **Promotion review** — most of the new detectors (Phase 1-5 + extensions)
  ship at `logonly`. Walk `cfm webtop waf hit-rates --hours 168` after a week
  of production data and promote well-behaved rules per the playbook below.
- **Inspector-audit deferred items** — see "Known gaps" item 8.

The git log on `configs/lua/cfm_waf*.lua` and `internal/webdetector/waf_*.go`
is the canonical record of what was shipped when. A snapshot of the rules and
their default modes lives in [Rule IDs](#rule-ids) below.

---

## Security principle

- **Challenge** is a bot/human gate. A solved `cfm_clearance` proves the client passed the gate.
- **WAF** is payload inspection. A clearance does **not** prove the request payload is safe.
- They complement each other. Clearance must skip repeated challenge gates; it must **never** skip exploit detection or block decisions.

Threat surface (shared hosting): outdated WordPress/Joomla/Drupal, vulnerable plugins, public upload handlers, admin AJAX/REST/XML-RPC, file managers, plugin/theme editors, backup/migration plugins, hijacked admin sessions. WAF inspection must continue post-clearance because authenticated attackers and stolen browser sessions are in scope.

---

## Severity model

Every WAF rule produces an action:

```
disabled (0) < logonly (1) < challenge (2) < block (3)
```

`_M.check` collects every match into a `hits` array and returns the strongest action. A `block` hit short-circuits later detectors (block is the cap). Rule order no longer affects enforcement.

Return shape: `(hit, reason, ttl, action, hits, waf_rule_id)`. The first four are the original API; `hits` is per-rule diagnostics; `waf_rule_id` is the strongest rule's stable numeric ID (see [Rule IDs](#rule-ids) below).

---

## Operating the WAF

This section is for the operator running the WAF in production. After landing
a new detector or after a stretch of production traffic, the question is
always: are these rules catching real attacks without flagging legit users?
The hit-rate aggregator is what makes that question answerable with data,
not eyeballing.

### Reviewing hit-rates

Run weekly. The window matters — a week of traffic gives a stable rate even
on low-volume vhosts.

```bash
cfm webtop waf hit-rates --hours 168                  # last 7 days, all hosts
cfm webtop waf hit-rates --hours 168 --host site.com  # one vhost
cfm webtop waf hit-rates --hours 168 --hint ok_to_promote  # only candidates
cfm webtop waf hit-rates --json                       # machine-readable
```

Output is one row per registered rule with a `promotion_hint` column. Read
the hint, look up the rule, decide what to do:

| Hint | Condition | Operator action |
|---|---|---|
| `ok_to_promote` | hits > 0 AND rate < 0.01% | Safe to promote one mode level. |
| `silent` | inspected > 0 AND hits == 0 | Verify the rule isn't broken before promoting. Run a known-positive sample (see "Testing a rule fires" below). If it fires, leave at logonly and wait. If not, debug. |
| `review` | 0.01% ≤ rate < 1% | Investigate FP candidates in `cfm.waf.log` before promoting. Tighten the rule or add per-vhost exclusions for noisy hosts. |
| `noisy` | rate ≥ 1% | Clear FP source. Either tighten the detector or add per-vhost exclusions. Don't promote. |
| `n_a` | inspected == 0 | Insufficient data — wait for the flusher (~1 minute) or for traffic. |

### Promoting a rule

```bash
cfm webtop waf set-rule rule_persistence challenge   # logonly → challenge
cfm webtop waf set-rule rule_persistence block       # challenge → block
```

**The playbook (don't skip steps):**

1. Land each new detector with mode `logonly`.
2. Wait at least one full week of production traffic.
3. Promote `logonly → challenge` only if `promotion_hint == ok_to_promote`.
4. Wait at least one more week with no operator complaints.
5. Promote `challenge → block` only if no operator complaints AND
   `promotion_hint == ok_to_promote`.
6. Never go `logonly → block` directly.
7. Per-rule kill-switch: `cfm webtop waf set-rule <name> disabled` — per-worker,
   doesn't survive reload.

False positives become tuning data: adjust score, context, or family — don't
just disable the rule. Most of the time the right move is a per-vhost
exclusion (see [Per-vhost rule exclusions](#per-vhost-rule-exclusions))
rather than disabling globally.

### Testing a rule fires (offline)

Before promoting, verify the rule actually catches its attack class. The
quickest path is a one-off `luajit` invocation that loads the WAF module
and feeds it a hand-crafted body:

```bash
luajit -e '
package.path = "configs/lua/?.lua;" .. package.path
_G.ngx = {
  now=function() return 1 end,
  decode_base64=function() return nil end,
  log=function() end,
  ERR=0, WARN=1, INFO=2,
}
local waf = require("cfm_waf")

-- Disable everything, then enable just the rule under test
local snap = waf.get_config()
for k in pairs(snap) do if k:sub(1,5)=="rule_" then waf.set_rule(k,"disabled") end end
waf.set_rule("rule_php_webshell_body", "challenge")

-- Feed a sample body and print the verdict
local hit, reason, _ttl, action, _hits, rule_id = waf.check({
  uri="/x.php", args="", method="POST", ip="1.2.3.4",
  headers={["Content-Type"]="application/x-www-form-urlencoded"},
  body=[[<?php $tmp=$_POST["k"]; include $tmp;]],
})
print(string.format("hit=%s reason=%s action=%s rule_id=%s",
  tostring(hit), tostring(reason), tostring(action), tostring(rule_id)))
'
```

Output:

```
hit=true reason=WAF_PHP_WEBSHELL_BODY:RAW_DYN_INCLUDE action=challenge rule_id=404
```

This is exactly what `cfm.lua` would see at access-phase time. Useful for:

- **`silent` rules** — confirm the detector is wired up and reachable.
- **`review`/`noisy` rules** — feed real samples from `cfm.waf.log` to
  see what triggers them.
- **New detectors** — sanity-check before pushing to production.

### Investigating FPs in `cfm.waf.log`

Every WAF trigger writes one JSON object per line to `cfm.waf.log`, with
all fields needed for FP investigation: UA, Referer, Content-Type, ASN,
country, action, TTL, and the rule id.

```bash
# Hits for a specific rule
grep '"waf_rule_id":410' /var/log/cfm/cfm.waf.log | jq

# Hits with a specific reason family
grep '"reason":"WAF_DYN_INCLUDE' /var/log/cfm/cfm.waf.log | jq

# Last 24h of hits on a specific vhost
grep '"host":"example.com"' /var/log/cfm/cfm.waf.log | jq
```

---

## False-positive case studies

A live record of FP shapes seen in production, what surfaced them, the
structural mistake the original rule made, and the fix. Treat this as
the **anti-pattern catalogue for new detectors** — every one of these
shipped through the existing tests and the rollout playbook, and was
only caught by reviewing real traffic. Add to this list when a new FP
shape surfaces and a rule is changed to suppress it.

### Catching methodology (what the repeats look like)

The pattern that keeps working:

1. **Collect a representative window** (a few days, all servers) of raw
   `cfm.waf.log` JSON. The forensic fields (`ua`, `referer`, `ct`,
   `asn_name`, `country`) are what let you tell "scraper using
   residential proxy" from "real user on Greek ISP". The fleet-history
   API endpoint strips those fields and truncates per agent — useful for
   dashboards, not for FP hunting.
2. **Aggregate by `(reason, host, ASN, UA family)`**. Anything where
   one (host, ASN) combination dominates a single rule's hits is a
   candidate. Anything from a residential ISP in your home country
   (we use Greek ASNs as the litmus) with a modern realistic UA is a
   stronger candidate.
3. **Read the URI and Content-Type**. Look for:
    - `data:` URIs or `;base64,` in the path (template artifacts)
    - `/wp-admin/` paths (admin tooling)
    - WordPress REST API paths (`/wp-json/…`)
    - `multipart/form-data` content type (binary file uploads)
    - `application/x-www-form-urlencoded` without `charset=UTF-8`
      (legacy ISO-8859-x / windows-125x form posts)
    - Bare-IP `host` headers
4. **Replay the patched detector against the original log**. A short
   harness reading `cfm.waf.log` and re-running the rule's Lua logic
   against the captured URI + body tells you the before/after FP count
   without waiting for a production window. Examples of this harness
   live in the test plans of PR #912 and PR #969.
5. **Stage the fix at the rule's current mode**, never tighter. If the
   rule was `logonly`, fix and re-soak at `logonly`. Promotion is a
   separate decision gated on `cfm webtop waf hit-rates`.

### FP case 1 — `WAF_LONG_PATH` on `data:` URI / base64 template artifacts

**Shape:** 84 events in a 4-day window, dominated by 52 hits on
`mobian.eu` and 11 on `www.ezbeauty.gr`, all from AS32934 Facebook IPs.
Path looked like `/data:text/javascript,setTimeout(function () { … }`
or `/templates/.../slick_carousel/assets/css/data:image/svg+xml;base64,…`.
Same trigger on `tehni.eu/claim-requests/image/jpeg;base64,…` from a
single Greek OTEnet user over a working session (10 hits).

**Root cause:** Bricks Builder (WP) injects inline scripts as
`<script src="data:text/javascript,…">`. Facebook's
`facebookexternalhit` OG-preview crawler dereferences the `src` as if
it were a relative URL. The SP Page Builder Joomla template emits an
unquoted `url(data:image/svg+xml;base64,…)` in a CSS rule, so the
browser resolves it relative to the stylesheet. A broken `<img>` tag
puts `image/jpeg;base64,…` directly into the path. None of those bytes
were ever produced by an attacker — they're template emissions
followed as URLs.

**Why we missed it:** the rule was designed for "single URL path
segment ≥ 800 bytes = base64-stuffed scanner payload". The threshold
was correct; the path classifier had no concept of "this segment is a
template artifact, not a payload".

**Fix:** in `detect_long_path_segment` skip the rule entirely when the
path contains `;base64,` (anywhere) or `data:<type>/<subtype>[,;]`.
Path-wide check, not per-segment, because base64 payloads contain `/`
and the segmenter splits them into many short segments followed by one
extremely long trailing chunk. Documented loophole: an attacker who
prepends `;base64,` to a long payload suppresses **only** this rule —
RCE, traversal, SQLi, and the base64 obfuscation scorer still inspect
the content. Shipped in **PR #912**. Effect: 84 → 3 (all 3 real).

**Lesson for new path-based rules:** before any length-based or
substring-based path check, ask "what artifacts can a CMS template
inject into the rendered HTML that a crawler might follow as a URL?"
Inline `data:` URIs, inline `srcset=` strings, and unquoted `url(…)`
in CSS are the three most common.

### FP case 2 — `WAF_XSS` matching `onerror=` inside `creationError=`

**Shape:** 1 event, but on `/wp-admin/edit.php` of `new.sikia-apartments.gr`
from a real Greek OTEnet IP (109.178.22.113) — a WordPress admin
working with WPML's Advanced Translation Editor. URL:
`/wp-admin/edit.php?post_type=appartments&lang=en&referer=ate&wpml_version=4.9.3&ateJobCreationError=101&jobId=63`.

**Root cause:** `detect_xss` used `string.find(s, "onerror=", 1, true)`
— a plain substring search. The literal bytes `onerror=` appear inside
`creationError=` (`…creati**onerror**=…`), so the substring matches
even though no real XSS attribute is present. The detector had no
concept of HTML attribute syntax — every `on*=` token in an HTML
attribute must be preceded by a delimiter (space, quote, `<`, `;`,
`/`), but the substring check didn't enforce that.

**Why we missed it:** plain-substring matching was chosen for speed,
and the unit tests for `detect_xss` used realistic XSS payloads which
all started with a delimiter. No test exercised the "keyword embedded
in a longer identifier" case.

**Fix:** anchor each event-handler check on a non-word boundary using
the Lua frontier pattern `%f[%w]`. Kept the cheap plain `has()`
precheck so non-XSS requests pay zero pattern-engine cost. Shipped in
**PR #912**. Effect: 7 WAF_XSS events → 6 (the 6 remaining are real
attacks, the one cleared was the WPML FP).

**Lesson for new substring-based rules:** if the substring you're
matching is an English word or a code-token that could legitimately
appear inside a longer identifier, anchor on a word boundary.
`onerror=`, `onload=`, `eval(`, `system(` are the obvious traps;
others surface when you actually look.

### FP case 3 — `WAF_BAD_UTF8` on legitimate non-UTF-8 traffic

**Shape:** 772 events in 4 days across titan + rigel. Almost entirely
on Greek WordPress shops. Top URI paths:

```
377  POST /wp-admin/async-upload.php                ← media library uploads
135  POST /wp-admin/admin-ajax.php                  ← Greek post saves, plugin AJAX
 83  POST /wp-admin/post.php                        ← Greek post editor saves
 59  POST /flexboard/controller.php
 47  POST /landing-mama-ypnos/                      ← Facebook ad landing page
  9  POST /wp-admin/update.php                      ← plugin/theme installer
  7  POST /wp-json/contact-form-7/.../feedback
```

By Content-Type: 236 `application/x-www-form-urlencoded[; charset=UTF-8]`,
59 empty, 15 `multipart/form-data`. By source: 100% Greek-residential
ASNs hitting Greek hosts.

**Root cause:** three legitimate non-UTF-8 input shapes that the
strict Coraza-style walker flagged as BAD_LEAD / BAD_CONT / TRUNC:

1. **Multipart bodies carry raw binary file content** (JPEG/PNG/ZIP/PDF
   bytes). Never UTF-8 by design.
2. **Form posts from pre-charset themes carry single-byte legacy
   encodings.** A Greek "Π" sent as `%D0` (ISO-8859-7) decodes to byte
   0xD0, which looks like a UTF-8 2-byte lead expecting a continuation
   — the next byte is `&` (form separator), not 0x80–0xBF, so the
   walker fires `UTF8_BAD_CONT`. Perfectly legitimate Greek form data.
3. **URLs truncated mid-percent-encoded-UTF-8 by upstream
   redirectors.** Facebook's `facebookexternalhit` crawler chops ad
   landing-page URLs at character boundaries it thinks are safe; the
   resulting URL ends with `%CE%B` (incomplete escape) which
   double-decodes to a stray lead byte. 47 of the 772 events were this
   shape — every one of them came from AS32934 Facebook.

**Why we missed it:** the detector was a faithful port of Coraza's
`validateUtf8Encoding` operator. Coraza ships the operator scoped to
specific variables (`ARGS_NAMES`, `ARGS_VALUES`) for exactly this
reason; we initially applied it to the combined args+body buffer with
all six tags returning. The detector's own commit message flagged
"acceptable at logonly" but underestimated how many legacy WP
deployments still emit non-UTF-8 form data.

**Fix:** the walker returns **only the three encoding-bypass-specific
tags** — `UTF8_OVERLONG`, `UTF8_SURROGATE`, `UTF8_OUT_OF_RANGE`. The
other three tags (BAD_LEAD / BAD_CONT / TRUNC) still drive the cursor
forward internally but never fire as a trigger. RFC-3629-forbidden
2-byte leads (`0xC0` / `0xC1`) followed by a valid continuation are
caught explicitly as `UTF8_OVERLONG` since those leads can only
produce overlong encodings of ASCII. Shipped in **PR #969**. Effect:
772 → 0 FPs cleared, real-attack coverage preserved (replay against
test cases for `%C0%AF` overlong-`/`, surrogate codepoints in UTF-8,
and out-of-range codepoints all still fire).

**Follow-up (2026-06-04):** PR #969 suppressed BAD_LEAD/BAD_CONT/TRUNC but
the three *attack* tags still fired on multipart uploads — a binary file
part is exactly the place where `0xC0`/`0xC1` + continuation pairs (JPEG
SOF markers `0xFFC0`/`0xFFC1`) and `E0`/`F0` leads decoding to overlong /
surrogate codepoints occur by chance. e-vafeiadis.gr logged
`UTF8_OVERLONG` on **every** Greek-admin product-photo save. `detect_bad_utf8`
now **skips the body walk entirely when Content-Type is
`multipart/form-data`** — the encoding-bypass primitive (`%C0%AF` for `/`)
lives in the URL/args, which are still walked, and non-multipart text bodies
(urlencoded / JSON / XML) are still walked so the overlong-slash body bypass
(test 77c) keeps firing. Test 77b now carries real `0xC0`-overlong bytes so
it actually guards the skip.

**Lesson for new encoding-validity rules:** "not UTF-8" is not the
same as "attack". A web property that has been running long enough to
accumulate legacy WP plugins, pre-charset forms, or file-upload
endpoints will produce non-UTF-8 traffic on every benign request.
Before shipping a UTF-8 / charset / encoding validator, enumerate
exactly which malformations are encoding-bypass primitives (overlong,
surrogate, out-of-range, RFC-3629-forbidden leads) and report only
those. Generic "this string is not well-formed UTF-8" is a noise
generator.

### FP case 4 — `WAF_SSRF:SSRF_FTP` on WP All Import admin pages

**Shape:** 4 events, all from one real Greek admin (89.210.235.252,
AS3329 Vodafone-panafon, Chrome 148) on `xml.e-vafeiadis.gr`. URLs
like `/wp-admin/admin.php?page=pmxi-admin-manage&id=11&action=options`.
The admin was managing their WP All Import imports.

**Root cause:** WP All Import (and similar plugins — WPvivid,
UpdraftPlus, BackWPup) legitimately store `ftp://` URLs as plugin
configuration. The admin revisiting the settings page sends GET
requests whose query strings (and form state) echo the saved FTP URL.
`detect_ssrf_proto` saw `ftp://` in args and fired `SSRF_FTP`. The
URL was plugin state, not an attacker-controlled fetch target.

**Why we missed it:** SSRF detection was based on "no benign form
field should carry a `ftp://` value". That assumption held for most
endpoints — but not for WordPress plugin admin pages where the field
value is itself a stored configuration URL.

**Fix:** in the rule call site, when `tag == "SSRF_FTP"` and `uri`
matches `^/wp-admin/`, suppress that tag only. All other SSRF tags
(FILE, GOPHER, DICT, LDAP, TFTP, STRATUM, SFTP, IP-obfuscation
flavours) keep firing on /wp-admin/ because no benign WP plugin
legitimately stores those schemes as state. Shipped in **PR #969**.
Effect: 4 → 0.

**Lesson for new SSRF/protocol-scheme rules:** before adding a scheme
to the scanner list, search the top 200 WordPress plugins (and the
analogous lists for Joomla, Drupal, Magento) for plugins that
legitimately accept that scheme as a config value. `ftp://`,
`sftp://`, and `s3://` are likely; `gopher://`, `dict://`, `file://`
are very unlikely. The narrower the scheme's legitimate use, the
safer the rule.

### FP case 5 — `WAF_PHP_ENCODED_OPENER` on WPCode snippet saves

**Shape:** 4 events, two real Greek admins (193.92.137.123 and
89.210.235.252, Chrome 148, Vodafone + Nova residential IPs). URLs:
`/wp-admin/admin.php?page=wpcode-snippet-manager` and
`/wp-admin/admin-ajax.php`. The admins were saving PHP snippets via
the WPCode plugin's editor.

**Root cause:** `detect_php_encoded_opener` looked for base64 / URL-
encoded / HTML-entity / JS-escape forms of `<?php` in request bodies
— an encoding bypass primitive for upload-vetting WAFs that look for
literal `<?php`. (Audit **F16** later removed the URL / HTML-entity /
JS-unicode forms as legit-content encodings, leaving base64 + JS `\x`
hex-escape — but WPCode's own bodies are **base64**, so this case is
unaffected by F16.) WPCode (and Code Snippets, Insert PHP Code Snippet,
…) lets admins author PHP snippets through the WP admin UI. When the
admin saves, the plugin POSTs the snippet body to admin-ajax.php; the
plugin serialises the snippet contents in base64. The body literally
contains `PD9waHA…` (base64 of `<?php …`), so the rule fires.

**Why we missed it:** the rule was designed to catch attackers
smuggling PHP through endpoints that decode body data on the server
side. The detector had no concept of "this body legitimately contains
encoded PHP because the admin is authoring it".

**Fix:** suppress the rule entirely on `/wp-admin/*` paths. WP
cookie-auth has already gated those requests before they reach the
WAF, so we don't try to second-guess admin tooling. Webshells
delivered via theme/plugin file editors, upload exploits, or
vulnerable public endpoints still arrive on non-/wp-admin/ paths
where this rule remains active. Shipped in **PR #969**. Effect:
4 → 0.

**Refinement (audit F11):** the "cookie-auth has already gated it"
assumption is *wrong* for `/wp-admin/admin-ajax.php` and
`/wp-admin/admin-post.php` — both serve `wp_ajax_nopriv_*` /
unauthenticated `admin-post` actions and are reachable PRE-auth, so a
blanket suppression there is a pre-auth WAF blind spot for base64
`<?php` smuggling. But the edge can't distinguish a legit WPCode save
from a nopriv attack (both are base64 `<?php` on admin-ajax; the WP
cookie is spoofable), so enforcing would just re-run this incident.
The carve-out is therefore split: **437** (the JS `\x` hex-escape form
after F16) stays fully suppressed on all `/wp-admin/`; **438** (base64) is kept **`logonly`**
on the two pre-auth endpoints (detect-and-watch, zero enforcement — a
`logonly` hit is dropped by the autoblock feed, which ingests only
`action=block`, and no `WAF_BACKDOOR` rule is block-tier, so no ban even
though the family is autoblock-armed) and stays suppressed
on the rest of `/wp-admin/` (authed editors). Watch the logonly stream
(rule 438 on an admin-ajax URI) to separate real attacks from WPCode
noise before considering any promotion.

**Lesson for new body-content rules:** any rule that scans POST bodies
for code-shaped strings (PHP openers, SQL keywords, JS function
calls) needs an answer for "what legitimate admin tooling writes this
shape of content?" before going to production. WP admin (`/wp-admin/`),
phpMyAdmin, Adminer, Joomla administrator, cPanel file manager,
DirectAdmin, and the various theme/plugin code editors are the usual
suspects.

### FP case 6 — `WAF_UPLOAD_CONTENT:UPLOAD_PHP_TAG` on WP migration-plugin imports

**Shape:** repeated `block` events (rule 402, reason
`WAF_UPLOAD_CONTENT:UPLOAD_PHP_TAG`) on
`POST /wp-admin/admin-ajax.php?action=WMW_import` of `mtgtravel.gr`, from a
single real Greek admin (2.85.210.197, AS6799 OTEnet, Chrome 150). Referer was
the plugin's own admin page (`admin.php?page=WMW_import`); the same IP had a
fully authenticated wp-admin browsing session around the hits (themes.php,
dashboard widgets, load-styles.php all 200). The import ran as a ~90-minute
stream of chunked `multipart/form-data` POSTs, each large enough that the edge
buffered the body to disk (`client_body_temp` warnings in error.log).

**Root cause:** the Website Migration WordPress plugin (`WMW_*` admin-ajax
actions) uploads a whole-site backup in chunks. A WordPress site backup *is*
PHP source, and the archive chunks carry literal `<?php` bytes in the
multipart body, so rule 402's byte scan fires — on content that is the
upload's whole point. Same class as the `update.php?action=upload-plugin` /
Code Snippets carve-outs (`is_known_legit_php_upload_endpoint`): the
plugin/theme/backup/migration ecosystem legitimately ships PHP-bearing
payloads. Note the family is autoblock-armed (`UPLOAD_CONTENT` is a Phase-1
edge-`block` family), so each edge hit also feeds `waf_security` — a customer
mid-migration can earn a 6h nft ban on top of the edge TTL block.

**Why we missed it:** rule 402 deliberately has no admin-ajax carve-out
(upload exploits land exactly there), and the existing legit-PHP-upload
allowlist is keyed on the two installer endpoints only. Migration plugins
use plugin-specific admin-ajax actions the edge has never heard of.

**Fix — operator-side, temporary, rule-scoped exclusion for the duration of
the migration.** There is **no safe fully-automatic code carve-out** for this
case (see the rejected-approaches analysis below); the operator, who knows a
migration is running, is the right actor:

```
cfm webtop waf exclude add    /wp-admin/admin-ajax.php --type path --rule 402 --scope mtgtravel.gr
# ... run the import, then remove exactly what you added:
cfm webtop waf exclude remove /wp-admin/admin-ajax.php --type path --rule 402 --scope mtgtravel.gr
```

`--scope <vhost>` pins the exclude to the one migrating site — minimal
surface. Omit it and the path+rule exclude applies on every vhost (still
rule-scoped, but fleet-wide for that path). If the backup chunks also trip the
other block-tier body scanners — likely in practice, since a full-site backup
carries `php://input`/`php://temp` strings (→ `php_wrappers`, rule **305**,
armed→block, and it runs *before* 402), a SQL dump (→ `sqli`, **301**), and
serialized PHP objects from the DB (→ `php_object_injection`, **329**) — add
those ids to the same temporary exclude and remove them all afterwards:

```
cfm webtop waf exclude add    /wp-admin/admin-ajax.php --type path --rule 402 --rule 305 --rule 301 --rule 329 --scope mtgtravel.gr
cfm webtop waf exclude remove /wp-admin/admin-ajax.php --type path --rule 402 --rule 305 --rule 301 --rule 329 --scope mtgtravel.gr
```

With `--scope`, the exclude is pinned to one vhost, one path, and only the
listed rules: the rest of the WAF still inspects those requests (traversal,
XSS, CVE detectors, everything not listed), every other path on the same vhost
keeps all rules, and every other vhost is untouched entirely. Removing it after
the import restores full enforcement. (The same add/remove is available from
the cfm-admin WAF excludes card — type/value plus the rule-IDs and scope-host
fields.)

**Rejected — an automatic content-keyed exemption (why it cannot be safe
here).** The tempting fix is a fleet-wide rule keyed on the WordPress action
(`action=WMW_import`) that demotes the upload scanners to logonly. A first
draft of exactly this shipped on the branch and was **reverted after
adversarial review** — the approach is unsound at two independent levels:

1. **Parser differential (admin-ajax dispatches on `$_REQUEST['action']`).**
   The query action is not the effective action: a POST-body `action` field
   overrides the query (PHP `request_order=GP`, last duplicate wins). Any
   matcher must therefore reconstruct PHP's `parse_str` + rfc1867 multipart
   parsing in Lua — and an adversarial pass found **four** confirmed
   request differentials against real PHP where the matcher computed
   `WMW_import` while PHP dispatched an attacker-chosen `wp_ajax_nopriv_*`
   handler: an in-data fake `--boundary--` (substring, not line-anchored,
   match), a decoy `filename=` in an unrelated part header, a bare-`LF`
   header terminator, and an all-`LF` body — each exploiting a body-walker
   that *fails open* (grants the exemption) on any parse ambiguity. Matching
   PHP's lenient line-oriented parser byte-for-byte in Lua is a losing game.
2. **Windowed body vs full-body dispatch (fatal even with a perfect
   parser).** The edge only reads the first `waf_body_max_len` (32 KB) of the
   body; the origin PHP sees all of it. Legit migration chunks are *larger*
   than the window (they spool to disk — the `client_body_temp` warnings
   above). So an attacker places a webshell file part in the first 32 KB
   (fully in-window, exactly what rule 402 would catch) and hides
   `action=evil` *past* 32 KB. Any matcher that grants when it sees no
   conflicting action in its window is bypassed; any matcher that fails
   closed when the body is truncated denies **every** real (large) migration
   — the exact case the fix exists for. There is no setting of the fail
   direction that is both safe and useful.

Because the legitimate case is inseparable (at the edge, at request time)
from the attack, no automatic keying resolves it. The operator exclude wins
precisely because it is out-of-band: the operator asserts "a migration is
happening now", scoped and time-bounded, instead of the edge trying to infer
it from attacker-controlled bytes.

**Lesson:** chunked migration/backup imports (WMW, All-in-One WP Migration,
Duplicator, WPvivid …) are a third "legitimately uploads PHP" shape alongside
installers and code editors — but unlike the installer endpoints
(`update.php`, which *is* the cookie-auth-gated handler), a plugin-specific
`admin-ajax.php?action=…` is body-overridable for dispatch and reachable
pre-auth, so it cannot be safely allowlisted in code. When an exemption would
have to key on an attacker-movable routing key (`$_REQUEST`-style) *and* the
verifying scanner reads only a bounded prefix of a body the backend consumes
in full, the honest answer is an operator-driven, temporary exclusion — not a
detector carve-out.

### Structural anti-patterns to check during rule review

A short list. Every one of these surfaced as a real FP above; reading
new detector PRs with these in hand catches most of the next batch
before they ship.

| Anti-pattern | What to check | Affected case above |
|---|---|---|
| Plain-substring match on a token that's a common English word fragment (`onerror`, `onload`, `eval`, `system`) | Anchor on `%f[%w]` frontier or equivalent | XSS (#2) |
| Length-based rule on the URI path | Does any CMS template inject `data:` URIs, `srcset=` strings, or unquoted `url(…)` that a crawler might follow? | LONG_PATH (#1) |
| Generic "this isn't UTF-8" validator | Does the rule actually fire only on encoding-bypass primitives (overlong/surrogate/out-of-range), or does it flag all non-UTF-8? | BAD_UTF8 (#3) |
| Protocol-scheme scanner over args/body | What schemes are legitimately stored as config by top WP / Joomla / Magento plugins? | SSRF_FTP (#4) |
| Body-content scanner (code shapes, PHP openers, SQL keywords) | What admin tooling writes this content shape legitimately? Does the rule belong off `/wp-admin/` paths? | PHP_OPENER (#5) |
| Per-byte walker on body | Does it assume the body is text? Multipart file uploads carry arbitrary binary. | BAD_UTF8 (#3) |
| Rule that depends on a specific buffer composition (e.g. `args + "&" + body`) | Tests that exercise the rule should pass complete, self-contained inputs — not rely on implementation details of how the WAF concatenates args and body | BAD_UTF8 (#3, test 76) |

### Pre-merge checklist for a new detector

1. **Run on a captured production log.** Replay the rule's Lua logic
   against `cfm.waf.log` (or `access.log` if pre-WAF). Expect zero
   FPs at logonly, in a >24h window, before promoting.
2. **Check `/wp-admin/` and `/wp-json/` traffic specifically.** Almost
   all of the FPs above arrived via WP admin / REST endpoints. Carve
   out at the call site (cleanest) or per-vhost exclusion (operator-
   driven) rather than tightening the detector itself.
3. **Check bare-IP `host` traffic separately.** `WAF_IP_HOST` already
   catches it, but rules that also fire on the same requests can
   double-challenge legitimate research scanners (Palo Alto Cortex
   Xpanse, Censys, etc.) at well-known IP-only endpoints.
4. **Check Facebook + Instagram traffic.** AS32934 has its own ad
   crawler shapes (`facebookexternalhit`, in-app browser UAs) that hit
   ad landing pages with URLs sometimes mangled by FB's link-preview
   infrastructure.
5. **For length/encoding/protocol-scheme rules, write the
   anti-pattern test before the positive test.** Pick the most
   realistic legitimate input that could trip the rule (a multipart
   POST, a `data:` URI in path, a `;base64,` body, a legacy ISO-8859-x
   form post) and assert the rule does not fire. Then write the
   positive case.
6. **Start at `logonly`.** Promote only after `cfm webtop waf hit-rates`
   shows `ok_to_promote` (rate < 0.01%) over a representative window
   and you've grep'd the JSON log for any host whose hit-count is
   disproportionate.

---

## Rule IDs

Every WAF rule has a stable numeric ID grouped by first digit:

| Group | Range | Family |
|---|---|---|
| 1xx | 100-199 | Path / traversal |
| 2xx | 200-299 | Client identity (UA) |
| 3xx | 300-399 | Injection (SQLi, XSS, RCE, b64, deserialization, XXE, shellshock, …) |
| 4xx | 400-499 | Upload / malware / obfuscation |
| 5xx | 500-599 | Auth abuse / brute force |
| 6xx | 600-699 | Header / protocol anomaly |
| 7xx | 700-799 | SSRF / external interaction |
| 8xx | 800-899 | Information disclosure / debug |
| 9xx | 900-999 | Reserved (future detectors) |

Stability rule: **never renumber** an existing ID. New rules get the next free slot in their semantic group. Drift between the Lua source of truth (`configs/lua/cfm_waf.lua`) and the Go mirror (`internal/webdetector/waf_rule_ids.go`) is caught by `TestWAFRuleIDs_LuaParity`.

Current assignments:

```
1xx — Path / traversal
  101  rule_traversal
  102  rule_long_path_segment

2xx — Client identity
  201  rule_bad_ua

3xx — Injection
  301  rule_sqli                       310  rule_cmd_params
  302  rule_xss                        311  rule_cmd_payload
  303  rule_js_proto                   312  rule_cmd_payload_semi_cmd
  304  rule_b64_injection              313  rule_cmd_payload_pipe_wget
  305  rule_php_wrappers               314  rule_cmd_payload_pipe_curl
  306  rule_serialize                  315  rule_cmd_payload_pipe_bash
  307  rule_xxe                        316  rule_cmd_payload_pipe_sh
  308  rule_shellshock                 317  rule_cmd_payload_backtick
  309  rule_sqli_blind_lexical         318  rule_superglobal_override
                                       319  rule_sqli_union_variant
                                       320  rule_rce
                                       321  rule_proxy_header_sqli
                                       322  rule_reverse_shell
                                       323  rule_persistence
                                       324  rule_rootkit_artifacts
                                       325  rule_lolbin
                                       326  rule_java_deserialize
                                       327  rule_coinminer
                                       328  rule_log4shell

4xx — Upload / malware
  401  rule_upload_filename            405  rule_script_obfuscation
  402  rule_upload_content             410  rule_webshell_path
  403  rule_upload_obfuscation         411  rule_webshell_ping
  404  rule_php_webshell_body          412  rule_polyglot_upload
                                       413  rule_webshell_path_known
                                       421  rule_php_split_string_canary
                                       422  rule_php_dropper_wget_curl
                                       423  rule_php_dropper_markers
                                       424  rule_php_filesize_recon
                                       425  rule_php_touch_antiforensic
                                       430  rule_htaccess_poisoning
                                       431  rule_php_char_pool_obfuscation
                                       432  rule_php_polyglot_full_body
                                       433  rule_php_eval_loader_b64
                                       434  rule_php_superglobal_callable
                                       435  rule_php_concat_funcname_eval
                                       436  rule_php_decode_chain
                                       437  rule_php_encoded_opener       (JS \x hex-escape form)
                                       438  rule_php_encoded_opener_b64   (base64 form)

5xx — Auth abuse
  501  rule_auth_burst                 510  rule_xmlrpc_multicall
  502  rule_auth_wp_checks             511  rule_xmlrpc_pingback
                                       512  rule_xmlrpc_post_burst

6xx — Header / protocol anomaly
  601  rule_ctrl_chars                 605  rule_crlf_injection
  602  rule_ip_host                    606  rule_http_smuggling
  603  rule_header_vulns               607  rule_exploit_methods
  604  rule_content_type_anomaly       608  rule_smuggling_cl
                                       609  rule_header_flood
                                       610  rule_range_abuse
                                       611  rule_bad_utf8

7xx — SSRF / external interaction
  701  rule_ssrf
  702  rule_c2_tunnel

8xx — Info disclosure / debug
  801  rule_debug_toggles
```

### Where IDs surface

- **WAF log line** — `cfm.waf.log` events carry `waf_rule_id=N` alongside the existing `reason=` field.
- **History persistence** — stored in `HistoryEvent.Payload["waf_rule_id"]` for forensic queries.
- **API** — `GET /api/v1/waf/rules` returns the registry with group / group_name / reason_family / default_mode.
- **CLI** — `cfm webtop waf rules` prints the table grouped by family. `--json` for scripts.
- **Public Lua API** — `_M.get_rule_ids()` returns a copy of the `RULE_IDS` table; `_M.rule_id_for("rule_traversal")` looks up a single ID.

The `rule_id` field returned by the bridge's `/nginx/decision` endpoint is a **separate** namespace (decision-engine traffic-rule IDs, not WAF rule IDs). The WAF path uses `waf_rule_id` everywhere to avoid collision.

---

## Backdoor / obfuscation family (430-438)

Reason family **`WAF_BACKDOOR`** (added to `_M.WAF_HIGH_RISK_REASONS` so post-clearance challenges still escalate to block when these rules are promoted past `logonly`). Source workload for the initial set: a 2026-05-19 captured PHP webshell deployed as `wp-content/themes/bridge/includes/radio.php` — char-pool-obfuscated PDF-polyglot loader.

The rules are split deliberately so each catches a different *class* of evasion. The captured radio.php sample trips 431 + 432 + 433 together (severity aggregation picks the strongest action; all three rule IDs appear in `hits`).

### Rule 430 — `rule_htaccess_poisoning`

**Catches:** `.htaccess` / `.user.ini` uploads that turn benign files into PHP executors.

**Why it matters:** the standard escape from a successful "no .php upload" filter is to upload a `.htaccess` (or `.user.ini`) that flips the handler for `.jpg`/`.gif`/`.png` to PHP, then upload a `shell.jpg` that's now executable. CFM had zero coverage for this before.

**How:** body substring scan for handler-flip primitives anchored on `x-httpd-php` to avoid colliding with legit AddType for fonts / media. Also flags `auto_prepend_file` / `auto_append_file` (Apache `php_value` or `.user.ini` `key = value` forms) and `Options +ExecCGI`.

**Tags:** `HTACCESS_ADDTYPE_PHP`, `HTACCESS_SETHANDLER_PHP`, `HTACCESS_ADDHANDLER_PHP`, `HTACCESS_AUTO_PREPEND`, `HTACCESS_AUTO_APPEND`, `USER_INI_AUTO_PREPEND`, `USER_INI_AUTO_APPEND`, `HTACCESS_EXEC_CGI`.

**FP notes:** legitimate plugin `.htaccess` content (`RewriteRule`, `ExpiresByType`, `AddType image/svg+xml`) does not contain the handler-flip anchors. **Caveat for shared hosting:** `AddType application/x-httpd-php .php` is also a *legitimate* hand-written directive an admin/host uses to force PHP in a directory, and the three Apache-directive branches (`addtype`/`sethandler`/`addhandler`) are **not** prose-gated the way the `.user.ini` branch is — so a forum/ticket/CMS POST that merely *discusses* the directive, or a File-Manager `.htaccess` edit, matches. Unlike rule 432, this rule is **not** gated by `legit_archive_upload` either.

**Tier:** stays at `logonly` (observe-only). Promotion to `challenge` is deferred until the three Apache-directive branches get the same prose-gate (require a directive-shaped context, not the bare token) that the `.user.ini` branch already has; until then the shared-hosting FP surface above rules out interrupting.

### Rule 431 — `rule_php_char_pool_obfuscation`

**Catches:** PHP obfuscator output where function names are assembled by indexing into a random-character pool, e.g.

```php
$t_Ohw = "8Njlp26zFZ1PYvUsnckDOX5JdhCwMSRafLi0bqeQo4WxtBrTAu3IEm7VHG_K9gy";
$IDC3B = $t_Ohw[61].$t_Ohw[7].$t_Ohw[34]…;  // builds "gzinflate"
```

**Why it matters:** every static substring detector — ours, CRS, libinjection — looks for literal `gzinflate` / `base64_decode` / `eval` tokens. Char-pool extraction defeats them by construction: the function name never appears as a substring of the source. This catches the entire FOPO / PHP-Obfuscator / Code-Eater output class.

**How:** Lua pattern with a backreference (`%1`) requiring 3+ indexed accesses against the *same* variable, dot-concatenated:

```
%$([%w_]+)%[%d+%]%s*%.%s*%$%1%[%d+%]%s*%.%s*%$%1%[%d+%]
```

**Tag:** `CHAR_POOL_BUILDER`.

**FP notes:** legitimate PHP reads sequential array elements with a loop or `implode`, never with three unrolled `$v[N].$v[N].$v[N]` accesses. The pattern grammar appears in no legit idiom.

### Rule 432 — `rule_php_polyglot_full_body`

**Catches:** uploaded files whose first 16 bytes are image/PDF/ZIP magic but which contain `<?php` (or `<?=`, `<jsp:`, `<% page`, `<script language="php"`) **anywhere** in body — not just within rule 412's first-64-byte window.

**Why it matters:** rule 412 covers the leading-64-bytes polyglot case (which still fires on the captured sample because its `<?php` opener sits at byte 13). The general class is broader: an attacker can pad the magic prefix with arbitrary bytes and slip the PHP opener anywhere — at byte 500, byte 5000. Legit binary files never contain `<?php` at any offset.

**How:**
1. First 16 bytes match one of: `%PDF-`, `\xff\xd8\xff` (JPEG), `\x89PNG\r\n\x1a\n` (PNG), `GIF87a` / `GIF89a`, `PK\x03\x04` (ZIP/JAR/DOCX), `BM` (BMP), `RIFF` (WebP/WAV).
2. Body within scan budget contains a PHP/JSP/script opener.

**Tags:** `POLYGLOT_DEEP_PDF`, `POLYGLOT_DEEP_JPEG`, `POLYGLOT_DEEP_PNG`, `POLYGLOT_DEEP_GIF`, `POLYGLOT_DEEP_ZIP`, `POLYGLOT_DEEP_BMP`, `POLYGLOT_DEEP_RIFF`.

**FP notes:** image / PDF / ZIP files do not legitimately contain `<?php` tokens — the magic-byte gate plus the PHP-opener gate together are malware-only. **Caveat (fixed 2026-06-04):** the 5-byte `<?php` opener is binary-safe, but the 3-byte `<?=` short-echo opener (`3C 3F 3D`) collides with high-entropy binary roughly once per ~16 MB of image data — it fired `POLYGLOT_DEEP_*` (and rule 402 `UPLOAD_PHP_TAG`) on innocent WebP/JPEG product-photo uploads (e-vafeiadis.gr: the same product save alternated 200/403 across retries, proving a content-dependent collision). `<?=` is now matched only when followed by an actual PHP expression — an optional `@`, then a variable/superglobal (`$`), backtick exec, quoted string, `(`, or a function call `name(` whose name may contain digits (`base64_decode(`, `md5(`, `str_rot13(`) — via `has_php_short_echo`. This keeps the input-driven short-tag webshell shapes (including superglobal-free ones like `<?=base64_decode(file_get_contents('php://input'))`) while removing the binary-collision FP. The remaining unmatched forms (e.g. a numeric echo `<?=1`) are not exploitable webshell openers.

**Tier:** stays at `logonly`. It was briefly promoted to `challenge`, but `WAF_BACKDOOR` is a high-risk reason, so for a client holding a valid clearance cookie the challenge is converted to a **block** (`post_clearance_action`) — and because the `BACKDOOR` family is autoblock-armed (`detectors.conf`), that converted block can earn a **6h nft ban** of a logged-in customer who uploads e.g. a PDF containing the literal string `<?php` via a raw-body endpoint. (Multipart uploads never trip 432 — the body starts with the boundary, not the file magic — so the risk is raw-body uploads.) Promote only after post-clearance-converted hits are excluded from the Phase-1 autoblock feed.

### Rule 433 — `rule_php_eval_loader_b64`

**Catches:** the obfuscator-output loader shape, *independent* of which obfuscator built the function-name strings:

```php
eval($a($b("BASE64_PAYLOAD…")));    // variable-fed call chain + large base64 literal
assert($d("LONG_BASE64_STRING"));
call_user_func($f, $payload);
```

**Why it matters:** we don't peer into the encoded payload (could be gzdeflate-of-gzdeflate, str_rot13, XOR, anything). We recognise the *transport*: a terminal `eval` / `assert` / `call_user_func` / `call_user_func_array` whose first argument is a variable-fed call (`$<name>(`), with a base64-shaped string ≥ 200 chars in the same body. Resilient across obfuscator versions — works whether the decoders are built by char-pool, string-concat, string-reverse, or any other mechanism.

**How:**
1. Body contains `eval(` / `assert(` / `call_user_func(` / `call_user_func_array(` followed (with optional `@` and whitespace) by `$<varname>(` — the variable-fed shape.
2. Body contains a quoted literal whose inner content is ≥ 200 chars and ≥ 90% base64-alphabet (`A-Za-z0-9+/=`).

**Tag:** `EVAL_LOADER_B64`.

**FP notes:** `eval(base64_decode("..."))` with a *literal* function name does not match — this rule targets the variable-fed shape that is the hallmark of obfuscator output. A simple `eval(base64_decode(...))` without variable indirection is the older, less-evasive form already caught by other rules.

### Rule 434 — `rule_php_superglobal_callable`

**Catches:** the modern minimalist webshell that invokes a superglobal as a callable, e.g.

```php
<?php $_GET['c']($_GET['p']);
<?php $_REQUEST['x']();
<?php $_SERVER['HTTP_X_CMD']();   // magic-header-triggered shell
```

**Why it matters:** the dangerous primitive is **invoked** via the superglobal, not named — so every `eval(`/`system(`/`exec(` substring scanner misses it. This is the dominant shape for backdoors written post-2020 because it defeats CRS / Coraza / our own 404 scoring at once.

**How:** body substring scan for `$_GET[…](`, `$_POST[…](`, `$_REQUEST[…](`, `$_COOKIE[…](`, or `$_SERVER[…HTTP_…](` — a superglobal subscript immediately followed by the PHP function-call grammar `(`.

**Tags:** `SG_GET_CALL`, `SG_POST_CALL`, `SG_REQUEST_CALL`, `SG_COOKIE_CALL`, `SG_SERVER_HTTP_CALL`.

**FP notes:** legitimate code reads superglobals as values (`echo $_GET['name']`) or uses them as array keys (`$config[$_GET['key']]`), never as the callable itself. The pattern requires the `(` immediately after the subscript — array-key use disqualifies because the next char is `]`, not `(`.

### Rule 435 — `rule_php_concat_funcname_eval`

**Catches:** the function-name version of canary 421's split-string trick — assemble a dangerous function name from short literal pieces, then invoke:

```php
<?php $a = "sys" . "tem"; $a($_GET['c']);
<?php $f = "ev" . "al";   $f($payload);
```

**Why it matters:** complementary to 431 (char-pool extraction). 431 catches `$pool[N].$pool[N].$pool[N]…`; 435 catches the simpler `"piece"."piece"` form that older / hand-rolled obfuscators favour. Substring sets looking for `system` / `eval` / `assert` miss both.

**How:** capture `$<varname> = "<piece1>" . "<piece2>"` where:
- each piece is 1-6 chars of `[a-zA-Z_]` only (alpha+underscore, no digits, no slashes — disqualifies path concats `"/var"."/log"` and version-number assemblies)
- the same `$<varname>` is then invoked with `(` later in the body
- the invocation is **not** preceded by `->` (excludes legitimate dynamic method dispatch `$obj->$method()`)

**Tag:** `CONCAT_FUNCNAME_CALL`.

**FP notes:** the tight alpha+underscore character class plus the method-dispatch exclusion handles the common legit shapes. Template engines that build method names this way use `$obj->$method()`, not `$method()` directly.

### Rule 436 — `rule_php_decode_chain`

**Catches:** the classic obfuscator-loader pattern when the decoder names *are* substrings of the source (older obfuscators, hand-rolled droppers):

```php
eval(gzinflate(base64_decode(strrev($payload))));   // 4 decoders, < 80 chars
```

**Why it matters:** complementary to rules 431 (char-pool extraction) and 433 (variable-fed eval loader). Those two catch the modern obfuscators that hide the decoder names; 436 catches the older / lazier shape where the names are literal. Together they cover both "named decoders" and "hidden decoders".

**How:** scan body for occurrences of any decoder primitive (followed by `(` to disqualify substring-of-identifier matches):

> `base64_decode`, `gzinflate`, `gzuncompress`, `gzdecode`, `str_rot13`, `strrev`, `hex2bin`, `convert_uudecode`, `bzdecompress`, `pack`

Collect their positions in the body. Fire if **any three** occurrences fall within a 300-byte window. The proximity gate is the FP-mitigation: legit code that uses these primitives in separate functions across hundreds of lines doesn't trip; nested-call-chain obfuscators always do.

**Tag:** `DECODE_CHAIN`.

**FP notes:** some WordPress plugins (security loggers, translation files, packaged archives via `pack`) do use multiple decoders — but in separate functions / methods, easily > 300 bytes apart. WP core itself uses `base64_decode` and `pack` in `wp-includes/pomo` but never three in proximity. Production data over a logonly week will confirm.

### Rules 437 / 438 — `rule_php_encoded_opener` (JS `\x` hex-escape) · `rule_php_encoded_opener_b64` (base64)

**Catches:** an encoded `<?php` opener in a body — a signal of payload smuggling through a filter that strips/blocks the literal opener, but *only* for encodings a normal client does not emit for content. **Split into two rule ids on 2026-07-02** (one detector, routed by encoding); **audit F16 (2026-07) then removed the URL / HTML-entity / JS-unicode forms** from 437 because they are the normal on-wire encoding of legitimate content, leaving only the two attack-shaped forms:

| Rule | Encoding | Bytes detected | Tag |
|---|---|---|---|
| **438** | Base64 of `<?php` | `PD9waHA` (boundary-anchored, case-sensitive) | `B64_PHP_OPENER` |
| **437** | JS `\x` hex escape | `\x3c\x3fphp` | `JS_HEX_OPENER` |

The detector checks base64 first, so a base64 opener is attributed to **438** and the hex-escape form to **437**.

**Why the removed forms were removed (F16):** the URL / HTML-entity / JS-unicode encodings are exactly how legit content is *transported*, not evasion, so they FP-challenged real comment / forum / API POSTs — and the traffic that *matters* is already covered elsewhere:
- **`%3C%3Fphp` / `%3C%3F=` (URL):** an `application/x-www-form-urlencoded` body is url-encoded **in its entirety**, so a user who types `<?php` into any form field (blog comment, contact form, forum, paste tool) produces exactly `%3C%3Fphp` — indistinguishable from evasion. And the **PHP webshell-body scorer** (rule 404, `detect_php_webshell_body`) `normalize()`-url-decodes the body, so a **marker-bearing** payload (`<?php system($_GET…`) is caught by it (`<?php` + exec-marker + superglobal, at `challenge`) regardless of this rule.
- **`&lt;?php` / `&#60;&#63;php` (HTML entity):** rich-text editors HTML-escape pasted code.
- **JS-unicode `\uXXXX` opener:** Go's `encoding/json` (and many JS encoders) escape a literal `<` to its `\u`-prefixed form **by default**, so a JSON API echoing user content trips it.

**What remains (both attack-shaped, ~zero FP):**
- **438 (base64):** a browser never base64-encodes a form field; the match is boundary-anchored + case-sensitive, so `PD9waHA` at a value boundary (`p=PD9waHA…`) only appears in deliberate smuggling. A 2026-07 six-server review found 16/16 base64 openers were botnet POSTs of base64 `<?php` to `/xmlrpc.php`, 0 FP. The promotion candidate (see FP notes).
- **437 (JS `\x` hex escape):** `\x3c\x3fphp` is a raw `\xNN` byte-escape. A url-encoded backslash is `%5C`, so a form body cannot carry a literal `\x3c`; and `normalize()` does **not** unwrap `\xNN` (it decodes only `%xx`) — so rule 404 never sees a bare hex opener, making 437 the **only** coverage for a *markerless* hex opener (a marker-bearing one is still caught by 404). That non-redundancy, plus near-zero FP, is why it was kept when the redundant-and-FP-prone forms were cut.

**How:** the `\x` hex-escape form is matched as a substring on the lowercased body. The **base64** form (`PD9waHA`) is matched **case-sensitively** (base64 is a case-sensitive alphabet) and **only at a base64 value boundary** — string start or right after a non-base64 separator. The base64 `<?=` short-tag form (`PD89`) is **intentionally not matched**: a 4-char base64 token collides with legitimate base64 data (a 2026-06-25 review found it 6/6 FP), so it was removed.

**FP notes:** **base64 boundary fix 2026-06-04.** The base64 check was originally a lowercased mid-blob substring scan (`has(s, "pd9waha")`), which collided with legitimate base64 *data* — a Google product-feed module (`techking.gr`, OpenCart `route=…/get_product_datas`) whose product text carried code samples, base64-encoded into the body. Same FP class as rule 326's `rO0AB`. The fix (case-sensitive + value-boundary) keeps every real smuggled opener — which always presents `PD9waHA…` at the *start* of a payload value, e.g. the captured live webshell feed `/wp-content/<rand>default.php?p=PD9waHA…` on `flow.gr` (a true positive) — while dropping mid-blob / case-variant collisions. **Both rules ship at `challenge` (promoted `logonly` → `challenge` 2026-06-25; split 2026-07-02; 437 narrowed to `\x` hex-escape by F16 2026-07).** 438 (base64) is the candidate for `block` after a 1-2 week burn-in of the per-rule-id split telemetry. `/wp-admin/*` paths are suppressed for both (WPCode / Code Snippets legitimately POST base64 `<?php` bodies there), with one **audit-F11 exception**: the pre-auth `admin-ajax.php` / `admin-post.php` endpoints keep 438 (base64) at `logonly` (detect-only, no enforcement) because they are reachable unauthenticated (`nopriv` actions) — the blanket "already gated by WP cookie-auth" assumption doesn't hold there. See FP case 5 for the full rationale. Any residual doc / security-research edge case is handled by per-vhost exclusion.

### How they compose

| Sample shape | Fires |
|---|---|
| `.htaccess` upload with `AddType … x-httpd-php` | 430 |
| Obfuscator output with `$pool[N].$pool[N].$pool[N]…` | 431 |
| Image / PDF upload with `<?php` past byte 64 | 432 |
| Eval loader: `eval($a($b("LONG_B64")));` | 433 |
| Minimalist webshell: `$_GET['c']($_GET['p']);` | 434 |
| Concat funcname: `$a = "sys"."tem"; $a();` | 435 |
| 3+ literal decoder primitives in close proximity | 436 |
| `%3C%3Fphp…` (URL/HTML/JS encoded opener) in body | 437 |
| `PD9waHA…` (base64 opener at a value boundary) in body | 438 |
| Captured radio.php (PDF magic + char-pool + eval-loader) | **431 + 432 + 433** simultaneously |

Rules 430-436 default to `logonly`; **437 and 438 default to `challenge`** (see their FP notes above). Operators tune per the standard playbook (one week of hit-rate data → promote to `challenge`, one more week → promote to `block`). Per-vhost exclusions apply normally: `cfm webtop waf exclude add /path/here --rule 430`.

---

## Per-vhost rule exclusions

Operators can suppress specific WAF rules on specific hosts/paths without disabling the whole WAF for that scope. This solves the canonical "scraper triggers `WAF_PROXY_HDR` on one site" pattern (3xK Tech / vitolighting from `docs/waf-analysis-2026-05-08.md`) — keep the rest of the ruleset hot, drop just the noisy rule on the affected host.

### Data model

`internal/webdetector/exclude_store.go`'s `excludeEntry` carries an optional `RuleIDs []int`:

| Entry shape | Meaning |
|---|---|
| `RuleIDs == nil` | **Whole-WAF skip.** All WAF rules suppressed for this host/path. The legacy "WAF off for this vhost" case. |
| `RuleIDs == []int{}` (zero length but non-nil) | Stored as `nil` by `normalizeRuleIDs`; never round-trips as empty. |
| `RuleIDs == [101, 320, …]` | **Rule-scoped skip.** Only the listed `waf_rule_id`s are suppressed; everything else still fires. |

Whole-WAF wins on collision. Two rule-scoped entries on the same host/path get merged via `MatchWAFRules` (sorted, deduplicated union).

### CLI

```
cfm webtop waf exclude list
cfm webtop waf exclude add    <value> [--type host|path] [--rule N|Nxx|N-M ...] [--scope host ...]
cfm webtop waf exclude remove <value> [--type host|path] [--rule N|Nxx|N-M ...] [--scope host ...]
```

`<value>` is matched at a domain/path **boundary** (not a raw substring), or
as a glob when it contains any of `* ? [ ]`. For `--type host` a literal is the
exact host or a dot-boundary subdomain suffix (`shop.gr` matches `shop.gr` and
`www.shop.gr`, never `myshop.gr` / `shop.gr.evil.com`); for `--type path` it is
the exact path or a path-segment prefix (`/admin` matches `/admin` and
`/admin/x`, never `/administrator`). `--type host` matches against the request
host; `--type path` matches against the request path. `--type` defaults to
`host`.
Each entry is single-axis on its `--type` — host **or** path — but `--scope`
adds an independent host filter on top, so you can pin a path exclusion to one
vhost without a unique path string (or a glob like `*/plexusnet/*`).

Omitting `--rule` creates a **whole-WAF** entry (legacy "WAF off for this
scope"). Pass `--rule` one or more times to create a **rule-scoped** entry
that suppresses only the listed `waf_rule_id`s.

`--scope <host>` (repeatable / comma-separated) restricts the entry to
specific vhosts — the third axis that lets you express the exact intersection
"rule N, on path P, for vhost H" (e.g. suppress rule 402 on
`/wp-admin/admin-ajax.php` for one migrating site only). Omitting it leaves the
entry admin-global (all vhosts), as before. **Admin-only in effect:** a scoped
(cPanel) token is always pinned to its own vhost set server-side, so a
`--scope`/`scope_hosts` value from a scoped caller is ignored — it can never
widen or redirect an exclude to another tenant's vhost. Because the qualifier
can only *add* a host filter, it never broadens an exclude.

Rule-ID spec accepts:

- Bare ID: `--rule 320`
- Wildcard: `--rule 3xx` → expanded to 300-399 at parse time
- Range: `--rule 310-317`
- List: `--rule 320,3xx,605` (deduped)
- Repeat: `--rule 201 --rule 605` (merged)

### Worked example — desktop-client false positive

A Greek clinical-software vendor's desktop activator phones home from many
residential IPs without sending `User-Agent`, `Accept`, or `Referer`. It
trips `rule_bad_ua` (`waf_rule_id=201`, reason `WAF_BAD_UA:UA_EMPTY+NO_ACCEPT+NO_REFERER:score=4`)
on every check-in. The traffic is legit; the rule is doing exactly what it
should for everyone *else*.

Right answer — narrow path-scoped exclusion of just rule 201:

```
cfm webtop waf exclude add /plexusnet/updates_v4/plexus4activator.php --type path --rule 201
```

Now `rule_bad_ua` keeps firing on every other URL on every other vhost, the
activator URL stops being challenged, and the rest of the WAF still inspects
the request (SQLi, RCE, upload rules, etc. all still apply). Confirm with:

```
cfm webtop waf exclude list
```

Wrong answers, for reference:
- `cfm webtop waf exclude add www.iqdevelopment.gr --type host` — disables the **entire WAF** for that vhost. Way too broad.
- `cfm webtop waf set rule_bad_ua disabled` — disables rule 201 globally. Worse.
- Editing the Lua detector — rule 201's bot signal is correct in general; the fix is operator-side configuration.

### API

```
GET  /api/v1/waf/exclude/list
POST /api/v1/waf/exclude/add?type=host&value=example.com[&rule_ids=320,3xx,310-317][&scope_hosts=a.com,b.com]
POST /api/v1/waf/exclude/remove?type=path&value=/plexusnet/&rule_ids=201[&scope_hosts=a.com]
```

`rule_ids` is a CSV string in the same spec format as `--rule`. Empty / missing → whole-WAF entry.

`scope_hosts` is a CSV of vhosts to scope the entry to (the API form of
`--scope`). It is honoured only for an admin token; for a scoped token the
effective scope is always the token's own vhost set, so a `scope_hosts` value
from a scoped caller is ignored (it can never widen or redirect the entry).
Empty / missing → admin-global (all vhosts). To remove a scope-qualified
entry, echo the same `scope_hosts` (the list response returns each entry's
`scope_hosts`, so the UI/CLI can round-trip it) — the entry is keyed by its
`(type, value, scope_hosts, rule_ids)` tuple.

`GET /api/v1/waf/exclude/list` returns each entry's `rule_ids` (sorted, deduped) and `scope_hosts` (sorted, deduped) when set; either field is omitted otherwise.

### Lua wiring

cfm.lua's `waf_skip_for(host, path)` returns one of:

```
nil                      -- no exclusion
{whole = true}           -- skip whole WAF
{rule_ids = {[101]=true, [320]=true, …}}  -- skip these specific rules
```

The Lua-side WAF (`cfm_waf.lua` `_M.check`) reads `ctx.skip_rule_ids` (a set keyed by integer rule_id) and passes it to `record()`. Each rule fire that has a `skip_rule_ids` match returns the same shape as a no-hit (`severity = 0`), so it never leaks into severity, hits[], or the engine's strongest-action selection.

cfm.lua's vhost-controls panel still shows the "WAF on/off for this host" toggle, but only counts whole-WAF entries — rule-scoped entries are filtered out so they don't change the toggle state.

### Tests

`scripts/tests/cfm_waf_severity_test.lua` covers `ctx.skip_rule_ids` end-to-end. `internal/webdetector/exclude_store_test.go` covers the matching layer. `internal/webdetector/exclude_rule_ids_test.go` covers the rule-ID-spec parser.

---

## Hit-rate measurement

The "Operating the WAF" section above covers the operator workflow. This
section documents the pipeline.

### Pipeline

```
[ cfm.lua ] every WAF check:
   waf_insp_incr(host)            # 2 shdict.incr ops per request (per-host + global)
   maybe_flush_waf_insp()         # 1 shdict.get; only one worker per minute wins
                                  # the SH:add lock and POSTs the snapshot
                  │
                  ▼  POST /nginx/waf/stats {rows:[{hour_unix, host, count}, ...]}
[ Go bridge ] handleWAFStats → SetWAFStatsHook → engine.RecordWAFInspected
                  │
                  ▼  UPSERT waf_inspected(hour_unix, host) ← absolute count
[ SQLite ] waf_inspected table (sparse, ~240 rows/day per host)
```

Each push carries the **absolute** value of the live shdict counter for the current hour. Repeated pushes for the same `(hour, host)` simply overwrite — `INSERT … ON CONFLICT DO UPDATE`. Lock TTL races are safe (idempotent).

### API: `/api/v1/waf/hit-rates`

```
GET /api/v1/waf/hit-rates?hours=24          # global, 24h
GET /api/v1/waf/hit-rates?hours=168&host=X  # per-vhost, 7 days
```

Response (one row per registered rule, even when `hits=0`):

```json
{
  "hours": 24,
  "host": "",
  "inspected_total": 1500000,
  "rules": [
    {"id": 320, "name": "rule_rce", "group": 3, "group_name": "injection",
     "reason_family": "WAF_RCE", "default_mode": "block",
     "hits": 12, "rate_pct": 0.0008, "promotion_hint": "ok_to_promote"},
    {"id": 101, "name": "rule_traversal", "group": 1, "group_name": "path",
     "hits": 75000, "rate_pct": 5.0, "promotion_hint": "noisy"}
  ]
}
```

Per-rule precision uses `json_extract(payload_json, '$.waf_rule_id')` so families with multiple rules (e.g. all `WAF_AUTH_BURST` tags) are counted separately. Events from before the rule-IDs PR have NULL `waf_rule_id` and are excluded from the per-rule view (they still appear in the legacy `WAFByRule` reason-aggregation).

### Hit log format

Every WAF trigger writes one JSON object per line to `cfm.waf.log`,
carrying enrichment (ASN / country) and the per-request forensic fields
(UA, Referer, Content-Type) that drive FP investigation.

```json
{"ip":"1.2.3.4","host":"example.com","uri":"/admin/upload",
 "method":"POST","action":"block","reason":"WAF_UPLOAD_FNAME:PHTML",
 "waf_rule_id":401,"ttl_sec":3600,
 "ua":"curl/7.81.0","referer":"","ct":"multipart/form-data; boundary=...",
 "asn":12345,"asn_name":"EXAMPLE-AS","country":"US"}
```

The earlier split (compact text in `cfm.waf.log` + a sampled JSON in
`cfm.waf.sampled.log`, gated by `CFM_WAF_SAMPLE_RATE`) is gone. Operators
tail / grep `cfm.waf.log` directly for FP investigation.

### Cost / regression notes

| Path | Cost | Notes |
|---|---|---|
| Per WAF check | ~3-5µs | Two shdict incr + one get-and-compare. <1% of WAF check cost. |
| Per flush (~1/min cluster-wide) | ~3µs on the lock winner | Snapshot+RPC runs in `ngx.timer.at(0, …)`; RPC latency is 100% off the request path. |
| Per WAF trigger | ~50µs | Forensic fields (UA / Referer / CT) attached on every push; JSON encode + one file write. |
| `/api/v1/waf/hit-rates` | <100ms typical | `json_extract` is O(N events in window); operator-pulled, never on hot path. |

#### Body-aware scan path (php_wrappers / ssrf_proto / js_proto)

Measured on bench host with the three body-aware rules enabled, running through `_M.check` end-to-end. "Plain JSON" = realistic JSON with no `%xx` sequences (the common case). "%-encoded" = body full of `%xx` escapes (forces the slow `url_decode_once` path).

| Body | Content-Type | Effective cap | Per-request CPU |
|---|---|---|---|
| 2 KB plain JSON | application/json | 2 KB (within budget) | ~10 µs |
| 30 KB plain JSON | text/plain | 2 KB (truncated by `other` budget) | ~11 µs |
| 30 KB plain JSON | application/json | 30 KB (`json` budget=32K) | ~71 µs |
| 500 KB plain JSON | application/json | 32 KB (capped by `json` budget) | ~87 µs |
| 30 KB %-encoded | application/json | 30 KB | ~2 ms (slow path: two gsub passes) |

End-to-end ceiling in production is bounded by `CFM_WAF_BODY_MAX_LEN` (default 8192); `body_scan_budget.json = 32768` only takes effect once the env var is also raised. Until then, JSON traffic is effectively capped at 8 KB regardless of the table value — still a 4× improvement over the previous 2 KB `max_scan_len`.

`normalize()` short-circuits when input contains no `%`, so the gsub passes only run when actual percent-encoding is present. JSON / multipart bodies almost never carry `%xx`, so the fast path covers the dominant case and dropped baseline cost ~12× vs the previous unconditional double-gsub.

Backward compat: all new wire fields are `omitempty`; `CREATE TABLE IF NOT EXISTS` upgrades existing SQLite DBs silently.

Kill switch: `CFM_WAF_STATS_ENABLE=0` disables hit-rate counters + flushing.

---

## Request flow

```
[ nginx: location-level dispatch ]
  ├─ /__cfm_challenge, /__cfm_verify, /cpanelwebcall, /cfm-admin/  → bypass cfm.lua
  ├─ \.(css|js|woff2?|ttf|eot|png|jpe?g|gif|webp|ico|map)$         → bypass cfm.lua, proxy to origin
  └─ everything else                                               ↓
[ access_by_lua: cfm.lua ]
  ├─ POST resume handling
  ├─ Step 1   validate cfm_clearance → clearance_allow (no return yet)
  ├─ Step 2   run WAF (always, regardless of clearance)
  │            ├─ block            → exit 403
  │            ├─ challenge + clearance → convert via post_clearance_action
  │            │                       (high-risk → block; else → logonly)
  │            ├─ challenge no clearance → challenge flow
  │            └─ logonly          → log; refresh clearance if any; allow origin
  ├─ Step 2b  honour clearance_allow → refresh cookie, allow origin (return)
  ├─ Step 2.5 forced_challenge for marked locations
  └─ Step 3   bridge decision (Go side: ip/vhost/rule)
```

Key invariants:

1. **WAF runs even with valid clearance** for any request that reaches `cfm.lua`. No dynamic payload reaches origin without inspection.
2. **Post-clearance challenge cannot loop.** Conversion happens before the action switch; the `challenge` branch in the WAF hit handler is unreachable when `clearance_allow=true`.
3. **POST replays are safe.** `clearance_allow` is force-false on `cfm_resumed_post`; a re-challenged replay hits the `block_replayed` safety net.
4. **CFM control endpoints bypass `cfm.lua`.** `/__cfm_challenge`, `/__cfm_verify` are exact-match nginx locations — no WAF, no challenge, no origin.
5. **Static-asset URIs bypass `cfm.lua`** (`.css/.js/.woff2?/.ttf/.eot/.png/.jpe?g/.gif/.webp/.ico/.map`). The `location` block in `openresty.conf` / `angie.conf` skips the access phase and proxies straight to Apache. `.svg` is NOT in the bypass — it can carry script.

`X-CFM-Action` values for visibility:

| Value | Meaning |
|-------|---------|
| `allow_cookie` | No WAF hit, valid clearance, allowed |
| `logonly` | WAF logonly hit, no clearance involved |
| `logonly_pc` | challenge converted to logonly under clearance |
| `block` | Direct WAF block |
| `block_pc` | challenge converted to block under clearance + high-risk reason |
| `challenge` | WAF challenge, no clearance |
| `challenge_resume` | Challenge with POST-resume token |
| `block_replayed` | POST replay re-triggered WAF challenge → 403 |
| `challenge_forced` | nginx-marked location forced challenge |

---

## Configuration

| Var | Default | Allowed | Notes |
|-----|---------|---------|-------|
| `CFM_WAF_AFTER_CLEARANCE_CHALLENGE` | `logonly` | `block`, `logonly` | What a challenge becomes under clearance for noisy reasons. `challenge` is rejected. |
| `CFM_WAF_AFTER_CLEARANCE_HIGH_RISK` | `block` | `block`, `logonly` | What a challenge becomes under clearance for high-risk reasons. |
| `CFM_WAF_BODY_MAX_LEN` | `8192` | int bytes | Upstream body-read cap in `cfm.lua`. End-to-end ceiling for body-aware rules — see `body_scan_budget` below. Raise in lockstep with the json/multipart entries to fully exploit the per-Content-Type budget table. |

#### `CFG.body_scan_budget` (Content-Type-keyed body scan budget)

Body-aware detectors (`php_wrappers`, `ssrf_proto`, `js_proto`) consume a normalized `args & body` string built once per request by `get_norm_ab()` in `cfm_waf.lua`. Each request picks its byte budget from `CFG.body_scan_budget` based on the request's `Content-Type`:

| Key | Default | Matches |
|---|---|---|
| `urlencoded` | `8192`  | `application/x-www-form-urlencoded` |
| `json`       | `32768` | `application/json` (incl. `; charset=...`) |
| `multipart`  | `16384` | `multipart/form-data` |
| `xml`        | `16384` | `application/xml`, `text/xml` |
| `other`      | `2048`  | Everything else (incl. unset / unknown / `text/plain`) |

`CFG.max_scan_len` (default `2048`) is the legacy fallback used by callsites without header context — URI+args scans (`scan_str`) and body-only detectors invoked outside the engine's hot path. The 17+ standalone callsites in `cfm_waf_detectors.lua` still use it; only `get_norm_ab` is on the budget table today.

The `util.body_budget(headers)` helper is hardened against malformed user overrides (non-table values, missing keys, non-positive numbers, non-numeric values) — it falls back to `body_scan_budget.other`, then `CFG.max_scan_len`, then `2048`, so a bad `cfm_waf_config.lua` cannot crash the worker on every body-aware request.

High-risk reason families (matched by `:` prefix) live in `cfm_waf.lua` as `_M.WAF_HIGH_RISK_REASONS`:

```
WAF_RCE              WAF_PHP_WEBSHELL_BODY
WAF_UPLOAD_CONTENT   WAF_TRAVERSAL
WAF_UPLOAD_FNAME     WAF_XXE
WAF_UPLOAD_OBFUSCATION
WAF_CMD_PAYLOAD
WAF_B64_INJECT
WAF_SHELLSHOCK
WAF_WEBSHELL
WAF_CVE
WAF_DROPPER
```

A reason in this list, when fired with `challenge` action under valid clearance, gets converted to `block` instead of `logonly`. Matched against the prefix before the first `:` so `WAF_RCE:REVERSE_SHELL:BASH_TCP` still hits.

### `IGNORE_IPS` / `IGNORE_NETS` (global allowlist for the Lua self-bypass)

`cfm.lua`'s `is_self_origin(ip)` short-circuits the WAF (and the rest of `cfm.lua`) before any rule runs. It honours three sources:

1. **Loopback / link-local** (`127.0.0.0/8`, `::1`, `169.254.0.0/16`, `fe80::/10`) — hard-coded.
2. **Local interface IPs** of this box, written by `nft.go:writeSelfIPsLua()` to `/var/lib/cfm/lua/cfm_self_ips.lua`.
3. **`[global] IGNORE_IPS` / `IGNORE_NETS`** from `cfm.cfg`, written by `detectors.IPIgnore.WriteLuaCache()` to `/var/lib/cfm/lua/cfm_ignore_nets.lua`. Same allowlist the Go challenge engine uses via `SetBypassFunc(ipIgnore.ShouldIgnore)` — wiring them through to the Lua WAF closes the operator-expectation gap where "WAF runs on traffic from my own subnet."

File format (precomputed for fast Lua matching, refresh TTL 30s):

```lua
return {
  generated_at = "2026-05-19T...",
  ips = { ["1.2.3.4"] = true, ["::1"] = true },
  v4_ranges = {
    { 1412837632, 1412837887 },  -- 84.54.49.0/24 as uint32 [first, last]
  },
}
```

**IPv6 limitation:** `IGNORE_NETS` entries that are IPv6 CIDRs are silently skipped in `v4_ranges`. IPv6 *exact* IPs in `IGNORE_IPS` still work (they land in `ips`). Operators wanting IPv6 CIDR support need to list the specific addresses for now.

**Trigger:** the file is rewritten on every config reload that touches `[global]` (the same path that rebuilds `IPIgnore`), plus once on engine startup.

---

## Public API (cfm_waf module)

| Function | Purpose |
|----------|---------|
| `_M.check(ctx)` | Run all rules, return highest severity. 6-tuple (hit, reason, ttl, action, hits, waf_rule_id). |
| `_M.enabled()` | Module-level kill-switch. |
| `_M.should_push(shdict, ip, reason, action)` | Push rate limit, keyed on `(ip, reason family, action tier)` — dedups scored-hit floods without letting a non-block hit mask a block hit's autoblock push (F31). |
| `_M.get_config()` | Snapshot of CFG (read-only copy). |
| `_M.set_rule(name, mode)` | Live rule-mode tuning. Per-worker. Used by tests and ops kill-switches. |
| `_M.get_rule_ids()` | Snapshot of the RULE_IDS table. |
| `_M.rule_id_for(name)` | Lookup a single rule's stable numeric ID. |
| `_M.is_high_risk_reason(reason)` | Prefix match against `WAF_HIGH_RISK_REASONS`. |
| `_M.post_clearance_action(action, reason, after_challenge, after_high_risk)` | Returns `(converted_action, did_convert)`. Pure. |

---

## Tests

`scripts/tests/cfm_waf_severity_test.lua` — 69 cases covering severity aggregation, post-clearance gating, rule-id stability + drift detection, per-vhost rule exclusion via `ctx.skip_rule_ids`, and per-detector positive + negative cases for every rule shipped during the rebuild. Run via `make test-lua`.

`scripts/tests/cfm_waf_post_clearance_test.lua` — `_M.post_clearance_action` matrix: prefix match for bare families and family:tag forms, conversion table, defaults, malformed input.

`scripts/tests/cfm_panel_forced_mode_test.lua` — panel dispatch decisions (challenge / origin pass-through / API SSO bypass / internal-endpoint deny). Asserts on captured side effects.

`scripts/tests/cfm_rules_race_test.lua` — `cfm_rules` shdict-state compatibility under concurrent mutation.

`internal/webdetector/waf_rule_ids_test.go` — `TestWAFRuleIDs_LuaParity` parses `cfm_waf.lua`'s `RULE_IDS` table at test time and diffs against the Go `wafRuleIDs` slice. Catches drift between the two source-of-truth lists.

`internal/webdetector/exclude_rule_ids_test.go` and `exclude_store_test.go` — rule-id-spec parsing (`N`, `Nxx`, `N-M`, mixed) and per-vhost rule-exclusion store semantics.

`internal/webdetector/challenge_server_xss_test.go` — `jsStringLiteral`'s HTML-script-context safety: dangerous bytes (`<`, `>`, `&`, U+2028, U+2029) absent from output for representative attack payloads.

---

## SQLi blind-family expansion + body scan (rules 301 / 309, 2026-06-26)

Source workload: a sqlmap scan against the **WHMCS ticket form** (myip.gr
support) — hundreds of tickets, one per payload, all submitted in the
`application/x-www-form-urlencoded` **body**.

Three changes shipped together:

1. **`rule_sqli` is now body-aware.** It previously scanned only `uri+args`
   (`get_scan_ua()`); form-field SQLi in the POST body was invisible. Both
   SQLi rules now *also* run over the budgeted `args+body` string
   (`get_norm_ab()`) on POST requests (`cfm_waf.lua` §21 / §21b).
2. **Time-based / boolean / error-based blind family** is now detected,
   split across two confidence tiers (`cfm_waf_detectors.lua`):
   - **Rule 301 `rule_sqli` (`WAF_SQLI`, `challenge`)** — `SQLI_BLIND_TOKENS`,
     the **DBMS-unique** primitives that collide with no ordinary word:
     MSSQL `waitfor delay|time`; PostgreSQL `pg_sleep`; Oracle
     `dbms_pipe.receive_message`/`dbms_lock.sleep`; MySQL `now()=sysdate()` /
     `rlike sleep(` / `select sleep(` / `select(sleep(`; error-based `exp(~`;
     plus the boolean tail `=0+0+0+1`.
   - **Rule 309 `rule_sqli_blind_lexical` (`WAF_SQLI_LEXICAL`, `logonly`)** —
     `SQLI_LEXICAL_TOKENS`, the tokens that are real SQLi primitives **but
     also collide case-insensitively with legitimate code/content**:
     `benchmark(`, `extractvalue(` (=camelCase `extractValue(` in XML
     parsers/JS/Java), `updatexml(` (`updateXml(`), `floor(rand(` (valid
     PHP), `randomblob(` (`randomBlob(`), and the shell/code-prose forms
     `or sleep(` / `and sleep(` / `,sleep(` / `(sleep(`. **Observe-only** so a
     legit XML parser / updater / custom script can't be broken.
3. Tokens match a whitespace/`+`-collapsed scan string so a form-urlencoded
   space (`+` or `%20`) still hits the spaced tokens.

Tests: `scripts/tests/cfm_waf_sqli_test.lua` (captured payloads, per-DBMS
family, per-rule isolation, FP negatives).

### Rule 319 `rule_sqli_union_variant` (`WAF_SQLI_UNION_VARIANT`, `logonly`) — 2026-07-08

Rule 301 catches `union select` only when the two keywords are *adjacent*
(after `+`/whitespace collapse). Four common obfuscations slip through that
adjacency check because a word or punctuation sits **between** the keywords:

| Variant | Example payload | Why 301 misses it |
|---|---|---|
| `union all select` | `1 union all select …` | `all` between the keywords |
| `union distinct select` | `1 union distinct select …` | `distinct` between the keywords |
| `union(select` | `1 union(select …` | `(` between the keywords |
| `union/**/select` | `1 union/**/select …` | comment collapses to `unionselect`, not `union select` |
| `union/**/all/**/select` | `1 union/**/all/**/select …` | collapses to `unionallselect` / `uniondistinctselect` |

Rule 319 (`detect_sqli_union_variant` in `cfm_waf_detectors.lua`) matches
`union<mid>select` for `mid` ∈ {` all `, ` distinct `, `(`, ``, `all`,
`distinct`} on the same comment-stripped, `+`/whitespace-collapsed scan string
301 uses. It carries the **same value-terminator guard** as the 301
`+`-bypass fix — the `union` must be immediately preceded by a value break
(`[%d'"%)]`) or a SQL operand keyword (`null`/`true`/`false`) — so legitimate
prose like *"credit union all selected"* or *"european union distinct
selection"* does **not** fire.

**Tier: `logonly` (observe-only, never blocks).** Shipped 2026-07-08 for a
**multi-day real-traffic burn-in**. Walk `cfm webtop waf hit-rates` (and grep
`cfm.waf.log` for `WAF_SQLI_UNION_VARIANT`, grouping by `host`+`uri`) after
2–4 days; if the window is clean, promote `logonly → challenge`, then after a
further clean window `challenge → block` — never `logonly → block` directly.
Because 301 already blocks the adjacent form and its family auto-arms
`waf_security`, keep 319 un-armed for autoblock (default `0`, logonly) until
it has earned a block-tier promotion of its own.

**Expected FP sources to weigh during the burn-in** (from the 2026-07
adversarial review — all are logonly *log lines*, never blocks): a camelCase
identifier in a JSON/form body whose value quote is the terminator —
`{"widget":"unionSelect"}` / `unionAllSelect` collapses to
`unionselect`/`unionallselect`; SQL-tutorial or DBA-forum content *about* the
keyword (`"UNION ALL SELECT vs plain UNION"`); relational-algebra notation
(`(R1)union(select…)`); and a technical **search box** where a browser sends
`?q=PostgreSQL 12 union all select …` with a digit terminator. If any of these
show up materially in `cfm.waf.log`, tighten before promoting past `logonly`
(e.g. drop the empty-/`all`-/`distinct`-collapsed camelCase branches, which are
the FP-prone ones) rather than shipping the noise to `challenge`.

**Known gaps (documented, not closed here):** a MySQL version-gated executable
comment `/*!50000union*/select` is stripped whole (the `union` disappears) — it
also bypasses **rule 301**, so it belongs to a shared `strip_sql_comments`
follow-up, not this rule; a backtick identifier-break (`` `col`union all
select ``) is rejected because `` ` `` is not in the shared terminator class
(again shared with 301); asymmetric single-side comments (`union/**/all
select` → `unionall select`) and the `all`+paren combo (`union all(select`)
are rarer stacked obfuscations; and a **value-leading** `?p=union all select…`
(only `=` before `union`) is a *deliberate* miss to avoid noun-phrase FPs
(same trade-off as rule 301). These are burn-in-visibility gaps, not new
block-path holes — 301 still blocks the adjacent form.

> ### ✅ FP review — DONE 2026-07 (promoted)
> A 6-server `cfm.waf.log` review (titan, virgo, orion, rigel, earth, mars)
> found the two SQLi families **100% clean**:
> - `WAF_SQLI` (301): **24 hits, 24/24 true positives, 0 FP** — time-based
>   (`SLEEP`), union, and error-based SQLi against WP plugins (ays_sccp),
>   PrestaShop CommentGrade, Fuel CMS, and a custom login, from repeat-offender
>   scanners. **Promoted `challenge` → `block`.**
> - `WAF_SQLI_LEXICAL` (309): **188 hits, 188/188 true positives, 0 FP** —
>   dominated by a **distributed error-based sqlmap campaign** against one host
>   (`extractvalue(…CONCAT(0x7e…ELT…FLOOR(RAND()))` with case-randomization +
>   `/**/` evasion) that the DBMS-unique tier-1 would have missed entirely.
>   No legitimate app tripped a word-colliding token. **Promoted `logonly` →
>   `challenge`.**
> - `WAF_SUPERGLOBAL` (318): **0 hits** on all six — no data either way, **kept
>   `logonly`.**
>
> **Residual risk noted:** `WAF_SQLI_LEXICAL` at `challenge` on an `admin-ajax`
> **POST** could break a legit plugin whose XHR body carries a word-colliding
> token (a `fetch()` can't solve the challenge). Zero such cases in the review;
> if one ever appears, drop rule 309 for that vhost via the per-vhost exclusion
> mechanism, or trim the offending token from `SQLI_LEXICAL_TOKENS`.
>
> **Re-run this pass** (still the way to review any WAF family): grep
> `cfm.waf.log` per reason, group by `host`+`uri`, classify each as a
> legitimate app (FP) vs an attack (TP); promote only on a clean window.

## Known gaps

These are real and worth addressing, but not blocking:

1. **Body truncation.** `CFM_WAF_BODY_MAX_LEN=8192` (in `cfm.lua`) means uploads/payloads larger than 8 KB skip body-inspection rules silently. The Content-Type-keyed `body_scan_budget` (added in PR #764) raises the WAF-internal cap to 32 KB for JSON / 16 KB for multipart+XML / 8 KB for urlencoded, but the upstream env-var ceiling still bottlenecks effective inspection at 8 KB. Phase W2/W3/W4 won't deliver until `CFM_WAF_BODY_MAX_LEN` is raised in lockstep (or inspection is streamed) for upload endpoints.
2. **No multipart parser.** Polyglot upload detection (W4), upload context for W2/W3, and X1-in-body assume part-aware inspection. Today the WAF runs literal `has()` over raw bytes — works for finding `<?php` in image content, but can't distinguish multipart parts (claimed CT, filename, content).
3. ~~**No hit-rate measurement.**~~ DONE — see "Hit-rate measurement" above. `/api/v1/waf/hit-rates`, `cfm webtop waf hit-rates`, plus `cfm.waf.log` (one JSON record per trigger with UA/Referer/CT) for FP investigation.
4. **shdict pressure.** Auth-burst counters use shdict. Adding more counters scales contention. Per-rule benchmarks needed before Phase 5 lands.
5. **Per-rule kill-switch audit.** `set_rule()` exists; not every detector is reachable through a `rule_*` CFG key. Audit + fill gaps.
6. **Push payload uses post-conversion action.** `cfm.lua:1127` pushes `action=logonly` after challenge→logonly conversion. Probably correct (push the effective action) but confirm with Go-side consumers.
7. **Route log loses post-clearance signal.** The `waf_logonly` / `waf_block` log line at `cfm.lua:1131` after conversion doesn't say "from challenge". The separate `waf_post_clearance_convert` line at `cfm.lua:1089` carries it; correlation is by IP+timestamp. Could be folded into one line.
8. **Inspector-as-attack-surface follow-ups (2026-05-09 audit).** Quick sweep of the surface that reads attacker bytes (Lua WAF + challenge_server + nginx_bridge) showed strong defences in the high-risk places (no `ngx.re` → no PCRE ReDoS; bridge listener is unix-socket-only with token gate on every endpoint; body cap 8 KB; literal `string.find(s, pat, 1, true)` in the `util.has` hot helper; `cpanelUserExists` regex `^[a-z0-9][a-z0-9_]{0,15}$` blocks path traversal in `/var/cpanel/databases/<user>.json` reads) and one real reflected XSS that's now closed (#565). Items not fully audited: (a) caller traces for the remaining `os.Open`/`os.ReadFile` sites in `cpanel_api_handlers.go` and `challenge_server.go` outside the `cpanelUserExists`-gated path; (b) spot-check of the more exotic Lua patterns in `cfm_waf_detectors.lua` for polynomial-time backtracking (Lua patterns can't catastrophically backtrack but `(.-)*`-style patterns can be slow on crafted input); (c) per-field length bounds in bridge JSON handlers (the body is wrapped in `MaxBytesReader` but individual fields like `host` can still land 16 KB in memory); (d) `dispatchHook` channel-saturation behaviour under load. None block production; worth a dedicated `claude/inspector-audit-*` pass when there's space.

---

## Roadmap

The original detector / engine roadmap is shipped end-to-end. Every item is now in production at the `logonly` → `challenge` → `block` stage documented per rule in the [Rule IDs](#rule-ids) table; the **Outstanding** list at the bottom is the only forward-looking work.

### Shipped

| Item | Rule(s) | Notes |
|---|---|---|
| File split of `cfm_waf.lua` into `cfm_waf_util.lua` + `cfm_waf_detectors.lua` + engine | — | foundation; lets each detector tag header/uri/body/multipart surface |
| **C1** Log4Shell (bare `${jndi:` + lookup-syntax evasions) | 320, 328 | bare forms in `detect_rce` at `block`; evasion variants (`${${::-j}…`, `${lower:j}`, `${env:` etc.) in `detect_log4shell` at `logonly` |
| **C2** Java deserialization (`rO0AB…`, `\xac\xed\x00\x05`) | 326 | scans body / Cookie / Authorization / X-Forwarded-* |
| **R1** Reverse-shell one-liners (`bash -i >& /dev/tcp/`, `python -c 'import socket'`, `socat tcp-connect`, …) | 322 | 24 literal needles |
| **R2** Persistence (cron / systemd / bashrc / authorized_keys) | 323 | |
| **R3** Rootkit artifacts (`LD_PRELOAD`, `/etc/ld.so.preload`, `/dev/mem`) | 324 | |
| **R4** LOLbins (`certutil -urlcache`, `bitsadmin /transfer`, `-EncodedCommand`, `iex(iwr`) | 325 | scores with base64 detector when combined |
| **W1** Ambiguous webshell path names (`/shell.php`, `/x.php`, `/adminer.php`, `/alfa.php`, …) | 410 | challenge-tier; URI basename match, residual-FP names (generic/short + real-word/brand: `adminer.php`, `alfa.php`) |
| **W1k** Proper-noun webshell path names (`/c99.php`, `/r57.php`, `/wso.php`, `/b374k.php`, …) | 413 | block-tier split of W1 (2026-07-03); near-zero legit use, so hard-blocked |
| **W2** Webshell magic strings in body (`b374k`, `WSO 2.5`, `@eval(`, …) | 404 | scored; covers `b374k` / `c99shell` / `r57shell` / `wso 2./4./5.` / `weevelyshell` / `filesman` |
| **W3** PHP function obfuscation (`\x65val`, `chr().chr()…`, `hex2bin($_POST[`) | 405 | shared scorer across body and upload paths |
| **W4** Polyglot upload (image CT/ext + `<?php`/`<?=`/`<%`/`<script` in first 64 B) | 412 | required a multipart parser; also unblocked W2/W3 in upload context |
| **X1** C2 tunnel hostnames (pastebin, ngrok, webhook.site, discord cdn, telegram) | 702 | 21 hostnames |
| **X2** Coinminer (`xmrig --url`, `pool.minexmr.com`, `stratum+tcp://`, monerod, ethminer) | 327 | |
| **B1** HTTP smuggling (CL+TE coexist / multi-CL / malformed CL / multi-TE) | 608 | header-shape detector |
| **B3** Single URL segment ≥ 800 B | 102 | with `data:` URI artifact carve-out |
| **B4** Header bag > 16 KB excluding Cookie / Authorization | 609 | |
| **B5** POST + empty UA + Content-Length:0 + `.php` / `.phtml` / `.phar` URI | 411 | cheap, high-confidence webshell-ping fingerprint |
| Bad UTF-8 encoding (Coraza `validateUtf8Encoding` port) | 611 | overlong / surrogate / truncated multibyte in args+body |
| Range abuse (Apache Killer / `Request-Range` / multi-Range) | 610 | |
| **PHP dropper / canary family** (split-string exec-probes, wget+curl fallback droppers, `!success!`/`!ended!` markers, `<fs>` filesize recon, `@touch()` mtime backdating) | 421-425 | new `WAF_DROPPER` reason family; source workload was a 2026-05-19 shared-hosting compromise |
| Hit-rate counter + sampled hit log | — | see [Hit-rate measurement](#hit-rate-measurement) |
| Stable rule IDs + per-vhost rule exclusions (`SecRuleRemoveById`-style) | — | see [Rule IDs](#rule-ids) and [Per-vhost rule exclusions](#per-vhost-rule-exclusions); solves the vitolighting/3xK Tech-style FP cleanly without disabling whole-host WAF |

### Outstanding

| Item | Why deferred | Size |
|---|---|---|
| **B2** Suspicious method outside expected location (CONNECT to non-proxy, PROPFIND/SEARCH to non-DAV) — fold into the existing exploit-method check, `+2` | Low absolute volume in production; existing `rule_exploit_methods` (607) already covers the common cases | S |
| **Panel DNAT WAF profile** for cPanel / DirectAdmin file managers, backup restore, plugin/theme editors | Needs panel-session context plumbing; primary trigger is hijacked-panel webshell uploads which are currently caught at the body-inspection layer (404 / 405 / 412) | L |

---

## Implementation map

Where each layer lives in the tree:

| Layer | What | Where |
|---|---|---|
| Engine | Severity-aggregation `_M.check`, post-clearance conversion, kill-switches, `ctx.skip_rule_ids` gate | `configs/lua/cfm_waf.lua` |
| Detectors | 48 detector functions invoked from `_M.check` (base set + W1/R1/B5 + W4 polyglot + range/header_flood/long_path + log4shell + bad_utf8) | `configs/lua/cfm_waf_detectors.lua` |
| Util | `scan_str`, `normalize` (no-`%` fast path), `url_decode_once`, `header_string`, `body_budget` (Content-Type-keyed scan cap), IP literal helpers | `configs/lua/cfm_waf_util.lua` |
| Rule IDs | Stable 3-digit IDs, log-line plumbing, `/api/v1/waf/rules`, CLI | `configs/lua/cfm_waf.lua` (`RULE_IDS`), `internal/webdetector/waf_rule_ids.go` |
| Hit-rate | Per-rule rate gating, `/api/v1/waf/hit-rates`, JSON hit log; flush runs in `ngx.timer.at` so the request path never pays RPC latency | `configs/lua/cfm.lua` (`waf_insp_incr` + `maybe_flush_waf_insp`), `internal/webdetector/waf_hit_rates_api_handler.go` |
| Per-vhost exclusions | `excludeEntry.RuleIDs []int`, `--rule N\|Nxx\|N-M` CLI, `rule_ids` API param, `ctx.skip_rule_ids` Lua gate, vhost-controls panel toggle ignores rule-scoped entries | `internal/webdetector/exclude_store.go`, `exclude_rule_ids.go`, `cli_exclude.go`, `configs/lua/cfm.lua` (`waf_skip_for`) |
| CI | `Build & Test` job in `.github/workflows/security.yml` runs `go vet`, `make lua`, `make test-lua`, `check_*` shell guards alongside `go build` and `go test -race`. luajit installed explicitly per matrix run. | `.github/workflows/security.yml` |
| Tests | Severity, post-clearance, rule ID drift, hit-rate aggregation, rule-id parsing, exclude-store match, jsStringLiteral XSS, panel forced-mode dispatch | `scripts/tests/cfm_*_test.lua`, `internal/webdetector/*_test.go` |

## Production data references

- `docs/waf-analysis-2026-05-08.md` — Tier 1/2/3 analysis of three production servers. **Read before adding rules in any family already represented**, to avoid recreating known-FP patterns. Key takeaways: Facebook scrapers hit `/.../<path>` literals (handled in `detect_traversal`'s FB-skip); vitolighting/3xK Tech is the canonical "scraper triggers `WAF_PROXY_HDR`" pattern, solved by per-vhost exclusions; `WAF_BAD_UA` scoring covers most scanner UAs without explicit per-tool literals.
- `docs/security/code-scanning-triage-2026-05-09.md` — Critical+High CodeQL alert triage from 2026-05-09 (1 real XSS fixed, 10 FPs documented, inspector-audit follow-ups).
- `cfm.waf.log` on a running production server — one JSON record per trigger; replay representative attack samples through a new detector before promoting.

---

## Detector inventory

Implementation locations and techniques. For the operator-facing Rule IDs
table, see [§ Rule IDs](#rule-ids) above.

| # | Category | Technique | File:line |
|---|----------|-----------|-----------|
| 1 | Traversal | `../` + null + double-encode + sensitive-sink whitelist | `cfm_waf_detectors.lua:64` |
| 2 | RCE | Substring list (JNDI, `;wget`, `\|bash`, backticks, `base64,`) | `cfm_waf_detectors.lua:102` |
| 3 | Exploit methods | TRACE / TRACK / CONNECT | `cfm_waf_detectors.lua:127` |
| 4 | PHP wrappers | `php://`, `phar://`, `data://`, `zip://`, `expect://`, `glob://` | `cfm_waf_detectors.lua:148` |
| 5 | Control chars | `[\x01-\x08\x0b\x0c\x0e-\x1f]` in args/body with CT gating | `cfm_waf_detectors.lua:192` |
| 6 | PHP webshell body | Scored: `<?php`+superglobals+exec-family+dyn-include+webshell-names | `cfm_waf_detectors.lua:241` |
| 7 | Base64 body scan | Greedy `=([A-Za-z0-9+/]+=*)`, decode, scan decoded for shells/SQL/PHP | `cfm_waf_detectors.lua:401` |
| 8 | XSS | Substring: `<script`, `=javascript:`, `onerror=`/`onload=`/… with `%f[%w]` anchor | `cfm_waf_detectors.lua:457` |
| 9 | SQLi | Substring: `union select`, `information_schema`, `or 1=1`, `' or '1'='1` (post comment-strip) | `cfm_waf_detectors.lua:486` |
| 10 | Auth burst | Endpoint-tagged shdict counter window | `cfm_waf_detectors.lua:547` |
| 11 | WP login probe | HEAD-burst window + no-UA/Referer POST | `cfm_waf_detectors.lua:581` |
| 12 | XMLRPC multicall/pingback | Body substring | `cfm_waf_detectors.lua:726` |
| 13 | XMLRPC POST burst | shdict counter | `cfm_waf_detectors.lua:749` |
| 14 | cmd param key | `exec=`, `passthru=`, …; `cmd/system/command` value-aware shelly check | `cfm_waf_detectors.lua:880` |
| 15 | cmd payload | `;wget`, `\|bash`, backtick-cmd, with search-field / `filters=` carve-outs | `cfm_waf_detectors.lua:920` |
| 16 | Debug toggles | `xdebug` / `debug=1` / `trace=1` by key+value | `cfm_waf_detectors.lua:1045` |
| 17 | PHP serialize | `O:N:"`/`C:N:"` plain & URL-encoded | `cfm_waf_detectors.lua:1090` |
| 18 | Bad UA (scored) | INSTANT tool UAs + 6-signal score (UA / method / headers / URI risk) | `cfm_waf_detectors.lua:1123` |
| 19 | Shellshock | `() {` in any header value (URL-decode once) | `cfm_waf_detectors.lua:1315` |
| 20 | Header vulns | `Proxy`, `Lock-Token`, `If`, CVE-2025-24813 | `cfm_waf_detectors.lua:1342` |
| 21 | CT anomaly | Charset bypass (IBM037 etc.), boundary count, non-string CT | `cfm_waf_detectors.lua:1384` |
| 22 | Proxy header SQLi | `'` in XFF / X-Real-IP / Client-IP | `cfm_waf_detectors.lua:1445` |
| 23 | SSRF proto | `file://`, `gopher://`, `dict://`, `ldap[s]://`, `tftp://`, `stratum+*://`, `sftp/ftp://` + octal/hex/dword IP in `://` ctx | `cfm_waf_detectors.lua:1476` |
| 24 | JS proto pollution | `__proto__`, `constructor` + `.prototype` / `[prototype` | `cfm_waf_detectors.lua:1517` |
| 25 | XXE | DOCTYPE / ENTITY + SYSTEM / PUBLIC | `cfm_waf_detectors.lua:1537` |
| 26 | CRLF | Raw and URL-encoded CRLF + header-keyword | `cfm_waf_detectors.lua:1567` |
| 27 | HTTP smuggling (body) | VERB SP PATH SP HTTP/N | `cfm_waf_detectors.lua:1598` |
| 28 | Upload filename | Quoted/single/unquoted multipart `filename=` + ext patterns + special names | `cfm_waf_detectors.lua:1632` |
| 29 | Upload content | Body substring `<?php`, `<?=` (PHP-context-gated, see `has_php_short_echo`), `<jsp:`, `$_*` superglobals, ImageMagick MVG | `cfm_waf_detectors.lua:1700` |

> **Legit PHP-archive upload carve-out (fixed 2026-06-05).** Rules 401/402/403 and the 431–436 backdoor-content family stand down when `is_known_legit_php_upload_endpoint(uri, args)` matches — the Code Snippets REST flow and, added here, the **WordPress plugin/theme installer** (`/wp-admin/update.php?action=upload-plugin` / `upload-theme`). A plugin/theme `.zip` legitimately contains PHP (often obfuscated in commercial products), so on that authenticated, cookie-auth-gated path the PHP that is the payload must not be flagged — a plugin named e.g. `foo-block.php.zip` also tripped the double-extension filename rule. Media uploads (`async-upload.php`) are **not** exempted: a PHP opener inside a claimed image there is still a polyglot. (437/438 keep their own broader `/wp-admin/` carve-out for snippet-save plugins — with 438's audit-F11 pre-auth `admin-ajax.php`/`admin-post.php` `logonly` exception; see FP case 5.)
| 30 | Script obfuscation | Shared scorer (long-b64 / decode-helpers / eval / atob / XOR / chr-storm) | `cfm_waf_detectors.lua:1730` + `cfm_waf_util.lua:115` |
| 31 | Upload obfuscation | Same scorer on multipart | `cfm_waf_detectors.lua:1753` |
| 32 | Webshell path | URI basename ∈ 32-name set, split by confidence: proper-noun names → rule 413 (block), ambiguous/generic → rule 410 (challenge) | `cfm_waf_detectors.lua` `detect_webshell_path` |
| 33 | Reverse shell | 24 literal one-liner needles | `cfm_waf_detectors.lua:1897` |
| 34 | Persistence | crontab / cron.d / systemd / bashrc / authorized_keys with `>>`/`>` | `cfm_waf_detectors.lua:1981` |
| 35 | Rootkit | `LD_PRELOAD=/`, `/etc/ld.so.preload`, `insmod /tmp/`, `/dev/mem` | `cfm_waf_detectors.lua:2013` |
| 36 | LOLbin | certutil / bitsadmin, `-EncodedCommand`, IEX, `wget -o /tmp/` | `cfm_waf_detectors.lua:2049` |
| 37 | Java deserialize | `\xac\xed\x00\x05` raw + `rO0AB` b64 + `aced0005` hex (body/cookie/auth/xff) | `cfm_waf_detectors.lua:2073` |
| 38 | Webshell ping | POST + empty UA + CL:0 + `.php` / `.phtml` / `.phar` URI | `cfm_waf_detectors.lua:2124` |
| 39 | C2 tunnel | 21 hostnames (pastebin, ngrok, webhook.site, discord cdn, telegram) | `cfm_waf_detectors.lua:2168` |
| 40 | Coinminer | xmrig / xmr-stak flags + pool hostnames + monerod / ethminer | `cfm_waf_detectors.lua:2218` |
| 41 | Smuggling CL/TE | CL+TE coexist / multi-CL / malformed CL / multi-TE | `cfm_waf_detectors.lua:2267` |
| 42 | Long path segment | ≥ 800 B segment with `data:` URI artifact carve-out | `cfm_waf_detectors.lua:2347` |
| 43 | Header flood | > 16 KB excluding Cookie / Authorization | `cfm_waf_detectors.lua:2374` |
| 44 | Polyglot upload | Multipart parser → first 64 B of image-claimed parts checked vs PHP/ASP/JSP/script openers | `cfm_waf_detectors.lua:2423` |
| 45 | Range abuse | `Request-Range`, multi `Range`, oversized, ≥ 8 ranges | `cfm_waf_detectors.lua:2533` |
| 46 | IP host | Host header is bare IPv4 / IPv6 literal | `cfm_waf_detectors.lua:162` |
| 47 | Log4Shell evasion | `${${::-j}…`, `${lower:j}…`, `${env:` / `sys:` / `main:` / `date:` / `base64:` in args+body+headers | `cfm_waf_detectors.lua` (`detect_log4shell`) |
| 48 | Bad UTF-8 | Overlong / surrogate / truncated multibyte in normalized args+body (Coraza `validateUtf8Encoding` port) | `cfm_waf_detectors.lua` (`detect_bad_utf8`) |
| 49 | PHP split-string canary (421) | `<?php print "A"."B";exit;` exec-test probe; print/echo/die + quoted-string concat + whole-word `exit`/`die`, no control-flow disqualifiers | `cfm_waf_detectors.lua` (`detect_php_split_string_canary`) |
| 50 | PHP wget+curl dropper (422) | `wget -O` + `curl -o` fallback pair + `filesize()` integrity + `@touch(`/`file_exists(` | `cfm_waf_detectors.lua` (`detect_php_dropper_wget_curl`) |
| 51 | PHP dropper markers (423) | `'!success!'` + `'!ended!'` literals + `die(`/`exit(` framing | `cfm_waf_detectors.lua` (`detect_php_dropper_markers`) |
| 52 | PHP filesize recon (424) | `<fs>` literal tag + `filesize(` + `SCRIPT_FILENAME` reference | `cfm_waf_detectors.lua` (`detect_php_filesize_recon`) |
| 53 | PHP touch anti-forensic (425) | `@touch(<path>, <literal-unix-ts>)` mtime backdating + paired file-write primitive | `cfm_waf_detectors.lua` (`detect_php_touch_antiforensic`) |
| 54 | Superglobal override (318) | param KEY = PHP superglobal name (`_GET`/`_SERVER`/`GLOBALS`/…), delimiter-anchored so `db_server=` / value-position do not match; clean-room (NinjaFirewall gap analysis), `logonly` | `cfm_waf_detectors.lua` (`detect_superglobal_override`) |
| — | Body budget by CT | json=32K / multipart=16K / xml=16K / urlencoded=8K / other=2K | `cfm_waf_util.lua:249` |
| — | Normalize | `url_decode_once × 2` + `lower`, with no-`%` fast path. **No UTF-8 / unicode normalization.** | `cfm_waf_util.lua:211` |

## Coverage matrix vs external projects

Cell values: **stronger** / **equivalent** / **weaker** / **none** / **different-scope**.

Column key — **A** `corazawaf/libinjection-go` (pure-Go libinjection port) · **B** `wasilibs/go-libinjection` (WASM via wazero) · **C** `corazawaf/coraza` (full Go WAF) · **D** `p0pr0ck5/lua-resty-libinjection` (LuaJIT FFI binding, most relevant to CFM) · **E** `bungle/lua-resty-injection` (minimal LuaJIT FFI binding) · **F** OWASP CRS.

| Category | A — libinjection-go | B — wasilibs | C — Coraza | D — p0pr0ck5 | E — bungle | F — CRS |
|----------|---------------------|--------------|------------|--------------|------------|---------|
| SQLi | stronger (tokenizer + fingerprint) | stronger (same via WASM) | stronger (wraps A + CRS regex) | **stronger (FFI tokenizer + context variants)** | stronger (FFI, minimal API) | stronger (REQUEST-942) |
| XSS | stronger (HTML5 state machine) | stronger | stronger | **stronger (context-aware variants)** | stronger | stronger (REQUEST-941) |
| Traversal | none | none | equivalent (CRS-930 + `validateUrlEncoding`) | none | none | stronger |
| RCE | none | none | equivalent | none | none | stronger (CRS-932) |
| PHP wrappers | none | none | equivalent | none | none | equivalent (CRS-933) |
| Bad UA scoring | none | none | none | none | none | weaker (flat UA lists) |
| Header vulns | none | none | none | none | none | equivalent (CRS-921 / 944) |
| CT anomaly | none | none | different-scope (`validateByteRange`, `validateUtf8Encoding`) | none | none | equivalent (CRS-920) |
| Upload filename/content | none | none | different-scope | none | none | equivalent (CRS-953 / 954) |
| Polyglot upload | none | none | none | none | none | weaker |
| Webshell path / ping | none | none | none | none | none | weaker |
| Reverse shell / persistence / rootkit / lolbin | none | none | none | none | none | equivalent (CRS-932 unix tokens) |
| Java deserialize | none | none | none | none | none | equivalent (CRS-944) |
| C2 tunnel / coinminer | none | none | none | none | none | none |
| HTTP smuggling (CL/TE + body) | none | none | weaker | none | none | weaker |
| CRLF | none | none | weaker | none | none | equivalent (CRS-921) |
| Auth / XMLRPC bursts | different-scope | different-scope | different-scope (Coraza has no rate logic) | none | none | different-scope (CRS-DoS plugin) |
| Long path / header flood / range | none | none | equivalent (partial) | none | none | equivalent (CRS-920) |
| Normalize / decoding | none | none | **stronger** (`validateUtf8Encoding`, `t:normalizePath`, `t:cmdLine`, `t:cssDecode`, `t:jsDecode`) | none | none | stronger |
| SSRF proto | none | none | weaker | none | none | weaker (CRS-934) |
| JS proto pollution | none | none | none | none | none | equivalent (CRS-934) |
| XXE | none | none | equivalent | none | none | equivalent (CRS-934) |
| Proxy header SQLi | none | none | none | none | none | none |

**Net read:** the only two columns where any reference is meaningfully
stronger across CFM's workloads are libinjection (D / E) for SQLi + XSS
and Coraza's normalization operators (C) for encoding anomalies. The
rest of CFM's surface is either at parity with CRS or covers categories
no reference project covers at all (bad-UA scoring, webshell-name set,
auth / XMLRPC burst logic, C2 tunnel / coinminer fingerprints).

