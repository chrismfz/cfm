# Imunify360 vs CFM: what Imunify catches that CFM does not (measured)

Status: **analysis, partly built** (measured 2026-11-17 on earth; status
updated the same evening, see "Where we are"). Companion to
[`imunify-webshield-parity.md`](imunify-webshield-parity.md), which covers
WebShield alone.

## Where we are (2026-11-17)

| Gap | Status | What shipped / what is next |
|---|---|---|
| G1 global reputation | **part built** | dovecot counts Imunify's `user_disabled` refusals (24 h TTL ban + fleet report, chrismfz/cfm#1678). Public feeds: not started |
| G2 add-to-cart crawling | **built, logonly** | rule 530 `WAF_CART_CRAWL` (chrismfz/cfm#1677); burn-in reads 2026-11-20 and 11-24 |
| G3 attacks Imunify's ModSec sees | **re-scoped** | the GET webshell-path probes are low value (a probe with no file behind it); the real escape was PHP **uploaded** past rule 404's 2 KB window, now rule 417 (below) |
| G3b uploads that escaped (new) | **built, logonly** | rule 417, 10029 block, 415 extension tag (chrismfz/cfm#1679); CT-parameter bypass of 404/417/601/611 closed (chrismfz/cfm#1679, #1680) |
| WebShield's IP lists for proxied clients | **built, log mode** | `internal/proxyipfilter` (chrismfz/cfm#1670), country / ASN in its log (chrismfz/cfm#1681); `enforce` after a week of reads |
| G4 vulnerable code on disk | not started | the `vulnerability_hits` collector |
| G5 PHP runtime | not started | FS-009 |
| G6 malware at rest | **measured** | the 45-day trace below; ClamAV-vs-Imunify signature comparison not done |
| G7 smaller items | not started | |

Found on the way, tracked separately: Meta's forward proxies
(`fwdproxy-*.fbsv.net`, AS32934) have been permanently on mars' and titan's
`block_v4` since May, from the SYN / port-flood detectors (59 addresses, one
on the fleet list too). They break link previews and Facebook in-app visits
for direct clients today, and would for proxied ones under
`PROXIED_IPFILTER_LOCAL = enforce` (`docs/proxied-ipfilter.md`).

Imunify360 8.15.1 on earth, read-only: its config (`imunify360-agent config
show`), its incident store (`/var/imunify360/imunify360-resident.db`,
`incident`), the malware / vulnerability store (`imunify360.db`) and
Proactive Defense's (`proactive.db`), compared with what CFM's edge did with
the same traffic. Measured on one node; the fleet runs the same Imunify
setup on cPanel.

## What runs, and what it caught

| Engine | Enabled on earth | Caught | Where it sits relative to CFM |
|---|---|---|---|
| ModSecurity, Imunify's ruleset (`FULL`, app-specific, WordPress WAF, CMS account-compromise prevention) | yes | **51 176 incidents / 33 811 IPs in 7 d** | in Apache, **after** CFM's edge: everything it saw got through CFM's WAF |
| OSSEC (log rules, active response) | yes | 34 520 / 11 558 IPs in 7 d | same logs as CFM's detectors |
| PAM (`pam_imunify`: exim, dovecot) with Imunify's global RBL | yes | 8 824 locked logins in 7 d | before auth; CFM has no equivalent |
| Malware scanner (inotify realtime, cloud-assisted, auto cleanup, DB scan) | yes | 36 detections in 30 d (webshells, ~all cleaned) | CFM: ClamAV (`internal/clam`) |
| Proactive Defense (PHP runtime, `KILL`, auto-immunity) | yes | 39 blocks in 30 d | CFM: none; design FS-009 (`lsm-php-drop-detection.md`) |
| Vulnerability scanner (outdated plugin / app code) | yes, no patching (`PATCHMAN` off) | **41 179 vulnerable files** (top: VULN-ESUS-5224 ×2 722) | CFM: none |
| WebShield (IP lists on the real client, splash, captcha) | yes | see `imunify-webshield-parity.md` | bypassed by CFM's edge since -101 |
| DOS / CAPTCHA_DOS (`cl_dos`) | yes | 3 in 7 d | CFM: conn limits, challenge page rate limit |
| SMTP blocking, KernelCare EDF, Patchman, AI bot protection, port-scan block | off | — | — |

## The gaps, by measured size

### G1. Global IP reputation (Imunify's RBL). Largest, and nothing in CFM covers it

- PAM locked **8 824** mail/FTP logins in 7 days because the source is on
  Imunify's **global** RBL (`[IM360_RBL] The IP … has been locked`), before
  any password is tried.
- **0 of 25** sampled RBL-locked IPs (the last 24 h) are on CFM's fleet
  blacklist (`MYBLOCK`, 268 k).
- So the reputation comes from Imunify's whole customer base, not ours. On the
  web side the same intelligence shows up as ModSec rules keyed on it: "Block IP
  which is in the web-spammers RBL" (1 062), "Joomla Com_Fabrik Vulnerabilities
  (RBL)" (1 048).

CFM's detectors (exim / dovecot / ftp) only react after an address fails
locally, and the fleet list only knows what our ~10 nodes saw. It is worse
than that: of those 25, 19 are in the maillog only as dovecot
`Login aborted … (user disabled, 1 attempts in 2 secs) (user_disabled)`.
PAM refuses them before a password is checked, so no detector on this node
ever sees an auth failure, never bans them and never reports them to
cfm-web. On an Imunify node, PAM hides exactly the addresses the fleet list
would want. Counting `user_disabled` aborts per address in the dovecot
detector would bring them back into the fleet list.

**Built (chrismfz/cfm#1678):** the dovecot detector counts `user_disabled`
refusals per address (`USER_DISABLED_IP = 2` in 24 h), bans for at most 24 h
whatever the section's `BLOCK`, and reports to cfm-web, so the addresses
Imunify's RBL knows reach the fleet list from the first Imunify node that
sees them (`docs/DETECTORS.md`, "dovecot_auth — logins refused as
user_disabled"). It covers mail only, and only addresses that try an Imunify
node.

**Still proposed:** add proven public feeds to `cfm.blocklists`, which already takes
third-party feeds: blocklist.de (mail, imap, ssh, apache), Spamhaus DROP/EDROP,
and similar.
- Measure first: for a week, count how many PAM-RBL-locked addresses each
  candidate feed holds, and how many of our own customers' addresses it holds
  (false positives).
- Then load the ones that pay, as BLOCK feeds. They then reach Cloudflare
  visitors too, through `proxyipfilter`.

### G2. WooCommerce `add-to-cart` crawling. Big, cheap to fix

- Imunify's "GET add-to-cart flood pattern" fired **28 725 times in 7 days**,
  more than half of all its ModSec incidents. Top hosts in 24 h: armafabrics.gr
  2 041, olicatessen.gr 815, gastronom.gr 361.
- At CFM's edge, ~3 hours of log held **4 216 `add-to-cart=` requests from 884
  clients**, and 85% reached the shop (status 200).
- These are crawlers following the `?add-to-cart=<id>` links of WooCommerce
  listings (CCBot among them) from rotating addresses. Each one can start a
  session and a cart in the shop's database.

**Built (chrismfz/cfm#1677), logonly:** rule 530 (`WAF_CART_CRAWL`). The fleet
read before it: ~265 000 such requests a day, uncached at 1-3 s each, ~85% to
self-declared crawlers (meta-externalagent the largest). It tags `CRAWLER`,
`NO_REFERER` or `XSITE` and stands down for a shopper's click (same-site
Referer or Fetch Metadata) and for a cart or login cookie (`docs/waf.md`,
"Rule 530"). Open: whether the `CRAWLER` tag gets a 301 to the product page
instead of a cart write, after the burn-in.

The original proposal: a WAF rule (or traffic-rule recipe) for a `GET` with an
`add-to-cart` parameter from a client without a WooCommerce session cookie.
- Start it `logonly`, then challenge.
- A real shopper adds to the cart with a session (or by POST from the product
  page), so the cookie-less GET is almost always a crawler.
- Measure on the fleet first (`edge_access_tail`, `node="all"`); never `block`
  straight away.

### G3. Web attacks Imunify's ModSec sees after CFM's WAF let them through

Audited rule by rule on 2026-11-17: 3-5 random samples of each top rule
over 2 days (`incident.description` holds the matched variable and value),
and what CFM's edge did with the same kind of request over the edge log's
last ~24 h (2.5 M lines).

**Imunify false positives (nothing to copy):**

| Rule (2 d) | What it matched |
|---|---|
| Possible SQL injection (279 / 100 IPs) | TikTok's `ttcsid*` cookie, the MotoPress `mphb_session` cookie, `title=Home - Default (2)` |
| Spring Framework (317 / 17 IPs) | WooCommerce `product_shipping_class=-1`, `variable_shipping_class[0]`, a page builder's `class_name` |
| Drupalgeddon CVE-2018-7602 (178 / 54 IPs) | the whole `Cookie` header of WooCommerce shops (sourcebuster `sbjs_*` cookies) |
| Multiple access-control-allow-origin (506) | a response header of one site, not a request |
| Request body parsing error (187) | `SecArgumentsLimit`, more than 1 000 JSON keys: admin saves |
| WP REST "App-Password channel" (452 / 445 IPs) | `GET /wp-json/wp/v2/users/me` from desktop Chrome: logged-in editors |

So the 641 "SQLi that passed CFM" are not a CFM gap: none is an injection.

**Real, and CFM already stops it:**

| Rule | CFM at the edge, ~24 h |
|---|---|
| Dotfiles (`/.git/HEAD`, `/.env`, 220 / 2 d) | 157 569 exact probes: 105 k challenged (malpath), 10 k blocked, the rest 401/403/404 from the origin. 10 got a 200, all an app's catch-all page |
| Fake Googlebot (204 / 2 d) | 1 370 requests with a Googlebot UA from outside Google's crawler ranges. The heavy ones are GCP VMs (`*.bc.googleusercontent.com`) scanning `/.env`, `swagger.json`, `/proc/self/environ`: 403 at the edge. The good-bot exemption is FCrDNS-verified, so a fake Googlebot is an ordinary client |
| XML-RPC (`metaWeblog.newPost` with guessed users, fault responses) | 2 951 of 3 400 `POST /xmlrpc.php` are `cfm_block` (510-512); the 347 that pass are below the burst threshold, one or two per address |
| Webshell paths (`/images/images/…/cache.php`, 710 / 108 IPs) | 1 204 requests, ~all reached the origin and got 404/301/403. The 15 that got a 200 hit a CMS catch-all: no `cache.php` exists in those docroots (checked) |

**Real gaps worth a rule** (G2 included):

- **`add-to-cart` GET without a WooCommerce session** (G2): 8 125 hits from
  7 082 addresses in 2 days, one or two requests per address, often on a
  bogus path (`/ilv-blocked.txt?add-to-cart=…`, `/index.php?add-to-cart=…`).
  Residential-proxy crawling: per-IP counting never sees it, a request-shape
  rule does.
- **Webshell path probes** (`(/images)+/cache.php` and similar known drop
  names): CFM's WAF logged none of the 1 204. **Not built, by decision:** a
  GET for a file that is not there harms nothing, and the effort went to the
  uploads that did land (G3b).
- **Headless UA** (132 / 72 IPs in 2 d; the edge saw 8 237 `HeadlessChrome`
  requests in ~24 h, 464 to dynamic pages): a UA rule was measured and
  rejected for challenge v2 (most are site owners' own tools). Not a block.
  At most a `logonly` tag for the WAF corpus.
- **WordPress `/?author=N` enumeration**: ~230 / day at the edge, mostly
  404/301 from the origin. Low value: WordPress shows author slugs on every
  post anyway. Skip.

### G3b. PHP that was uploaded past CFM's WAF (found 2026-11-17, built)

Every file Imunify360 removed on the fleet in the last 45 days
(`malware_hits` in `imunify360.db`, the cleaned copies in
`/var/imunify360/cleanup_storage`) was traced to how it got there, from the
edge logs and the files' birth times (`stat -c %w`, which `touch` cannot
change). Two came in through the same CFM gap: rule 404 scores PHP source in a
POST body over its **first 2 KB only**, and PHP saved through a form field sits
wherever the file puts it.

- apolymanseisantoniou.gr (orion, 2026-11-15): a plugin-editor save with an
  eval of a request header at line 32;
- zerooneoliveoil.gr (rigel, 2026-11-17): a file manager's `cmd=put`, then the
  shell's own editor, saving a shell whose comment header fills the first 2 KB.

The other removals (compromised accounts, older backdoors) are in the
customer cleanup, outside the WAF. The backdoors rigel took as multipart
`.txt` uploads led to the fleet read of rules 702, 10029 and 415 in
`docs/waf.md`.

**Built (chrismfz/cfm#1679):**
- **rule 417** (`WAF_PHP_WEBSHELL_BODY:DEEP_*`, logonly): 404's scorer over the
  whole body the edge reads (32 KB), multipart text fields and JSON escapes
  included (`docs/waf.md`, "Rule 417");
- **rule 10029** (Fabrik list-filter eval, CVE-2026-67282, the dmkomotinis.gr
  compromise) promoted to block, armed: the first probe bans before a payload;
- **rule 415**'s tag names the uploaded file's extension, so its burn-in can
  be decided;
- a Content-Type naming `multipart/form-data` in a parameter hid the body
  from rules 404, 417, 601 and 611; they now read the media type, as PHP does
  (chrismfz/cfm#1679, #1680).

Six adversarial review rounds found and fixed 22 issues in 417 before merge;
the fleet burn-in decides any promotion.

### G4. Vulnerable code on disk: data CFM could use

41 179 files flagged vulnerable, and nothing patches them (Patchman off). CFM
cannot fix them, but the list says which plugins and versions the fleet runs.
That is exactly what decides which `WAF_CVE` rules to write next (`WAF_CVE.md`,
"CVE hunting").

**Proposal:** a read-only collector of `vulnerability_hits` (type, count,
users) per node, published to cfm-web. Use it to rank the CVE backlog by
exposure, not by headline.

### G5. PHP runtime defense

Proactive Defense blocked 39 executions in 30 days. 28 of them were
"Malware drop/interaction blocked", and one was an auto-immunity rule it
generated itself on 2026-11-12, the day of the Fabrik compromise. CFM has no
PHP-runtime layer. **Proposal:** the FS-009 design (`lsm-php-drop-detection.md`)
is the path at the kernel boundary; its count-only phase can be sized against
these 39.

### G6. Malware at rest

Imunify found 36 webshells in 30 days and cleaned almost all of them. The
45-day trace of the fleet's removals (G3b) answered "how did they get there"
for the web path; the signature question is still open.
**Proposal (measurement first):** compare against what CFM's ClamAV found on
the same node and window. If Imunify's cloud-assisted signatures find what
ClamAV does not, the gap is signatures, not plumbing.

### G7. Smaller items to check, not measured

- `AUTO_WHITELIST.panel_login`: an IP that logs in to cPanel is whitelisted
  for 24 h. Does CFM do the same (and should it)?
- `CONTROL_PANEL.compromised_user_password_reset`: Imunify forces a password
  reset on an account it judges compromised. CFM's mail-abuse findings
  (`docs/mail-abuse.md`) report but do not act.
- `MOD_SEC.cms_account_compromise_prevention`.

## Not gaps

- Anti-bot splash: 10 894 passed / 481 failed. CFM's challenge does this, and
  WebShield is out of the path at -101.
- DOS and captcha-DoS: CFM's connection limits and the challenge page's rate
  limit and ban.
- Exim auth failures (7 413): CFM's exim / dovecot detectors.

## Order (updated 2026-11-17)

Done or in burn-in: G2 (rule 530), the G1 dovecot part, G3b (rule 417, 10029,
415), the proxied IP filter. Next:

1. **Burn-in reads** (2026-11-20, 2026-11-24): 417, 415 by extension, 530,
   and the proxied IP filter with its new `cc=` / `asn=` fields. Promotions
   and `PROXIED_IPFILTER_FEED = enforce` are decided there.
2. **The Meta fwdproxy bans** (unban, and keep the flood detectors from
   banning Meta's verified crawlers), before `PROXIED_IPFILTER_LOCAL = enforce`.
3. **G1 public feeds**: measure blocklist.de / Spamhaus DROP against the PAM
   RBL locks for a week, no code until a feed proves itself.
4. **G4 collector** (`vulnerability_hits` → cfm-web), small, and it ranks the
   CVE backlog by the fleet's real exposure.
5. **WebShield P2-P4** (`imunify-webshield-parity.md`): P4 first ("never ban
   a CDN node as a client"). The first proxied-filter read already showed a
   Cloudflare Workers egress address (`2a06:98c0:3600::103`) on earth's
   `block_v6` and the fleet list, for WEB/MALPATH.
6. G5 / G6 as already planned (FS-009, the ClamAV comparison); G7 unmeasured.
