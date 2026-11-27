# Imunify360 vs CFM: what Imunify catches that CFM does not

What Imunify360 caught on a node where CFM's edge also ran, which of it CFM
misses, and where each gap stands. WebShield, the part of Imunify that sat in
front of CFM's edge, has its own section below.

Measured once, read-only, on earth (2026-11-17, Imunify360 8.15.1; the fleet's
cPanel nodes run the same setup): `imunify360-agent config show`, the
incident store (`/var/imunify360/imunify360-resident.db`, `incident`), the
malware / vulnerability store (`imunify360.db`), Proactive Defense's
(`proactive.db`), WebShield's package and log, compared with what CFM's edge
did with the same traffic. The numbers below are that measurement; they are
kept where they size a gap or justify a decision.

## Status

| Gap | Status | Where / what is open |
|---|---|---|
| G1 global IP reputation | **mail part built**; public feeds loaded 2026-11-27 (DROP block, blocklist.de / CINS challenge, log) | dovecot `user_disabled` counting (`internal/detectors/dovecot/auth.go:151`, ban cap `:407`, defaults `internal/detectors/dovecot_register.go:70-73`). Spamhaus DROP as BLOCK, blocklist.de / CINS as CHALLENGE on the web nodes since 2026-11-27 (`configs/cfm.blocklists`) |
| G2 WooCommerce `add-to-cart` crawling | **built, logonly** | rule 530 `WAF_CART_CRAWL` (`configs/lua/cfm_waf.lua:125`, `internal/webdetector/waf_rule_ids.go:215`). Open: promotion, and whether the `CRAWLER` tag gets a 301 to the product page |
| G3 attacks Imunify's ModSec saw past CFM | **re-scoped**, see G3b | webshell-path GET probes not built, by decision; headless-UA rule rejected; `?author=N` skipped |
| G3b PHP uploaded past rule 404's 2 KB window | **built; 417 and 415 block since 2026-11-24 (bans held)** | rules 417 and 415 (`rule_php_webshell_body_deep`, `rule_upload_content_deep` in `cfm_waf.lua` and `waf_rule_ids.go`); rule 10029 at block, `WAF_CVE` armed (`rule_cve_fabrik_listfilter_eval`); rule 415's tag carries the file extension (`configs/lua/cfm_waf_detectors.lua:5870`); multipart media type read as PHP does (`cfm_waf_detectors.lua:734`) |
| G4 vulnerable code on disk | open | no `vulnerability_hits` collector in the tree |
| G5 PHP runtime | open | design only: `docs/roadmaps/php-runtime-defense.md`, `docs/lsm-php-drop-detection.md` (FS-009) |
| G6 malware at rest | open | ClamAV-vs-Imunify signature comparison not done |
| G7 smaller items | open, unmeasured | |
| W0 WebShield DNAT ahead of CFM | **built** | `edge_health` check H, `internal/apiserver/edge_health_webshield.go:137` |
| W1 IP lists for clients behind Cloudflare | **built; local sets and fleet feeds enforced since 2026-11-26** | `internal/proxyipfilter` (`Decide`; bridge `writeEdgeBan` in `internal/webdetector/nginx_bridge.go`); modes `PROXIED_IPFILTER_*` in `internal/detectors/webdetector_register.go`. Open: clear permanent fleet bans on shared mobile / CGNAT addresses |
| W2 Imunify's splash list as a challenge source | open, measure first | |
| W3 graylisted direct visitors dropped | **decided: no CFM code** | warned in check H's fix text (`edge_health_webshield.go:175-181`) |
| W4 never ban a CDN node as a client | open | |

## What runs, and what it caught (earth, 2026-11-17)

| Engine | Caught | Relative to CFM |
|---|---|---|
| ModSecurity, Imunify's ruleset (`FULL`, app-specific, WordPress WAF, CMS account-compromise prevention) | **51 176 incidents / 33 811 IPs in 7 d** | in Apache, **after** CFM's edge: everything it saw got through CFM's WAF |
| OSSEC (log rules, active response) | 34 520 / 11 558 IPs in 7 d | same logs as CFM's detectors |
| PAM (`pam_imunify`: exim, dovecot) with Imunify's global RBL | 8 824 locked logins in 7 d | before auth; G1 |
| Malware scanner (inotify realtime, cloud-assisted, auto cleanup) | 36 detections in 30 d (webshells, ~all cleaned) | CFM: ClamAV (`internal/clam`); G6 |
| Proactive Defense (PHP runtime, `KILL`, auto-immunity) | 39 blocks in 30 d | CFM: none; G5 |
| Vulnerability scanner (`PATCHMAN` off: nothing patched) | **41 179 vulnerable files** (top: VULN-ESUS-5224 ×2 722) | CFM: none; G4 |
| WebShield (IP lists on the real client, splash, captcha) | see [WebShield](#webshield) | out of the path once CFM's redirect runs first |
| DOS / CAPTCHA_DOS (`cl_dos`) | 3 in 7 d | CFM: conn limits, challenge page rate limit |
| SMTP blocking, KernelCare EDF, Patchman, AI bot protection, port-scan block | off | — |

## The gaps

### G1. Global IP reputation (Imunify's RBL)

PAM locked **8 824** mail/FTP logins in 7 days because the source was on
Imunify's **global** RBL (`[IM360_RBL] The IP … has been locked`), before any
password was tried. **0 of 25** sampled RBL-locked IPs were on CFM's fleet
blacklist (`MYBLOCK`, the opt-in `cfm.blocklists` feed): the reputation comes from Imunify's whole customer
base, not our nodes. And PAM hides them from CFM: 19 of those 25 appear in
the maillog only as dovecot `Login aborted … (user_disabled)`, so no detector
saw an auth failure, banned them or reported them.

**Built (mail):** the `dovecot_auth` detector counts `user_disabled` refusals
per IP (`USER_DISABLED_IP = 2` in `USER_DISABLED_WINDOW = 24h`), bans for at
most `USER_DISABLED_BLOCK_TTL` (24h) whatever the section's `BLOCK`
(`core.ExtraMaxBlockTTL`), and reports to cfm-web, so an address Imunify's RBL
knows reaches the fleet list from the first Imunify node it tries. Reference:
`docs/DETECTORS.md`, "dovecot_auth — logins refused as user_disabled". Mail
only, and only addresses that try an Imunify node.

**Public feeds (2026-11-27).** Measured on earth's GeoLite2: Spamhaus DROP
(1 737 v4 networks, 90 v6) holds no Greek or Cypriot address; blocklist.de
`all` (25 229 v4, 607 v6) holds 16 and CINS Army (15 000) 8, residential ones
among them (OTE, Nova, Vodafone, Cyta, Primetel). So DROP / DROPv6 run as
`BLOCK` (every port, mail included; through `proxyipfilter` for Cloudflare
visitors too), and blocklist.de / CINS as `CHALLENGE` feeds (web only, a
challenge floor; `LIST_CHALLENGE`, log first), on the eight web nodes. EDROP is
merged into DROP. Open: how many PAM-RBL-locked addresses the feeds hold (the
mail half of the gap), which the CHALLENGE feeds do not cover.

### G2. WooCommerce `add-to-cart` crawling

Imunify's "GET add-to-cart flood pattern" fired **28 725 times in 7 days**,
more than half its ModSec incidents; at CFM's edge 85% of such requests
reached the shop. Crawlers follow listings' `?add-to-cart=<id>` links from
rotating addresses, one or two requests each (7 082 addresses in 2 days), so
per-IP counting never sees it; each request writes a session and a cart.

**Built, logonly:** rule 530 (`WAF_CART_CRAWL`, `docs/waf.md` "Rule 530 …").
Promotion is the burn-in's decision; so is whether the `CRAWLER` tag gets a
301 to the product page instead of a cart write. Never `block` straight away.

### G3. Web attacks Imunify's ModSec saw after CFM's WAF

Audited rule by rule (3-5 samples of each top rule over 2 days, against
CFM's edge log for the same kind of request).

**Imunify false positives, nothing to copy:** "Possible SQL injection" (TikTok
`ttcsid*` and MotoPress `mphb_session` cookies, a page title), "Spring
Framework" (WooCommerce `product_shipping_class=-1`), "Drupalgeddon
CVE-2018-7602" (sourcebuster `sbjs_*` cookies), "Multiple
access-control-allow-origin" (a response header), "Request body parsing error"
(admin saves past 1 000 JSON keys), WP REST "App-Password channel"
(`/wp-json/wp/v2/users/me` from logged-in editors). None of the 641 "SQLi that
passed CFM" is an injection.

**Real, and CFM already stops it:** dotfile probes (`/.git/HEAD`, `/.env`:
challenged by malpath or blocked at the edge; the few 200s were an app's
catch-all page); fake Googlebot (the good-bot exemption is FCrDNS-verified, so
a fake one is an ordinary client; the heavy ones, GCP VMs scanning `/.env`,
get 403); XML-RPC `metaWeblog.newPost` guessing (rules 510-512; what passes is
below the burst threshold).

**Decided:**
- **Webshell path probes** (`(/images)+/cache.php` and similar drop names):
  not built. A GET for a file that is not there harms nothing (none existed in
  the docroots that answered 200); the effort went to the uploads that did
  land (G3b).
- **Headless UA:** a UA rule was measured and rejected for challenge v2 (most
  are site owners' own tools). Not a block; at most a `logonly` tag.
- **WordPress `/?author=N` enumeration:** skipped. WordPress shows author slugs
  on every post anyway.

### G3b. PHP uploaded past CFM's WAF

Every file Imunify removed on the fleet in 45 days (`malware_hits`, the copies
in `/var/imunify360/cleanup_storage`) was traced to how it arrived, from the
edge logs and the files' birth times (`stat -c %w`). Two came through one CFM
gap: rule 404 scores PHP source in a POST body over its **first 2 KB only**,
and PHP saved through a form field sits wherever the file puts it (a
plugin-editor save with an eval at line 32, orion 2026-11-15; a file manager's
`cmd=put` of a shell whose comment header fills the first 2 KB, rigel
2026-11-17). The other removals came from compromised accounts and older
backdoors, outside the WAF.

**Built:**
- **rule 417** (`WAF_PHP_WEBSHELL_BODY:DEEP_*`, block since 2026-11-24, ban held): 404's scorer over the
  whole body the edge reads (32 KB), multipart text fields and JSON escapes
  included (`docs/waf.md`, "Rule 417");
- **rule 10029** (Fabrik list-filter eval, CVE-2026-67282) at block with
  `WAF_CVE` armed: the first probe bans before a payload;
- **rule 415**'s tag names the uploaded file's extension
  (`UPLOAD_PHP_TAG_DEEP:<ext>`), so its burn-in can be decided per extension;
- a Content-Type naming `multipart/form-data` in a parameter no longer hides
  the body from rules 404, 417, 601 and 611: they read the media type as PHP
  does.

Promotions of 417 and 415 are the burn-in's decision.

### G4. Vulnerable code on disk

41 179 files flagged vulnerable, none patched. CFM cannot fix them, but the
list says which plugins and versions the fleet runs, which is what should
decide the next `WAF_CVE` rules (`WAF_CVE.md`, "CVE hunting").

**Open:** a read-only collector of `vulnerability_hits` (type, count, users)
per node, published to cfm-web, to rank the CVE backlog by exposure.

### G5. PHP runtime defense

Proactive Defense blocked 39 executions in 30 days (28 "Malware
drop/interaction blocked"; one an auto-immunity rule it generated the day of
the Fabrik compromise). CFM has no PHP-runtime layer. **Open, two layers, no
third:** CFM-managed Snuffleupagus inside the PHP VM
(`docs/roadmaps/php-runtime-defense.md`; CFM writes no PHP extension of its
own), and at the kernel boundary FS-009 (`docs/lsm-php-drop-detection.md`),
whose count-only phase can be sized against those 39.

### G6. Malware at rest

Imunify found 36 webshells in 30 days. G3b answered "how did they get there"
for the web path; the signature question is open. **Open (measure first):**
compare with what CFM's ClamAV found on the same node and window. If Imunify's
cloud-assisted signatures find what ClamAV does not, the gap is signatures,
not plumbing.

### G7. Smaller items, not measured

- `AUTO_WHITELIST.panel_login`: Imunify whitelists an IP that logs in to
  cPanel for 24 h. Should CFM?
- `CONTROL_PANEL.compromised_user_password_reset`: Imunify forces a password
  reset on an account it judges compromised. CFM's mail-abuse findings
  (`docs/mail-abuse.md`) report but do not act.
- `MOD_SEC.cms_account_compromise_prevention`.

## WebShield

### W0. The DNAT order (built)

A connection is NAT'd once, by the first nat chain that rewrites it.
Imunify360 DNATs its IP sets to WebShield (`:52223` https, `:52224` http, and
the panel ports) from `ip nat PREROUTING` at priority -100. CFM's web redirect
(`inet cfm_redirect`) defaults to -99 (`NFTDNATPriority`,
`internal/dnat/status.go:19`). On a cPanel node `i360.ipv4.remote_proxy_static`
holds Cloudflare's ranges, so **every Cloudflare visitor went to WebShield and
never reached CFM's edge** (WAF, challenge, edge bans, logging). On earth, one
hour: the edge served 74 407 requests (235 through Cloudflare), WebShield
30 650 (~93% from Cloudflare); WebShield's archived logs showed this had gone
on for months.

The fix on an Imunify node is `NFT_DNAT_PRIORITY = -101` in `cfm.conf` and
`cfm dnat on --priority -101` (one transaction). `edge_health` check H
(`web-dnat-order`, `docs/edge-health.md`) warns when a non-CFM DNAT of tcp/80
or tcp/443 runs at a priority no later than CFM's redirect
(`netfilterdiag.WebDNATAhead`, `internal/firewall/netfilterdiag/netfilterdiag.go:1091`)
and WebShield served 100+ requests in the last 15 min
(`edge_health_webshield.go:39-43`); a DNAT by anything else warns on the order
alone.

### What WebShield does per request

From `imunify360-webshield-bundle` 1.50.1 (`webshield.conf`,
`virtserver.conf`, `wscheck.conf`, `nginx/lua/{accesscheck,reqrouter}.lua`):

1. **Real client IP:** behind Cloudflare from `CF-Connecting-IP` /
   `True-Client-IP`; behind any other proxy in its geo map (bunnycdn, gcore,
   cloudfront, quic-cloud, fastly, ezoic, sucuri, ...) from `X-Forwarded-For`.
2. **Verdict:** one query per request to Imunify's IP-list daemon: `WHITE`,
   `WHITE_STATIC`, `REMOTE_PROXY`, `BLACK`, `BLACK_LOCAL`, `COUNTRY_BLACK`,
   `GRAY`, `SPLASH`, `NOT_FOUND`.
3. **Route:** `WHITE*` → backend; `BLACK*` / `COUNTRY_BLACK` → **403**; `GRAY`
   → captcha, except through Cloudflare with `cloudflare_captcha off` (earth):
   backend; `SPLASH` without a `wsuserid` cookie → antibot splash; else →
   backend with `X-Real-IP`.
4. **Feedback:** a solved captcha is reported to the agent; too many captcha
   requests blacklist the IP (`CAPTCHA_DOS_ALERT`).

In the ~4 h before the switch on earth, 14 690 of WebShield's 15 982
Cloudflare 403s came from 62 real IPs on Imunify's `blacklist` / `drop.sync`;
the rest were the origin's own 403s. Direct, QUIC.cloud and ShortPixel traffic
drew almost none. No country was blocked.

### What CFM loses with its redirect first

| WebShield function | With CFM first | Status |
|---|---|---|
| Imunify blacklist on the **real IP behind Cloudflare** | lost: nft sees only Cloudflare's address | W1 |
| Imunify blacklist, direct client | kept: Imunify's filter drops the source on every port | — |
| `GRAY` / `captcha.sync`, direct client | **hard drop**: Imunify accepts those sets only on WebShield's ports | W3 |
| `GRAY` via Cloudflare | no change (`cloudflare_captcha off` let them through too) | — |
| `SPLASH` antibot (`splashscreen.sync`) | lost: a splash-listed client reaches the edge unchallenged | W2 |
| Real IP behind other CDNs | n/a: the edge trusts Cloudflare only (`trusted_proxies.conf`), on purpose | W4 |
| reCAPTCHA, captcha-DoS blacklisting | covered: CFM's PoW challenge, the page rate-limit ban, `CHALLENGE_V2_PATHS_REJECT_BAN` | — |
| Country block | n/a: not configured; CFM's geo policy is challenge-tier only by doctrine | — |

### W1. IP lists for clients behind Cloudflare (built; LOCAL enforced, FEED log)

The gap was not only Imunify's: CFM's own fleet blacklist and local bans never
reached a client behind Cloudflare either (two scanners other nodes had
fleet-banned for WAF hits got 200/301/404 from the origin through Cloudflare on
earth). Built as `internal/proxyipfilter`: the lists in the daemon's memory,
asked by the bridge decision for proxied requests; `[webdetector]
PROXIED_IPFILTER_FEED` / `_LOCAL` = `log` | `enforce` | `off` (defaults: both
`enforce` since 2026-11-26).
Design, precedence and log format: `docs/proxied-ipfilter.md`.

Open:
- FEED `enforce`, once the fleet list's permanent bans on shared mobile /
  CGNAT addresses are gone (see Order);
- **promote on hit** (a client blocked from these lists also goes to the edge
  ban store, so the static locations and cached URLs are covered): not built;
- **Imunify's lists as a second source** (`i360.ipv4.blacklist`,
  `.blacklist.custom`, `.drop.sync`, ~1.5 k on earth): not built. Several of
  the 62 Imunify-blacklisted IPs above are on the fleet list too; add it only if
  the reads show the fleet list leaves a real remainder. (`internal/locate/imunify.go`
  already queries Imunify's local list for `cfm which` / locate, not for this
  filter.)

### W2. Imunify's splash list as a challenge source (open, measure first)

`splashscreen.sync` is the list Imunify wants an antibot check for. It could
feed a per-IP v1 challenge source, in shadow first. Worth it only if the set
is non-empty on the fleet: it was empty on earth.

### W3. Graylisted direct visitors (decided: no CFM code)

With CFM first, Imunify's own filter drops a graylisted client's new
connections to the edge ports (it accepts those sets only on WebShield's
ports). CFM cannot undo a DROP in another base chain. The options are
Imunify-side (a shorter graylist TTL) or accepting it, as the nodes that ran
CFM first all along have. It rarely bites (earth: 0 drops in 4 h, 37
graylisted IPs). Check H's fix text says so; track the `imunify360_log_gl`
drop counter on the fleet if it ever matters.

### W4. Never ban a CDN node as a client (open)

The edge trusts Cloudflare only. Another CDN's node (BunnyCDN, Gcore,
CloudFront, Fastly, ...) reaching the edge looks like one client carrying many
visitors, and a per-IP ban would take a site down for all of them. Imunify's
`remote_proxy_static` names those ranges. Measure them on the fleet
(`edge_access_tail` by client, `node="all"`), then either add an "address is a
proxy" list that per-IP autoblock never bans, or confirm CFM's existing guards
cover them. Case in point: a Cloudflare Workers egress address
(`2a06:98c0:3600::103`, AS132892) was on earth's `block_v6` and the fleet list
for WEB/MALPATH (2026-11-17); every Worker fetching through it shares that ban.

### Not proposed

Copying WebShield's reCAPTCHA (a Google dependency), its domain whitelist or
its country block: CFM has its own challenge, exclude and geo-policy
mechanisms, and none is a measured gap.

## Not gaps

- Anti-bot splash (10 894 passed / 481 failed on earth): CFM's challenge.
- DOS and captcha-DoS: CFM's connection limits and the challenge page's rate
  limit and ban.
- Exim auth failures (7 413): CFM's exim / dovecot detectors.

## Order

1. **Burn-in reads** (2026-11-20, 2026-11-24): rules 417, 415 by extension,
   530, and the proxied IP filter with its `cc=` / `asn=` fields. Done: 417 and
   415 block (bans held); `PROXIED_IPFILTER_LOCAL` defaults to `enforce` since
   2026-11-26 (scanners only on the local sets).
2. **Meta's forward proxies** (`fwdproxy-*.fbsv.net`, AS32934), the condition
   for LOCAL enforce: 59 of them were permanently banned on mars and titan by
   the SYN / port-flood detectors in May-June 2026, breaking link previews and
   in-app visits. Done: new bans are prevented (the L4 flood and port-scan
   autoblock spares a forward-confirmed good bot,
   `internal/firewall/autoblock_goodbot.go`, kill switch
   `THROTTLE_GOODBOT_EXEMPT = 0`), and on 2026-11-26 no node held an AS32934
   ban. `PROXIED_IPFILTER_FEED` enforces too since 2026-11-26 (a day of log on
   seven nodes: four Greek residential addresses, one a permanent ban). Next:
   clear the fleet list's permanent bans on shared mobile / CGNAT addresses.
3. **G1 public feeds:** loaded 2026-11-27 (DROP / DROPv6 BLOCK; blocklist.de
   and CINS CHALLENGE, `LIST_CHALLENGE = log`). Next: a week of
   `[list_challenge]` lines per list (`cc=`), then enforce; the mail half
   (PAM RBL locks) still needs its own measure.
4. **G4 collector** (`vulnerability_hits` → cfm-web).
5. **W4**, then W2.
6. G5 / G6 as planned (FS-009, the ClamAV comparison); G7 unmeasured.
