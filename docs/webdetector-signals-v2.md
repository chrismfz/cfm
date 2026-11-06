# Web detector signals v2: login outcomes, compromise, abuse, behaviour

Status: **design; phase 0 built** (2026-11-04): the `auth` column
(`log-cfm.lua`, column 14, login POSTs only), `LogRec.Auth`, and the corpus
behind the MCP `auth_corpus` tool (`auth_corpus.go`). Nothing counts logins
yet. Context: the vol2.gr takeover
attempt (titan, 2026-11-04). It got rule 440 and the rule 501 clearance cap
(PR #1638). It also showed that slow or distributed login attacks pass the
edge unseen. This document plans what the log-driven web detector
(`internal/webdetector`) should count beyond the 40x floods it counts today.

The first web detector counted status codes per IP over 120 s. That was the
right tool for scanners. It cannot see an attacker who sends one wrong
password to each of 150 sites per hour, or the one request that succeeds.

---

## 1. What the fleet shows (domlog hunt, 2026-11-04)

A read-only scan of the cPanel domlogs (the current logs plus the October and
November archives, about 5 weeks). Titan and qualityweb were still running
when this was written.

| node | failed `wp-login.php` POSTs | distinct IPs | top sprayer |
|---|---:|---:|---|
| orion | 628 322 | 104 203 | 155.2.215.83: 237 fails on 108 sites |
| speedhost | 525 301 | 63 819 | 161.33.128.237: 27 357 fails |
| mars | 387 863 | 76 110 | 185.198.240.26: 160 fails on 78 sites |
| virgo | 303 036 | 79 004 | 104.234.53.x on ~73 sites |
| rigel | 111 892 | 31 678 | |
| earth | 5 730 | | |

That is about 1.96 M failed logins on six nodes in five weeks. Almost none of
it trips rule 501, which needs 8 POSTs per IP in 20 s. The sprayers come in
/24 blocks: 155.2.215.x, 142.111.152.x, 185.198.240.x, 104.234.53.x. A
per-/24 grain catches what a per-IP one misses.

Other patterns from the same scan:

- **User enumeration** (`?author=N`, `/wp-json/wp/v2/users`): 62.60.130.x
  across 34–60 sites, a recon step before the spray.
- **Registration spam**: ygeiadermapharm (rigel), 4 108 register POSTs from
  179 IPs.
- **Lost-password bursts**: d-business.gr (mars), 30–36 per IP from
  Indonesian addresses; enateam.
- **Checkout volume**: more4u.gr 2 215 checkout POSTs from 1 409 IPs. This
  looks like real shop traffic. A card-testing signal needs a per-shop
  baseline, never a fixed number.

### 1.1 What turned out to be false, and why it matters for the design

Two findings looked like compromises and were not. The design below is
shaped by them.

1. **A `wp-login.php` POST answered `302` is NOT a success.** On glaveris.gr
   the 302 was followed by `GET /wp-login.php?login=failed`: hide-login and
   limit-login plugins redirect a failure. The "success from a dirty IP" lists
   (391 on orion, 421 on mars) are therefore unusable as they stand. The
   current ROADMAP entry said "a 302 is a success"; that is corrected there.
   **Status code alone cannot tell success from failure.** §2 adds what can.
2. **A PHP file under `/wp-content/uploads/` answered `200` is NOT a
   webshell.** Every one checked on disk was absent; WordPress's rewrite
   answered with a soft 404. That covers 20+ paths on 12 sites, among them
   gacbp.com `nx.php`, netalyx.com `b1ack.php`, the kavalahome.gr theme
   files and northnet.gr `code-execution.php`. The real `.php` files found
   (news1.gr, 142 `resizeme-N.php`, 2019) are JPEGs with a PHP name and no
   PHP code in them. **A compromise signal from the log needs a filesystem
   confirmation before anyone is told** (§4).

The only confirmed compromise in this period is needlestories.gr (92 fake
plugin directories). vol2.gr was an attempt, cut off by rule 440.

---

## 2. Login outcomes: the missing column

Before phase 0 the socket line had 14 columns (`log-cfm.lua` `_M.log`,
parsed by `parseTSVCols`, `engine.go`), with no `Location` and no
`Set-Cookie`. The edge's file log writes `uloc="$upstream_http_location"`;
the socket did not.

**One more column, `auth`, sent ONLY for a POST `auth_endpoint_tag`
classifies as a login.** The edge reports facts; the daemon decides the
outcome (`authOutcome`, `auth_corpus.go`). That way a per-CMS rule learned
from the corpus is a Go change, not an edge release. As built the field is

    <TAG>;li=<0|1>[;a=<action>][;x=1];l=<location path>;c=<cookie names>

- `TAG`: `auth_endpoint_tag` minus `AUTH_` (`WP_LOGIN`, `JOOMLA_ADMIN`,
  `DRUPAL_LOGIN`, `MAGENTO_ADMIN`, ...). xmlrpc is left out (rule 510).
- `li=1`: the LAST `wordpress_logged_in_*` cookie the response set has a
  real value. A logout's expired cookie carries a blank value. "Last" matters
  for 2FA: with the Two Factor or WP 2FA plugin, `wp_signon` sets the real
  cookie, the plugin clears it in the same answer and shows its
  second-factor form (200). The edge sends `li=2` for that (a real value set,
  then cleared), and the daemon reads it as `mfa`: the password was right. A
  cleared cookie with no real value before it stays `li=0`:
  `wp-login.php?reauth=1` clears it on every failed login, and reading that
  as 2FA hid every failure. The second-factor
  POST that sets the cookie for good is the `ok`. Only the edge sees cookie
  values, so this one bit is decided there (`ngx.header["Set-Cookie"]`).
  The value never leaves the edge.
- `l=`: the `Location` path, its scheme, host (protocol-relative and
  backslash forms too) and query dropped. It is the ORIGIN's Location
  (`$upstream_http_location`). On an HTTP/2 or HTTP/3 answer,
  `ngx.header["Location"]` is already empty in the log phase, and that is
  how most browsers log in (813 of 895 login redirects on orion). Until
  2026-11-05 those redirects read as having no Location. An http
  login sent to `https://` on the same host with a query DIFFERENT from the
  request's (a hide-login plugin on an https site: `?login=failed`) is the
  plugin's verdict, not `x=1`. A canonical redirect keeps the request's
  query. The queries are compared whole, so a client cannot hide its
  failures behind a query of its own. A 302 canonical rule that changes the
  query reads as a verdict: rare, since most keep `REQUEST_URI`. The scheme
  compared is `$cf_xfp`, the one the origin is told, not the listener's
  `$scheme`, which is http behind Cloudflare Flexible.
- `c=`: the names of up to 8 cookies the response set.
- `x=1`: the Location leaves the request's scheme or host (a canonical
  redirect: http to https, bare to www). Only the bit is sent, never the
  host.
- `a=`: the query's `action`, read as PHP reads it: the exact name,
  URL-decoded, the last occurrence (`ngx.req.get_uri_args`, not nginx's
  `$arg_action`, which is raw, first and case-insensitive). It comes before
  `c=`, so a field cut at the daemon's 640-byte cap loses cookie names, not
  the action.

The daemon's WordPress rule (the one verified so far):

- `?` whenever the origin did not answer: `cfm_upstream` is not
  `cfm_apache*` (CFM's challenge server, an edge block), or no upstream time
  was logged (the conf presets `cfm_apache`, and some edge exits keep it). Such an answer says
  nothing about the password.
- `ok`: `li=1`. This is checked first, whatever the action. PHP's
  `$_REQUEST` lets a body `action=login` override the query, so a query
  action must never hide a success.
- `mfa`: `li=2`, a 2FA plugin's password step. Counted nowhere. Until
  2026-11-06 it read as `fail`, so an admin's every 2FA login was one.
- `na`: one of wp-login.php's own other actions (lostpassword,
  retrievepassword, resetpass, rp, register, postpass, logout,
  checkemail, confirmaction, confirm_admin_email, entered_recovery_mode).
  Any other value, an unknown one included, is a login: wp-login.php runs
  its login case for it. A login hidden behind `?action=lostpassword` with
  `action=login` in the BODY still lands here (the edge does not read the
  body), and both answer 200 on a failure. Since 2026-11-06 `na` + 200 is
  therefore a `fail` (a lostpassword / register form shown again is a failed
  attempt too): the ban must not be dodged by adding `?action=lostpassword`.
  Only a non-200 answer to those actions stays `na`.
- `fail`: the form again (200), or a 302/303 to a path containing `login`
  (`wp-login.php`, a hide-login slug) on the same scheme and host. A
  canonical redirect is not a verdict, so it is `?`. A canonical redirect is
  a 301/308 to the login page (lelaki.gr, the first day's corpus), or any 3xx
  with `x=1` (Apache's `RewriteRule [R]` is a 302). The `?login=failed` query itself
  never reaches the daemon.
- `?`: anything else (a 2FA or CAPTCHA step elsewhere).

Per-CMS markers must be **measured, not guessed**: the CLAUDE.md rule for CVE
signatures applies here too. Joomla (`/administrator/`), OpenCart, Magento,
Drupal, Laravel `/admin/login` and generic `/login` are `?` until a fleet
read of the corpus decides each rule. A CMS whose success cookie cannot be
told from its anonymous session cookie (Laravel's `laravel_session` is set on
every answer) is decided by its Location alone, or stays `?`.

The column is sent **only on a login POST**: every other line keeps its 14
columns byte for byte. That is what keeps an older daemon right during an
upgrade. Its parser folds anything past column 13 into the bypass flag, so a
15th column on every line would have turned every bypass client into a
non-bypass one. The new parser reads 12–15 columns, and an old edge simply
feeds no login field. The tag is computed on the request's PATH, decoded
once (as Apache will route it), never on the query: on the raw URI,
`/wp-l%6Fgin.php` hid a login and `POST /contact/?redirect_to=/wp-login.php`
made a form post a WordPress login. A POST whose path holds neither `login`
nor `admin` is skipped before the tag is computed (every tag leg needs one
of them; the Lua test pins it), so a long query is never scanned.

### 2.1 What the fleet's edge logs say (2026-11-04)

These come from a read of the edge's full access logs (`log_format cfm`,
which carries `ust` and `uloc`) on all 8 nodes, about 5 days each. They are
the input to phase 1's rules. "Verified" means the follow-up requests of
the same client confirmed the outcome.

| login | failure | success | decided by |
|---|---|---|---|
| WordPress `wp-login.php` | 200, or 302 back to a login path | `wordpress_logged_in_*` set | the cookie (built) |
| cPanel webmail `/login/?login_only` | `ust=401` (verified) | 200 with no Location, then `/cpsess<N>/…` (verified, hundreds) | status; it is tagged `LOGIN_POST`, and must be split from a generic `/login` |
| Joomla `/administrator/index.php` | 303 → `/administrator/index.php`, then ONE 200 and nothing (inferred); brute force: 200, no follow-ups | the same 303, then admin XHRs (`com_ajax`, `com_joomlaupdate`, `com_cpanel`) (verified) | follow-ups only. Every admin save is a POST to the same URL, with `option=com_login` in the BODY |
| OpenCart `route=common/login` | 200 re-render (inferred) | 302 → `common/dashboard&user_token=` (verified) | Location; OpenCart 4's AJAX login answers 200 JSON both ways |
| Magento 2 `/<adm>/admin/index/index/key/<K>/` | the same 302, the follow-up GET answers 200 (the form) (inferred) | 302 → the same URL, whose GET then → 302 dashboard (verified) | follow-ups only |
| PrestaShop `/admin<x>/index.php?rand=` | no navigation (inferred) | GETs `controller=AdminDashboard&token=` (verified) | follow-ups; AJAX, 200 both ways. A logged-out admin's background XHR → 302 AdminLogin is NOT a login |
| WHMCS admin `dologin.php` | 302 → `login.php?…&incorrect=1` (verified) | 302 → `index.php` / `clients.php` (verified) | Location (the query, which the edge drops today) |
| WHMCS 8 client `/login` | 302 → `/login` (verified) | 302 → `/clientarea.php` (inferred) | Location |
| Laravel classic / Fortify `/login` | 302 back to `/login` (public) | 302 elsewhere, but `/two-factor-challenge` is a step, not a success | Location target |
| Laravel Livewire / Filament (ekdosi, invoicer, mycs) | more Livewire POSTs, no navigation (inferred) | navigation to `/admin/<tenant>`, `/dashboard` (verified) | follow-ups only; the login is `POST /livewire-<hash>/update`, 200 both ways, never tagged today |
| Drupal `/user/login`, phpMyAdmin | not seen (scanners only; standalone pma stopped by the challenge) | — | unmeasured |

What this means for phase 1:

- **Only an origin answer counts.** Many login POSTs never reach the origin:
  the edge challenges them (303/307 → `/__cfm_challenge`; 1 074 generic
  `/login` POSTs on speedhost). `authOutcome` already returns `?` unless
  `cfm_upstream` is `cfm_apache*`.
- **Location and cookies decide only a few CMSes** (WordPress, OpenCart,
  WHMCS, classic Laravel). The rest need a **follow-up check**: after a
  login POST from (ip, host), watch that client's next requests for a few
  minutes. Admin pages, dashboard XHRs or a session-only path mean a
  success. One more login page, or nothing, means a failure. Everything a
  follow-up check needs is in `LogRec`, so it is daemon-only work: a small
  per-(ip, host) pending map with a TTL. Brute force needs no follow-up
  check at all: its signature is the repeated POST with no navigation in
  between.
- **WHMCS's `incorrect=1` is in the Location QUERY**, which the edge drops.
  A short allow-list of outcome query keys (`incorrect`, `login`, `error`)
  can be carried as key names only, without their values, if WHMCS is in
  scope.
- **`LOGIN_POST` mixes cPanel webmail, WHMCS, Laravel, Django and
  WordPress's `/login` alias.** Phase 1 splits it by path before any rule.

The corpus (`auth_corpus.go`, MCP `auth_corpus`) groups login lines by
(tag, outcome, upstream, `li`, method, status, path, Location path, cookie
names).
The path keeps the query fields that name a front controller's action
(`option`, `task`, `route`, `controller`, `action`, `view`): every Joomla
admin POST is tagged, a save as well as the login, and only those tell
them apart. Hex and
digit runs are folded, so a Joomla md5 cookie name or a site id does not
make a shape per site. Each shape keeps a count, distinct IPs and hosts
(capped at 64) and up to 5 example hosts. The Location keeps two path
segments, a person's name after `/members/`, `/user/`, `/author/` (...)
folded to `<user>`. Every kept string is a copy, so no entry pins the 256 KB
socket line it came from, and the distinct-IP and -host counts keep only
hashes. It is bounded at 2 000 shapes. One /24 (or IPv6 /64) can hold at most
16 of them, because the path is the client's to choose; a network past its
share has its new shapes refused (`dropped`, `dropped_by_tag`). A full corpus
evicts its least-used shape (lowest count, then oldest), releasing its
network's slot (`evicted`), so neither junk nor an old busy week freezes it.
It lives in memory, and emptied by a restart or config reload. Reading it per CMS is
the input to phase 1's outcome rules.

---

## 3. Login signals (all keyed on `auth`)

**Built (shadow), 2026-11-04: L1, L2 and L4 for WordPress**
(`login_ledger.go`, rows `login_spray`, `login_spray_net`,
`login_dirty_success`, kill switch `[webdetector] LOGIN_SIGNALS`). The
thresholds below are the starting ones. The units, as built:

- A **client** is an IPv4 address or an IPv6 /64, since one host holds a
  whole /64. Counted per address, one IPv6 machine spread its tries out of
  sight.
- A **network** is an IPv4 /24 or an IPv6 /48. A /48 sprayer with one try
  per /64 wrote no row at /64 grain.
- A **site** is a registrable domain (public suffix aware). An owner's typos
  on `example.gr`, `www.` and `staging.` are one site, not a spray.
- **Not counted:** a client on the bypass list or flagged `rec.Bypass` (a
  crawler, QUIC.cloud). Through a CDN that address is every visitor of the
  sites behind it. A proxy CFM does not know (Sucuri, a tenant's own) still
  reads as one client; the fleet read has to look for it.
- **Windows:** a fixed 24 h window and a sliding one-hour estimate per
  client and per network. A line older than the current hour counts into it
  (the edge's batches arrive out of order), and a line stamped more than 5
  minutes ahead of the daemon's clock is counted at the daemon's time.
- **Bounds:**
  - 100 000 clients and 20 000 networks. Eviction drops idle-for-a-day
    entries first, then unflagged ones, and flagged ones last, so a flood of
    new addresses cannot erase the sprayer whose later success L4 must catch.
  - 8 sites per client and 16 clients per network.
- **Rows:**
  - A spray row is written once per key per 6 h.
  - A dirty success is written once per (client, site) per hour, and at most
    4 per client per hour.
  - Each row type has a budget of 30 a minute (bursts of 60). The rest are
    counted into the next row's `suppressed`, because a row is a synchronous
    insert on the ingest path into a history store whose row cap
    (`HISTORY_MAX_ROWS`) every other detector shares.
- **Single site:** `single_site` marks an L1 row from one site (the
  20-an-hour and 50-a-day shapes). An owner's app with a stale password
  looks the same, so phase 2 must not ban those blindly.
- **CGNAT:** mobile-carrier /24s may trip L2's pool rule on a busy node, and
  then every login from them reads `flagged_by=net`. Check this in the read.

Spray rows carry counts, never a site name, so a scoped caller reading its
own host's rows sees no other tenant. L3 (vhost
under attack), L5 and L6 are not built. They need a per-vhost baseline, the
learned admin origins, and the follow-up-request check (§2.1). The other
CMSes join when the corpus gives them an outcome rule.

**L1 enforcement (built 2026-11-06):** the `login_bruteforce` detector
(`docs/DETECTORS.md`) bans from the ledger's failures with its own, stricter
rules: ≥ 5 `fail` on one site in 1 h, or `fail` on ≥ 5 sites in 1 h, a 3 day
ban sent to cfm-web, GR/CY 10 minutes and not sent. The shadow rows below keep
their own thresholds and keep being written.

Every signal ships **shadow** first: a history row plus the MCP, with no
action. Proposed action tiers follow the user's open "ban through the
Sinker or an edge deny" question; that decision is made per signal after
the shadow read.

| id | grain | fires when (starting thresholds, tuned on the shadow read) | proposed action |
|---|---|---|---|
| L1 spray | IP, all vhosts, 1 h / 24 h | ≥ 10 `fail` on ≥ 3 vhosts in 24 h, or ≥ 20 in 1 h, or ≥ 50 in 24 h (built) | ban through the detector sink (leniency, edgeban for proxied clients, notify) |
| L2 block spray | /24 (v4), /48 (v6) | ≥ 5 IPs of the block flagged by L1 in 24 h, or ≥ 30 `fail` from ≥ 5 of its IPs in 24 h (built) | ban the IPs seen; a subnet ban only after its own review |
| L3 vhost under attack | vhost | `fail`/h ≥ 10× its 7-day median, and ≥ 50 | alert, then a tighter per-IP limit on that vhost (≥ 3 `fail` in 1 h → L1 action) for the attack's TTL |
| L4 dirty success | (vhost, IP) | `ok` from an IP flagged by L1/L2 in the last 24 h, or after ≥ 10 own `fail` on that site in 24 h (built). Not when the client failed there and already succeeded there at least as often (an owner's tool, most of the first fleet day's rows); successes alone excuse nothing (a stuffing hit before the flag). A site is the registrable domain, so tenants under one shared domain share the record. A reset request excuses nothing (anyone can send one before a spray). Known residual for phase 2: successes are per client and site, not per account, so on a site with open registration a client can bank logins on its own account and hide a later admin success. The FIRST success on a site always counts | **alert, high priority** (never an automatic ban: it can be the owner after typos) |
| L5 new admin origin | vhost | `ok` from a country + ASN never seen succeed on that vhost in 30 days | info alert, shadow-only until its FP rate is known |
| L6 risky follow-up | (vhost, IP) | within 30 min of an L4 or L5 login: a plugin/theme upload (`update.php?action=upload-plugin`, `plugin-install.php`), `plugin-editor.php`/`theme-editor.php` POST, `user-new.php` POST | **alert, critical**: the needlestories / vol2.gr chain |

Notes:

- L1/L2 keep a per-IP **fail ledger** with a TTL (24 h). L4 reads it. It is
  per node; §6 makes it fleet-wide.
- The 120 s `bucketSW` window does not fit hour-long counts. Use a separate,
  bounded LRU of per-IP / per-/24 / per-vhost counters with 5-minute slots.
  Each map gets a size cap and a counter for what the cap evicted.
- Recon feeds L1: an IP in the user-enumeration ledger (§5) counts as having
  one extra vhost.
- xmlrpc `system.multicall` is already rule 510 at the edge, and stays there.

---

## 4. Compromise indicators (need filesystem confirmation)

The log can raise a candidate; only the disk can confirm it. The daemon runs
as root on the node, so it can `stat` the file under the vhost's document
root (resolved like `/etc/userdomains` → `/var/cpanel/userdata`; DirectAdmin
and Plesk have their own maps). It runs async and rate-limited, with a
per-path result cache.

| id | candidate from the log | confirmed when | action |
|---|---|---|---|
| C1 executed PHP in uploads | GET/POST `/wp-content/uploads/**.php` answered 200/302 | the file exists AND its first 64 KB holds a PHP open tag | alert (critical), the file path in the alert |
| C2 rare plugin/theme PHP | a POST 200 to a `/wp-content/{plugins,themes}/**.php` path that ≤ 3 IPs ever requested on that vhost | the file exists and is not part of a known plugin (no `readme.txt` / plugin header in its directory, or a directory created in the last 7 days) | alert |
| C3 fake plugin directory | periodic scan (daily) of `wp-content/plugins/` | a directory matching the needlestories / vol2 shape: `wp-<random>` or `word-word-word-<4hex>`, a single PHP file, no `readme.txt`, recent mtime | alert; a list for the operator |

C1's two rules (the file exists, and it holds a PHP open tag) both come from
§1.1. C3 may fit better in the existing malware-scan path than in the web
detector; it is listed here because the web detector can point it at the
vhost and path to look at.

---

## 5. Recon and abuse (per vhost, shadow-first)

| id | signal | why |
|---|---|---|
| R1 user enumeration | IP requesting `?author=N` / `/wp-json/wp/v2/users` / `rest_route=/wp/v2/users` on ≥ 3 vhosts in 1 h | the step before a spray; feeds L1 |
| A1 registration spam | register POSTs per vhost per hour vs its baseline; distinct IPs | ygeiadermapharm: 4 108 from 179 IPs |
| A2 password-reset abuse | lostpassword POSTs per (vhost, IP) | mail-bomb / enumeration (d-business.gr) |
| A3 card testing | checkout POSTs per vhost vs baseline, with many distinct IPs, low asset ratio | needs a per-shop baseline. Without an outcome column it is a volume signal only, and stays an alert |

---

## 6. Fleet correlation (cfm-web)

The sprayers hit every node (the vol2.gr three tried 150+ sites on each).
Each node sees only its share. Proposal: nodes report the L1/L2 ledger
entries (IP, fail count, vhost count; no usernames, no paths beyond the tag)
to cfm-web. cfm-web sums them across nodes, and an IP over a fleet threshold
goes on the shared blacklist with a TTL. This uses the existing `report()`
merge: it never shortens a longer ban, and the whitelist always wins. Design
it in cfm-web's own doc when the node side has shadow data.

---

## 7. Behavioural features (shadow anomaly score)

The current signals are rules. Some clients fit no rule: a slow crawler that
fetches no assets, an AI scraper on rotating IPs, a headless browser that
passes the challenge. A per-IP feature vector over a 10-minute window, scored
by an unsupervised model, would rank them for review. It enforces nothing.

Features (all available in `LogRec` today):

- request count; distinct vhosts; distinct paths and path entropy;
- asset ratio (css/js/img/font among requests); share of HTML vs API paths;
- status mix (2xx/3xx/4xx/5xx shares); method mix (POST share);
- inter-arrival coefficient of variation (a bot's metronome; one sprayer hit
  a site every ~40 min for days);
- UA count per IP; UA claims a browser but fetches no assets;
- referer-empty share; share of requests between 01:00 and 06:00 local.

Model: **HBOS** (histogram-based outlier score). Each node keeps a streaming
histogram per feature and scores a window as the sum of `-log(density)`. It
is O(features) per score, has no training pass, and explains itself (the
features with the lowest density are the reason). Isolation Forest scores
better on correlated features but needs batch training and a model file. It
is a later option if HBOS's top-N proves useful.

Output: a `behaviour_score` history row for the top N per hour, and an MCP
listing with the per-feature contributions. Per the master plan's D3a
discipline: no action, and no retirement of any existing signal, on the
score's word until a fleet read shows what it catches.

AI crawlers specifically: per-vhost request share by declared AI crawler
family (GPTBot, ClaudeBot, PerplexityBot, Bytespider, meta-externalagent,
Amazonbot), and the share whose PTR does not verify. That gives operators "who
is eating this site" without new enforcement. Blocking or rate-limiting them
is a per-vhost traffic rule the owner chooses.

---

## 8. Phases

0. **Column + corpus.** The `auth` column (§2) in `log-cfm.lua` and the
   parser, the per-CMS corpus line, and a version-skew test. Nothing counts
   yet.
1. **Shadow counters.** L1–L6, R1, A1–A3 as history rows and MCP, with no
   action. The behaviour score (§7) runs in shadow beside them.
2. **Fleet read** (one to two weeks): thresholds from real distributions,
   per-CMS outcome rules from the corpus, an L4 FP list.
3. **Alerts on.** L4, L6 and C1–C3 alerts. L3 alerts.
4. **Actions**, each its own reviewed change: the L1/L2 ban through the
   sink (the user's Sinker-or-deny choice), the L3 per-vhost tightening,
   then §6.

Out of scope: a login challenge gate (customer friction, declined), and
reading request bodies (usernames, passwords) — the detector counts outcomes,
never credentials.
