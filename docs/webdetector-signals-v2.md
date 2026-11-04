# Web detector signals v2: login outcomes, compromise, abuse, behaviour

Status: **design, nothing built** (2026-11-04). Context: the vol2.gr takeover
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

Today the socket line has 14 columns (`log-cfm.lua` `_M.log`, parsed by
`parseTSVCols`, `engine.go`). It has no `Location` and no `Set-Cookie`.
The edge's file log already writes `uloc="$upstream_http_location"`; the
socket does not.

**Add one column, `auth`, computed at the edge in the log phase, ONLY for a
request `auth_endpoint_tag` classifies as a login.** That is a cheap test,
and every other request carries `-`. Its value is
`<tag>:<outcome>`, for example `WP:ok`, `WP:fail`, `JOOMLA:?`.

- `ok`: the response sets the CMS's logged-in cookie. For WordPress that is
  `wordpress_logged_in_*`, which WordPress sets only on a completed login,
  after a 2FA step too. This is the only reliable success marker. The edge
  reads it with `ngx.resp.get_headers()["set-cookie"]` in the log phase,
  name prefix only, never the value.
- `fail`: a POST that set no logged-in cookie and either answered 200 (the
  form shown again) or redirected to the login page (`Location` containing
  `wp-login.php` / `login=failed`).
- `?`: anything else (a 2FA interstitial, a CAPTCHA plugin's own page). It
  is counted as neither.

Per-CMS markers must be **measured, not guessed**: the CLAUDE.md rule for CVE
signatures applies here too. WordPress is the one verified. For Joomla
(`/administrator/`), OpenCart, Magento, Drupal, Laravel `/admin/login` and
generic `/login`, phase 0 ships the column with outcome `?` plus a corpus
line: tag, status, Location path, and the names of the cookies set. A fleet
read of that corpus then decides each CMS's `ok`/`fail` rule. A CMS whose
success cookie cannot be told from its anonymous session cookie stays `?`, and
only its failure-shaped answers count.

Version skew: the Go parser already accepts 12–14 columns, so it must accept
15 too, and an old edge with no `auth` column simply feeds no login signal.

---

## 3. Login signals (all keyed on `auth`)

Every signal ships **shadow** first: a history row plus the MCP, with no
action. Proposed action tiers follow the user's open "ban through the
Sinker or an edge deny" question; that decision is made per signal after
the shadow read.

| id | grain | fires when (starting thresholds, tuned on the shadow read) | proposed action |
|---|---|---|---|
| L1 spray | IP, all vhosts, 1 h / 24 h | ≥ 20 `fail` on ≥ 3 vhosts in 1 h, or ≥ 50 in 24 h | ban through the detector sink (leniency, edgeban for proxied clients, notify) |
| L2 block spray | /24 (v4), /48 (v6) | ≥ 5 IPs of the block in L1's ledger, or ≥ 100 `fail` from the block in 1 h | ban the IPs seen; a subnet ban only after its own review |
| L3 vhost under attack | vhost | `fail`/h ≥ 10× its 7-day median, and ≥ 50 | alert, then a tighter per-IP limit on that vhost (≥ 3 `fail` in 1 h → L1 action) for the attack's TTL |
| L4 dirty success | (vhost, IP) | `ok` from an IP in the L1/L2 ledger, or ≥ 10 own `fail` before it | **alert, high priority** (never an automatic ban: it can be the owner after typos) |
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
