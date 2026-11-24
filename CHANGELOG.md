# Changelog

All notable changes to CFM are recorded here.

**Versioning is date-based: the version *is* the release date** (`YYYY.MM.DD`,
from `date +%Y.%m.%d` in the Makefile). Each released `.deb`/`.rpm` produced by
`make release` carries that day's date, so every dated heading below
corresponds to a real package that was built and `make sync`'d out.

Format loosely follows [Keep a Changelog](https://keepachangelog.com/):
group entries under **Added / Changed / Fixed / Security / Removed**. Work in
progress accumulates under **[Unreleased]**; on release day it moves under a
new `## YYYY.MM.DD` heading (see CLAUDE.md → "Releasing & CHANGELOG").

This file keeps releases from **2026.10.01** on. Older entries were removed
on 2026-11-18 to keep the file readable: every release from 2026.08.22 has
its notes on its GitHub release (tag `vYYYY.MM.DD-HHMMSS`), and the full text
of every earlier entry is in the git history of this file. The first ~1000 PRs
(Mar–Jun 2026) were never back-filled here.

## [Unreleased]

### Added
- **One API call for everything that applies to a vhost.**
  `GET /api/v1/webdet/vhost-profile?host=` (admin) returns one host's
  settings and what decided each: challenge (manual or automatic, tier and
  its source, lockdown, under attack), WAF on/off and the excludes that cover
  the host (`example.com`'s exclude also covers `www.example.com`), HTTP/3,
  ClamAV, the Site Cache policy that decides it (its own or a covering
  `*.example.com`) with the node switches, and every traffic rule whose scope
  takes it, with its state (enabled, disabled, expired). It also lists the
  other known hosts of the same domain. Each part comes from the code the
  edge and the existing pages already use, so it cannot disagree with them.
  It backs the coming per-vhost page in cfm-admin.
- **Web Traffic: rank the clients by any column.** Click Requests, Rate,
  Traffic, Origin time or IPs: the node picks the top clients by that column
  (the traffic mix API's new `sort=origin|requests|bytes|ips`, also on the MCP
  `traffic_mix` tool), so "by requests" shows the busiest clients, not the
  costliest ones reordered. The choice is remembered per browser.
- **Traffic mix: a window that ends in the past.** `until=<unix>` (a 5-minute
  boundary within the last 24 h; also on the MCP `traffic_mix` tool) ends the
  window there instead of now, so a finished hour (`window=1h&until=<10:00>`)
  reads exactly 09:00-09:59 every time. cfm-web's hourly traffic history uses
  it.
- **Web Traffic: browser-UA scrapers spread over many addresses are
  labelled.** A "likely human" client (one exact browser UA) whose last hour
  came from 50+ addresses, under 3 requests each, with under 10% static /
  XHR / POST is marked **distributed** (IPs, requests per IP, static share)
  and offered "Challenge its IPs" / Deny / Throttle on those addresses (up to
  500; never on the UA, which real visitors send too). On titan on
  2026-11-24 three such Mac Chrome 131/133/136 populations (~460 IPs each,
  0-8% static, 3-5 s of origin per page) were a quarter of the origin time
  and read as humans. A label only: nothing acts on it. Every browser-UA row
  now shows its IP count and its static/XHR share (API: `evidence_share`,
  `distributed`); a visitor population's addresses are never listed.
- **The Web Traffic page keeps its 24 h across a restart.** The traffic mix
  is saved every 5 minutes and on shutdown (with the TTL bans) to
  `/var/lib/cfm/traffic_mix.json.gz` (root-only: the last hour's client IPs
  are inside) and restored at start, so an upgrade or a `systemctl reload
  cfm` no longer empties it. A crash loses at most 5 minutes; a file from
  another version or a corrupt one starts the page empty, as before.

## 2026.11.24

### Security
- **Google's user-triggered fetchers no longer skip the WAF and the
  challenge.** These are the `google-proxy-*.google.com` IPs behind Read
  Aloud, Translate and link previews. They fetch whatever URL a user hands
  Google, so anyone can aim them at a site. They were exempt twice over:
  - **The bypass list.** It took all five of Google's IP feeds (`google-all`),
    including the three user-triggered ones. It now takes the common crawlers
    (Googlebot) and the special-case crawlers (AdsBot) only, 1620 fewer
    prefixes.
  - **The good-bot check.** A `google-proxy-*` PTR verified as the good bot
    "google". Under `google.com` only Google's special-case crawlers
    (`rate-limited-proxy-*`) verify now, everywhere that check is read
    (challenge exemption, v2 waiver, bans, uniqIP, shadow, L4 autoblock).
  - **The challenge-exclude file.** It shipped `ptr=*.google.com;
    verify_fcrdns=1` and `asn=as15169; ua=*google-read-aloud*`, and the
    proxies pass the user's own UA through. The reference file is narrowed to
    `ptr=rate-limited-proxy-*.google.com`, and the Read-Aloud rule is gone. A
    node whose `/etc/cfm/webdetector_challenge_exclude.txt` was edited keeps
    its copy (the new default lands as `.dpkg-dist` / `.rpmnew`). CFM refuses,
    in code, any `ua=` / `asn=` / `ptr=` rule match for a `google-proxy-*`
    client once its PTR is cached, so the old lines grant nothing past an IP's
    first request or two. Remove them by hand. A Challenge Access-Control
    entry is not covered: an operator's `asn_in: [15169]` entry (the
    product-feed recipe) still lets them reach the paths it names.

  Why: from 2026-11-21, ~440 of them walked `www.mathematica.gr`'s phpBB
  forum on orion. They sent ~2M requests (671k on the 11-24 morning) with no
  static asset, and at the 08–09 peak took about 40 % of orion's origin time.
  Elsewhere on the fleet the same proxies sent 0–31 requests per node that
  day.

  Cost: on a vhost that is challenging, Read Aloud and Translate now see the
  challenge, and a v2 arm rejects them. The Merchant Center feed fetcher
  (`google-xrawler`, no PTR) stays exempt by its UA rule. The bypass list changes with the
  package (`make release` regenerates it from the same, narrower sources).

### Added
- **Visitors who solved a challenge are micro-cached.** A vhost under a
  challenge (ours, or automatic under heavy traffic) used to send every page
  of every visitor who had solved it to the origin: the edge's own
  `cfm_clearance` cookie, refreshed on each request, made the response
  unstorable. On a micro-armed vhost they are now served from the
  micro-cache like any anonymous visitor, and each gets only their own
  clearance cookie back, on a cache HIT too (measured on nginx with three
  visitors; the stored copy never holds one). The WAF still runs first, and
  every micro rail applies (session cookies, admin paths, …). Needs the edge
  conf of this release (`$cfm_edge_sc`); with an older one nothing changes.
- **Bypass-list crawlers are micro-cached.** Googlebot, Bingbot, Applebot,
  DuckDuckBot, Skroutz and the other crawlers of the bypass list used to go
  straight to the origin on every request, so a crawl storm reached PHP and
  MySQL in full even on a micro-armed vhost. On a micro-armed vhost they are
  now served from the micro-cache, in their own keyspace: a page stored for
  a crawler is never served to a visitor (an SEO prerender, or a hacked
  site's spam shown to Googlebot only), nor a visitor's page to a crawler.
  Every micro rail still applies (cookies, method, admin paths, uncacheable
  pages); a purge drops both. A CDN of the list (QUIC.cloud) is not cached
  and now logs `mwhy="cdn"`. Crawlers off the list (Meta, Amazon, the AI
  crawlers) were already micro-cached like visitors on an armed vhost.
- **Traffic rules: an expiry and a total throttle, for incidents.** A rule can
  carry `match.until` (RFC3339): past it the rule matches nothing, and it is
  deleted a day later; cfm-admin's editor offers 1 h / 6 h / 24 h / 7 d. The
  new `throttle_total` action gives ALL matching clients one budget
  (`rate_rps`, per vhost or for the whole node) instead of a per-client limit,
  which a crawler spread over hundreds of IPs walks past (on titan a per-IP
  limit cut 0–4% of Meta's load, a 5 r/s node total cut 65%). `ip_any` now
  takes up to 500 entries (a scraper's top IPs). **Downgrade:** an older cfm
  never enforces a rule with an expiry or a total throttle (it lists it
  unsupported and keeps it), and an older edge applies the per-client
  `soft_bot` throttle for a total one; this build also freezes a stored rule
  whose action carries a key it does not know.
- **cfm-admin: Web Traffic page** (`/cfm-admin/webdetector/traffic/`, in the
  nav in place of Web Bots, whose UA console stays reachable from it). Built
  on the traffic mix: the bots' share of the origin time, requests vs origin
  time vs traffic by class, a 5-minute chart, the clients to act on (rate,
  traffic, origin share, IPs) and the bots-vs-humans split per vhost. Actions:
  challenge a client's top IPs (a per-IP challenge, never the whole vhost and
  never a ban; an IPv6 client's /64 cannot be challenged per IP and is left
  out, said so), and **Deny… / Throttle… for a while**: an expiring traffic
  rule (15 m to 7 d) keyed on a UA family or on the client's top IPs (up to
  500, /64s included), on every vhost or a chosen list, as a 403, a total
  budget (the page suggests a quarter of the client's current rate and shows
  the share it would cut) or a per-client limit. A browser UA is never a UA
  target (every real Chrome of that version sends the same string); likely
  humans are offered nothing. The emergency rules run before the operator's
  own rules (priority 1–9) and are listed under "Active emergency rules" with
  +1 h and End now. Also: lift a manual vhost challenge, undo a `cfm bots`
  UA rule.
- **`POST /api/v1/challenge/ip/add` and `/remove`** (admin-only): the
  operator's per-IP challenge on a list of up to 500 IPs (TTL 5 m to 24 h,
  default 1 h), and lifting it (the page's Undo). It also revokes the IP's
  clearance for the challenge's length, so a client that had already solved
  (a solving farm) is challenged too; a person there re-solves once. A live,
  longer challenge is never shortened and keeps its own reason (a shorter
  one is extended, and an undo leaves it alone); IGNORE_IPS and blocked IPs are
  skipped with the reason. With `CHALLENGE_UNSOLVED_HOLD = enforce`, an IP that
  keeps loading the challenge without solving stays challenged.
- **Traffic mix: who the web traffic is and what it costs the origin, for
  24 h** (`GET /api/v1/webdet/traffic-mix`, MCP `traffic_mix`, admin-only).
  Every request lands in one of four classes: known crawlers (by UA), other
  bots and tools, browser-UA automation (an IP making 20+ dynamic requests a
  minute with no static file, POST or XHR in 10 minutes) and likely humans.
  Each class reports requests, origin seconds, bytes, status mix, edge-served
  requests, and average and peak r/s, with a 5-minute series, the top vhosts
  by origin time and the top clients (the raw UA for browser-looking ones)
  with their top IPs over the last hour. On titan on 2026-11-24 this is the
  table that showed Meta and a Chrome/152 scraper at a third of the requests
  but ~61% of the origin time. `?host=` (with `merge_www` for the www. twin)
  narrows it to one vhost, without a status mix or clients. Beyond the last
  hour each 5-minute bucket keeps its top 256 vhosts and 64 clients per class,
  the rest summed under `_other`. The classes are labels, never an enforcement
  decision; the counters survive a config reload, not a restart.

### Changed
- **WAF rules 307 (XXE) and 416 (a PHP file as the request body) now ban.**
  Both block since 2026-11-17 with their `waf_security` ban held for a
  burn-in. On 8 nodes from 2026-11-19 to 11-24 (5.5 days), 307 had 220 hits
  from 91 IPs and 416 had 74 from 66. Every hit came from a datacenter
  scanner or webshell uploader. None came from GR/CY, none hit a panel port,
  and none was a false positive. A hit now gives the usual soft 6 h ban
  (15 min for GR/CY under leniency). `RULE_307 = 0` / `RULE_416 = 0` in
  `[waf_security]` hold one again. Both rules move back to their earlier
  place in the WAF: in the late group, rule 303 (still held) could take the
  hit, and with it the ban. Rule 303 stays held: its sweep sends one request
  per Google Cloud IP, so a ban would add thousands of addresses that never
  return.
- **WooCommerce add-to-cart from a declared crawler now gets a 301, and
  meta-externalagent has a node-wide cap.** On 2026-11-24 Meta's AI /
  indexing crawler (meta-externalagent) sent titan ~530 pages a minute for
  three hours at ~1.5 s of PHP each, ~27 000 of them `?add-to-cart=` cart
  writes; titan and orion hit 100% CPU. Three changes:
  - Rule 530's `CRAWLER` tag (a declared crawler UA) is answered with a 301
    to the same URL without `add-to-cart`, so the shop writes no cart. Not
    behind Cloudflare (a CDN could cache the 301 for shoppers), and only
    when nothing stronger matched. `NO_REFERER` / `XSITE` stay logonly.
    `wc_cart_crawl_redirect = false` in `cfm_waf_config.lua` turns it off.
  - The edge gives meta-externalagent one budget for the whole node: 2
    pages/s (burst 10) and 6 connections, then 429. The per-vhost Meta
    budgets never bound it, since it spreads over every shop. Link previews
    (facebookexternalhit), ads (meta-externalads), the in-app browsers and
    its images are not affected.
  - meta-webindexer (Meta AI's search indexer) gets the same node budget
    under its own key, and the per-vhost Meta budgets. It was in no budget
    at all and was Meta's second largest origin cost on 2026-11-24: about 2
    origin requests at a time on titan and on orion, mostly at night, ~8
    across seven nodes, against ~21 for meta-externalagent and under 4 for
    link previews, ads and the catalog together.
  See `docs/waf.md`, "Rule 530".

### Changed
- **WAF rules 415 and 417 block (bans held).** Rule 417 (PHP source in the
  whole POST body, past rule 404's 2 KB) and rule 415 (PHP in an uploaded
  file, past rule 402's head) move from logonly to block after a 7-day
  read on 8 nodes. 417 had 5 hits, every one an attacker: a Joomla tool
  writing `system($_GET…)` into each template's `error.php` through the
  template editor (twice, on one site), and an eval spray. 415 had 1, a
  `.png` carrying `<?php` posted to a WordPress form-upload endpoint. No
  false positives. Neither bans: their autoblock is held per rule
  (`RULE_415 = 0`, `RULE_417 = 0`), because a real plugin file saved
  through an editor, or a real file quoting PHP, still scores, and that
  must be a 403 rather than a 6 h ban. 415 now runs late with the other
  held rules, so a request an armed rule also catches keeps that rule's ban.
  417 now stands down, like the other body-PHP rules, on the code-editor and
  installer endpoints (Code Snippets, String Locator, the plugin / theme
  installer). On a site without pretty permalinks
  (`/index.php?rest_route=/code-snippets/...`) they are not exempt, since any
  other app's index.php could be reached that way: such a site needs a
  rule-scoped exclude. Webmail is not exempt: an email over 2 KB quoting PHP gets a
  403 there. See `docs/waf.md`, "Rule 415" and "Rule 417".
### Added
- **`rate_outlier` shadow lines show what an outlier costs the origin.**
  Each line now also carries:
  - `static=`: the IP's static-asset requests in the window;
  - `host_static=`: the vhost's own static share. It is near 0 behind a CDN
    or with the assets on another host, where every visitor reads
    `static=0`;
  - `origin=`: its origin time over the window, as average concurrent
    origin requests (every upstream try summed);
  - `origin_busy=`: the same for the whole node, as the pressure context.
    Both read `-` on a log that reports no upstream (unmeasured, not 0);
  - `tier=cost`: set when the IP fetched no static asset and `origin=` is
    at least `ABUSE_SHADOW_RATE_COST` (default 0.5 of the window, i.e. 60 s
    in the default 2 min). The tier is checked every tick, so an IP that
    first crossed the rate bar cheap still logs its `tier=cost` line.

  The `abuse_shadow` MCP tool counts these lines (`would_challenge_cost`)
  and ranks them (`top_cost_tier`). Nothing is enforced. This is the
  week-long measurement before deciding on a per-IP challenge.

  Why: on the 2026-11-24 morning a scraper drove titan and orion past load
  100. A plain outlier is mostly browsers (275 of titan's 469 that day). The
  cost-tier outliers were 30–50 % of the origin time in those hours, about
  none at normal hours, and only 5 IPs among them fleet-wide carried human
  solve evidence.
- **A per-IP challenge that is loaded again and again but never solved can
  now be held instead of running out** (`[webdetector]
  CHALLENGE_UNSOLVED_HOLD`, default `log`). On titan a facet scraper on Greek
  residential IPs was challenged per IP, reached the origin with 0 pages while
  the challenge lived, loaded the challenge page ~80 times a minute without
  solving, then waited out the 20-minute TTL and, under the 45-minute
  `CHALLENGE_COOLDOWN`, went back to full rate for over an hour. With
  `enforce`, 20 unsolved page loads in 10 minutes hold the challenge for an
  hour, renewed while they continue (at most 24 h). It only extends a live
  per-IP challenge (never starts one, never over a block, no vhost-wide
  effect), and a solve on the address ends it. `log` writes
  `[challenge] unsolved_hold verdict=would_hold` lines to the challenge log for
  a burn-in; review by 2026-12-08 (`docs/abuse-defense-master-plan.md` §5).

### Fixed
- **`make rpm` after `make deb` failed on an unpackaged file**
  (`/usr/share/cfm/etc-cfm-files.list`). The .deb's `/etc/cfm` seed list
  (2026.11.23) was written into the staging tree both packages share, and the
  rpm copies that tree's `/usr` as a whole. The rpm staging now drops it, as
  it already drops the .deb's license copy; `check_deb_config_seed.sh` pins
  it.
- **`cfm bots block meta-externalagent` / `meta-webindexer` now match Meta's
  current crawler UA.** Since Meta moved to `Mozilla/5.0 (Windows …) …
  Chrome/145 … (compatible; meta-externalagent/1.1 (+https://…))`, the UA
  normalizer (Go `NormalizeUA` and its edge twin `cfm_ua_emergency.lua`)
  looked only at the first `(...)` group and keyed the crawler as `mozilla`,
  so the rule never hit (titan, 2026-11-24: 0 hits a minute). Every group is
  scanned now (a group ends at its matching `)`, an unclosed one runs to the
  end), and `indexer`, `googleother` and `google-inspectiontool` join the bot
  markers (none of those names matched one). Browser UAs still read
  `mozilla`. **Review your active rules before upgrading (`cfm bots list`):**
  Googlebot smartphone now keys as `googlebot` and Bingbot mobile as
  `bingbot`, so an existing `googlebot` / `bingbot` rule starts covering the
  mobile crawler too. `google-inspectiontool` (Search Console) joins the
  Google crawlers that need `--confirm`. The two normalizers are now
  ASCII-only on both sides (they keyed a UA with NBSP or non-ASCII letters
  differently) and run one shared fixture. The edge's UA trim is linear
  now: while any `cfm bots` rule was active, one request with a long run of
  spaces inside its User-Agent cost ~200 ms of worker CPU (8 KB header).
- **A Debian/Ubuntu upgrade no longer stops to ask about `/etc/cfm` files.**
  Every `/etc/cfm` file was a dpkg conffile, and CFM edits several of them
  itself (`cfm allow` / `cfm block`, the WebUI's notify and detectors editors,
  `cfm edge ipv6`, `cfm kernsec`). So on every release that changed one,
  `apt upgrade` stopped at "Configuration file '/etc/cfm/cfm.conf' … (Y/I/N/O/D/Z)":
  `-y` cannot answer that, a broadcast multi-host session hung on every Debian
  node, and unattended-upgrades skipped cfm altogether, so those nodes quietly
  stayed on the old version. The .deb now does what the rpm's
  `%config(noreplace)` always did: an edited file is kept and the new default is
  written beside it as `<name>.dpkg-dist` (the `.rpmnew`), a file nobody changed
  is updated, and nothing is asked. The first upgrade to this version already
  runs without a question; your files are not touched. As on the rpm, a
  listed `/etc/cfm` file you deleted is installed again from the default.

## 2026.11.23

### Fixed
- **agent config sync: spamd no longer skips the files we push.** Every
  synced file was written with mode 0600, whatever it had before. spamd reads
  its config without root, so on 2026-11-22 `myip.cf` and
  `mailfromfilters.cf` were rewritten 0600 on every cPanel node and spamd
  dropped them ("cannot open … Permission denied"): no `*_MYIP` RBL tests, no
  Mail From Filters, and no `dns_server` line (Spamhaus answered the public
  resolver with `*_BLOCKED_OPENDNS`). A rewrite now keeps the file's mode and
  owner, a SpamAssassin file is always made group/other readable (so one an
  older agent left at 0600 is repaired by the next sync), and a new file under
  `/etc/mail/spamassassin/` gets 0644 (0600 elsewhere). The temp file is
  unique and gets its mode before the rename, so a failed chmod fails the
  update instead of leaving an unreadable file (a failed chown is logged and
  the file is written as the agent's, as before). A rollback restores the old
  content but keeps a SpamAssassin file readable, every directory level
  created under the SpamAssassin dir is 0755, and temp files a killed write
  left behind are removed by the next write.
- **sslcollector: edge workers no longer grow with every certificate
  reload.** The certificates and keys a worker had replaced were freed only
  when LuaJIT's garbage collector next ran a full cycle, which it rarely did,
  because it does not see the OpenSSL memory behind them; on titan (3513
  names) workers reached 410-530 MB. Each fetch or snapshot load that changes
  the store now runs a full collect once the payload is released (~50 ms for
  3000 pairs, in the background timer, never on a handshake), and logs a
  `[sslcollector] gc src=… gc_ms= lua_kb= rss_mb=` line: the collect's time,
  the Lua heap and the worker's RSS.

### Fixed
- **`cfm webtop` no longer takes a flag for a host.** `cfm webtop challenge
  add --help` armed manual challenges for `--help` and `www.--help`, and
  `challenge remove -- --help` removed a host named `--`. Every subcommand
  that takes a host now prints its usage for `-h`, `--help` or `help` and
  refuses a host that starts with `-`, before calling the API. The commands
  that create state (`challenge add/tier/lockdown`, `attack on`,
  `site-cache set`, `exclude add`) also refuse a value that is not a hostname
  (letters, digits, dots, hyphens, an optional leading `*.`; exclude values
  keep their `*`/`?`/`[…]` globs). The commands that read or clear an existing
  record (`challenge remove/status/host`, `attack off`,
  `site-cache get/off/remove/purge/stats`, `exclude remove`) refuse only a
  flag, so they can still clear one keyed on an odd host: `cfm webtop
  challenge remove www.--help` cleans up after the bug. `cfm webtop challenge
  --help` and `cfm webtop attack --help` print the usage instead of calling
  the API.
- **Every `cfm` command prints its usage for `-h`, `--help` or `help` and does
  nothing else.** Several never read their arguments, or ran when the flag
  parser stopped at a positional `help`:
  - `cfm reset --help` emptied table `inet cfm`, `cfm disable --help` deleted
    it, and `cfm flush --help` freed every TTL ban and discarded the saved
    ones. These three now take no argument at all: any other argument is
    refused before nft is touched.
  - `cfm kernsec init|apply|disable|rollback help` and `cfm lsm
    init|enable|disable|restart help` ran the command with its defaults
    (`cfm lsm init --help` ran the whole bring-up). `cfm realip fix --help`
    rewrote the origin's config. `cfm daemon help` started a second daemon.
  - `cfm clam enable|disable|hook …|scan on|off --help` rewrote `cfm.conf`.
  - API writes with the help word as the target or ignored: `cfm bots block
    --help` (an emergency UA rule for `--help`), `webtop history prune
    --help` and `mysqltop history prune --help` (30 days pruned), `mysqltop
    user-kill --id=N help` (killed the connection), `webtop waf clear`,
    `http3 enable|disable`, `rules remove`, `challenge-access remove`, `tokens
    revoke`, `clam sigignore add help`.
  - A help word after the target: `cfm unblock|unallow <IP> --help` and
    `cfm allow <IP> help` acted on the IP, and `cfm dnat [cpanel] bypass
    add|remove <IP> --help` edited the bypass list. They now print usage, and
    refuse any argument after the target.
  - `cfm auth session purge help` and `cfm auth log purge help` purged:
    every `cfm auth` leaf is now flags-only.
  - Harmless but wrong: `cfm test --help` ran the checks, `cfm debug help`
    wrote a one-minute bundle, `cfm htpasswd help` asked for a password,
    `cfm list|status|allow-list|php-inventory help` and the webtop/bots/
    health/mysqltop views ran, and `cfm ssl --help`, `webtop waf|rules
    --help` said "unknown subcommand".
  The help-word check is one shared package (`internal/clihelp`); a test per
  command package runs every subcommand with each help word against a
  backend and an API server that fail on any call.

### Changed
- **The SSL Collector sends each key without the chain its file may carry.**
  Panels write key files as bundles (cPanel's combined key+leaf+chain,
  DirectAdmin's `.combined`, Virtualmin's `ssl.combined`), and the whole file
  went out as `key_pem`: every chain twice in `/dumpall`, in `/cert` and in the
  on-disk snapshot, decoded again by every edge worker. Only the key blocks go
  now (the chain is in `cert_pem`; nothing read it from `key_pem`); a file with
  no key block is sent as it is. Discovery is unchanged. Measured on the
  fleet's snapshots, 2026-11-23: 4181 of virgo's 4193 key files were bundles;
  `dump.json` 56 to ~32 MB on virgo, 101 to ~58 MB on earth. Offline check on
  virgo's real snapshot: every key byte-identical and every pair still loads.

### Fixed
- **`cfm dnat cpanel on/off` (`cfm edge panel …`) no longer restarts the edge
  when its reload fails.** The listener reload fell back to `systemctl
  restart` (and `service … restart`). A reload fails when the edge refuses
  the config, so the restart stopped the live edge and failed the same
  config test on start: every site down while the web DNAT still pointed at
  it. Even a working restart refuses new connections while the old edge
  drains. virgo, 2026-11-23: a failed reload under `panel off` restarted
  `cfm-edge` and outlived the caller's 60 s timeout. A failed reload now
  leaves the running edge as it is and is reported as the error.

## 2026.11.22

### Fixed
- **An upgrade restarts the cfm daemon once, not twice.** The rpm's `%post`
  stops and starts it, and `%systemd_postun_with_restart` asked for a second
  restart: on EL9/EL10 at the end of the transaction, after every
  `%posttrans`, where it landed in the middle of cfm-edge's post-upgrade
  restart (rigel, 2026-11-23: the starting daemon put the panel DNAT back while
  the edge was being taken out of the path). On an upgrade the OLD package's
  `%postun` runs, so the change takes effect from the upgrade after next.
- **`cfm edge panel off` reports a redirect it could not remove.** The nft
  engine dropped the delete's error and the panel-off path dropped it again,
  so the command returned 0 with the panel DNAT still in place. Now the error
  reaches the exit code (an absent table is still "already off"), and the off
  stops there: it no longer removes the panel allowlist under a live redirect
  (that would drop the panel traffic it still sends to the edge) or persists
  OFF. When the panel failsafe's own off fails, it now records FAILED health
  and an ON transition (`failsafe-off-failed`) instead of AUTO_FAILSAFE and an
  OFF transition, which reported the panel auto-disabled while its DNAT was
  still on.

_Nothing yet._

### Fixed
- **The firewall's base rules: two cases where the input chain could be left
  open while EnsureBase reported success.**
  - **A missing plain block drop was never put back.** The "is this base rule
    already there?" check matched a rule inside a longer one, so a missing
    `ip saddr @block_v4 drop` (or any plain allow/block rule) read present
    inside its `ct state established,related …` twin. That twin drops only
    connections already open: new connections from banned addresses reached
    the ports policy's accepts, and EnsureBase never re-added the rule. A
    rule inside another base rule no longer counts (both engines). A missing
    early rule now goes back right after the nearest early rule above it
    that the chain holds (in the early part of the chain, never a late
    copy), not at the top: there, a re-added drop would sit
    above the allow accepts and drop an allowlisted address that is also in
    a block set.
  - **An unreadable chain whose existence was unknown read as success.** When
    neither `nft list chains inet` nor the input chain's rules could be read
    (two timeouts in a row), the exec engine declared the chain blind and
    reported success: on a cold boot or after `cfm reset` that chain could be
    new and empty, with policy accept and no allow/block rule, and no repair
    acts on a chain whose table exists. EnsureBase now fails there, so the
    daemon's start fails and systemd starts it again. nftlib took the same
    case for a new chain and added every rule blind (duplicates); it now
    fails the same way. A repair that knows the table was absent (the tick
    loop's, or `cfm reset` on nftlib) takes the chain for the new one it is
    and writes the rules. A chain that was listed and cannot be read is
    still left as it is (best effort), as before.
- **On EL8 nodes, the ports policy (TCP_IN/UDP_IN/TCP_OUT/UDP_OUT, on every
  start and config reload) no longer times out reading the firewall.** Its
  two reads of `inet cfm input` / `output` ran under nft's 10 s default,
  which also covers the wait for one of the four nft slots, and EL8's nft
  1.0.4 takes 4–12 s for any `list chain` (earth, mars, virgo, idle,
  2026-11-22). A timed-out apply changed nothing, so the extra
  `ct state established,related accept` copies EnsureBase now leaves to the
  ports policy stayed in place. Both reads and the policy's one `nft -f`
  transaction now get 30 s, on both engines; the output chain is not read at
  all when `nft list chains inet` (3–10 ms) shows it does not exist (a node
  without TCP_OUT/UDP_OUT). A failed read is still an error: nothing is
  planned from an unread chain.
- **On a node running the nftlib engine, EnsureBase now deletes every extra
  copy of each base rule in the `inet cfm input` chain, as the nft engine's
  does (below).** An old exec-engine bug re-added the whole base
  layer whenever its read of the chain failed (141–268 copies of each rule on
  earth, mars and virgo, 2026-11-22); nftlib removed only the loopback accept,
  the flood jump and the ICMP jumps, so a node switched to `nftlib` before its
  first restart on the fixed nft engine kept every other copy, and its flood
  meters counted each packet once per leftover `jump flood`. The extras go in
  the same `nft -f` transaction as the missing rules, the top-most copy of
  each kept, and the ports policy's own established/related accept is left
  alone. Both engines now write and deduplicate ONE list of base rules.
  nftlib's read of the input chain now gets the nft engine's 30 s (it had
  10 s, and EL8's `list chain` takes 4–12 s: a timed-out read leaves the
  chain, duplicates included, as it is), and on both engines the run that
  deletes the duplicates starts from 30 s, not 10 s, plus 1 s per 1000.
- **On EL8 nodes running the nft engine, the flood-counter dump that runs on
  every 20 s tick no longer holds an nft slot for seconds.** It read the
  counters with `nft list counters table inet cfm`, which on EL8's nft 1.0.4
  loads every set element of the table first: 2.8–18.5 s per run, idle
  (earth, mars, virgo, orion, 2026-11-22). Every other nft run waited behind
  it, and the wait counted against its own deadline. The counters now come
  from one netlink object dump, filtered by the kernel to the table's counters
  (0.3–1.2 ms on the same nodes, the same counters and values). The CLI
  listing is kept only as a fallback when netlink fails, at most once every
  5 minutes (the netlink error is logged when it changes and hourly). A
  failed read, or an empty answer, still repairs the table only when the cheap
  `list chains inet` probe says it is absent. The `[flood]` log lines are
  unchanged, except that they are now sorted by counter name.
- **On nodes running the nftlib engine, a failed table lookup no longer
  rebuilds the firewall base.** The flood-counter dump (every tick) ran
  EnsureBase on any error looking up the `inet cfm` table, and the flood-rules
  apply did the same: a netlink failure, ENOBUFS or a read deadline on an
  already slow kernel started a full repair. Both now repair only when the
  kernel answers that the table does not exist (ENOENT), as the nft engine
  does; any other error is logged and retried next tick. The portscan loop's
  table probe uses the same test. After an out-of-band wipe (`nft flush
  ruleset`, a panel firewall reload) the dump no longer keeps logging
  "cannot list counters" against a stale cached table handle: it drops the
  cache, so the next tick asks the kernel. The counter dump's failure also no
  longer skips that tick's throttle autoblock pass on this engine (the
  counters are log-only, the throttle bans are not).
- **A failed flood-counter read no longer skips that tick's throttle
  autoblock pass.** The dump returned before evaluating the throttle sets
  (`th_syn_v4`, …) whenever the log-only counters could not be read, so a
  slow or failing `nft list counters` also stopped throttle bans.
- **A cfm restart no longer leaves the edge without its bridge and ingest
  sockets for ~30 s; the nft engine no longer re-runs EnsureBase every minute
  or two, and no longer piles copies of its base rules into the input chain.**
  On EL8 (nft 1.0.4) with the fleet's large ban and feed sets, many nft
  listings load every set element first (measured idle: `list tables` 3.3–12.3
  s, `list chain inet cfm <chain>` 4–12 s, even for a chain that does not
  exist; EL9/EL10's nft answers in ms). EnsureBase ran several, plus one nft
  run per self-set statement: 28.9 s on virgo's 2026.11.22 upgrade, during
  which every bridge lookup failed open and the access-log lines meant for the
  webdetector were lost (66 `[crit] connect() … No such file` lines in the edge
  error log). Its `list tables` probe also ran past its 5 s deadline, read as
  "no table" and re-ran EnsureBase (20–30 s each) from the 20 s tick all day on
  earth, mars and virgo. Each re-run whose read of the input chain failed added
  every base rule again: mars's input chain held ~268 copies of each (7,546
  rules every packet walks), earth's and virgo's 141.
  - Table and chain existence, and the input chain's priority, now come from
    one `nft list chains inet` (3–10 ms on every node); a probe that times out
    or fails is "unknown", and only a definite absence starts a repair
    (portscan load, flood rules, counters dump). `cfm reset` / `cfm disable`
    try their flush / delete on an unknown instead of reporting success.
  - An input chain whose rules cannot be read gets no rules added (logged);
    the next EnsureBase removes every extra copy of each base rule in one
    transaction, keeping the top-most one, so the first restart after this
    upgrade brings those chains back to one copy of each rule (7,531 deletes
    on mars, 0.67 s in nft's check mode). **Expect flood limits to look
    looser on those nodes afterwards:** each copy of `jump flood` (and of the
    ICMP jumps) ran the flood chain again, so its per-IP meters counted every
    packet ~141–268 times. They now act at their configured values; retune
    nothing that was set against the old effective strictness without
    looking at it first.
  - The self sets are compared with the kernel's and left alone when
    unchanged (every restart); a change is one transaction, and if nft refuses
    it each set is retried alone, then with loopback and link-local only.
  - EnsureBase on a restart: on EL8 about the one input-chain read left (~4 s
    on mars, idle), was ~30 s; ~0.6 s on nft 1.0.9 in a netns with a 200k-entry
    feed set, was 10 s. nft engine only; nftlib already wrote the self sets
    over netlink.

### Changed
- **CFM's cfm-edge config no longer sets the `pid` path; the cfm-edge package
  owns it.** Nothing changes on a node today: the package's built-in default
  is the same `/run/cfm-edge.pid` its unit watches. It lets a later cfm-edge
  release move the pid file into its own runtime directory (so its sandbox no
  longer needs all of `/run` writable) without a CFM release in lockstep: a
  `pid` line here that disagreed with the unit's `PIDFile=` would get the
  edge killed at start. The render and its CI check now fail on a `pid`
  directive.

### Fixed
- **`install-edge.sh`, `install-openresty.sh` and `install-angie.sh` started
  with `sh` no longer fail half-way.**
  - **What happened:** they are bash scripts. Run as `sh install-edge.sh`, a
    shell that is not plain bash (bash 4.4 in POSIX mode on EL8, dash on
    Debian) ran the first steps, then stopped on a line only bash parses
    (EL8: `syntax error near unexpected token '<'`, then `command not found`).
    The script had stopped part-way through.
  - **Now:** each one re-runs itself under bash, outside POSIX mode, before
    its first step (it drops `POSIXLY_CORRECT` / `SHELLOPTS` for that). Read
    from stdin or `sh -c`, there is no file to re-run, so it stops at once
    with "This script needs bash".
  - `bash scripts/install-edge.sh` is still the documented way to run them.

## 2026.11.21

### Added
- **Three logonly WAF rules for the PHP advisories of 2026-11-19.** They
  measure, for a burn-in, the request shapes three of those php-src
  advisories describe: 10031 (CVE-2026-129289) a FastCGI request or
  FastCGI parameter inside a POST body, the PHP-FPM request smuggling
  payload; 10032 (CVE-2026-129496) an Authorization header past nginx's
  default 8 KB line, which this edge's 64 KB header buffers let through;
  10033 (the first leg of CVE-2026-129289, and the class of PHP multipart
  parser desyncs) a multipart body that leaves bytes PHP never reads. They
  log only (`cfm.waf.log`, reason `WAF_CVE:CVE_2026_…`), block nothing and
  feed no ban; the fleet read decides any promotion. Of the other advisories
  triaged, the session upload-progress one is already blocked by 10024 and
  the rest have no request shape a proxy can see. Not a substitute for the
  PHP update. Details: `WAF_CVE.md`.
- **A host-scoped PATH exclude for the malpath checks.**
  `cfm webtop challenge exclude add /images/.tmb/ --type path --scope example.gr`
  stops the malpath challenge (`CHALLENGE_PATHS`) and the `MALPATH` ban from
  counting that path on that site (and its `www.` alias) only; the same path
  elsewhere, every other path on the site, and a traversal or encoded path
  under the prefix (`/images/.tmb/../../.env`) still count. Before, the
  command was accepted and stored but matched nothing, so the only remedy for
  one site's tool tripping the list was deleting the entry for every site.
  `--scope` is required (an old unscoped entry stays inert), the first path
  segment must be a literal name (`/`, `/*`, `/*.php` are refused), and
  match-all scope globs are refused. A cPanel tenant's scoped token may
  manage these on its own vhosts, from the API or the cfm-admin excludes
  card: admins and tenants both get `path` on the challenge card, with a
  required scope field (a tenant's is prefilled with its first site in
  alphabetical order, and checked against its own sites) and a Scope column
  where an inert entry says so. WAF path excludes stay admin-only.
  `tokens/me` now lists a token's vhosts sorted.
  A skipped hit is logged once a minute per exclude
  (`action=path_exclude_skip`). Details: `docs/DETECTORS.md`.

### Fixed
- **The malpath list no longer challenges elFinder's thumbnails.** `/.tmb/`
  is the folder elFinder (Joomla JCE / K2, WP File Manager) keeps its
  thumbnails in: an admin browsing the file manager was challenged on the
  first one and had the clearance cookie revoked, so the file manager's
  next AJAX calls got the challenge page and it stopped working. The entry
  becomes `/worksec.php`, which keeps the one campaign it caught
  (`/.tmb/worksec.php`, ~110 a day over the fleet) in any folder.

### Changed
- **Site Cache micro buckets: 5 s to 300 s.** The 1 s and 2 s buckets are
  gone and a 300 s one is new, so the micro TTLs are now 5, 10, 30, 60,
  90, 120 and 300 s: one zone fewer, and a five-minute choice for pages
  that rarely change. No fleet vhost used 1 s or 2 s. A policy that still
  stores one runs as 5 s (the page shows "runs as 5 s"), as does an empty
  TTL. The burst-shield recipe is 5 s. An edge conf from before this
  release keeps working with the new Lua: a 300 s TTL runs as 120 s there
  until the conf is updated. The retired `cfm_micro_1s` / `cfm_micro_2s`
  cache dirs are left in place, unused. `cfm webtop site-cache help` and
  the MCP `site_cache_status` description list the new buckets.
- **`cfm edge` names the IPv6 next step.** When the host can do IPv6 but
  the running edge listens on IPv4 only, the summary's "needs a look" says
  what to run: `cfm edge ipv6 on`, or `cfm edge realip fix` first when the
  origin does not trust the edge (`127.0.0.1` and `::1`). The listen script's own hints
  (status, prestart, deploy, prepare) say `cfm edge ipv6 on [engine]`
  instead of `sh …/cfm-edge-listen-v6.sh render`, and the origin real-IP OK
  line no longer ends in an empty "header " on OpenLiteSpeed / LiteSpeed.

### Added
- **The edge's access log says why a request was not micro-cached.** A new
  last field, `mwhy="…"`, carries Site Cache Tier B's request-side reason
  for a micro-armed vhost (`auth:<cookie name>` for a session cookie,
  `method`, `path`, `uncacheable`, …; a cookie's name, never its value;
  `clearance` for a visitor whose challenge-clearance cookie takes the fast
  path, which never micro-caches; `waf`, `self-ip`), and
  `-` for everything else. Before, "why was my page not cached?" needed the
  trusted-source debug header, which cannot see a visitor's own cookies.
  An old conf with the new Lua simply has no field (no error); the panel
  listeners log `-` without warnings.

## 2026.11.20

_Nothing yet._

### Changed
- **`cfm edge` names the IPv6 next step.** When the host can do IPv6 but
  the running edge listens on IPv4 only, the summary's "needs a look" says
  what to run: `cfm edge ipv6 on`, or `cfm edge realip fix` first when the
  origin does not trust the edge (`127.0.0.1` and `::1`). The listen script's own hints
  (status, prestart, deploy, prepare) say `cfm edge ipv6 on [engine]`
  instead of `sh …/cfm-edge-listen-v6.sh render`, and the origin real-IP OK
  line no longer ends in an empty "header " on OpenLiteSpeed / LiteSpeed.

### Added
- **`cfm realip fix` writes OpenLiteSpeed's trust on DirectAdmin.** It
  appends `127.0.0.1T, ::1T` to the server-level allow list (and sets
  `useIpInProxyHeader 2` where it is not 1-4), writes each edited file both
  live and as its copy in `custombuild/custom/openlitespeed/conf/`, so
  `da build rewrite_confs` keeps it (the DirectAdmin way; no rebuild is run),
  and reloads OpenLiteSpeed gracefully: through its systemd unit
  (`systemctl reload openlitespeed`, DirectAdmin's own path, so systemd
  follows the new master), `lswsctrl restart` only without one. The edge
  installers run `cfm realip fix`, so on such a node they now reload
  OpenLiteSpeed too, as they reload Apache. OpenLiteSpeed has no config test:
  unless a new master comes up (the old one still running means the config
  was not taken), the files are restored and it is restarted again. A trust
  only in a live file (the rewrite_confs warning) is kept by writing its
  custom copy, with no restart; a fix a rebuild would undo, or a file changed
  since the plan, is refused.
  Several lists or values, or a custom copy that differs from the live file,
  stay a manual step. LiteSpeed Enterprise and a plain OpenLiteSpeed are
  unchanged (manual).
- **`cfm edge`: one command for the edge proxy.** A bare `cfm edge` shows
  the edge at a glance: the engine that runs (a warning when more than one
  does), web DNAT (priority, ports, bypass count, last health probe), panel
  DNAT, the running engine's IPv6 listen decision and the origin real-IP
  verdict, and what needs a look (DNAT on with no edge running, DNAT off with
  its intent on). The subcommands are the existing ones under one name:
  `cfm edge on|off|bypass` (= `cfm dnat …`), `cfm edge web` (the full
  `cfm dnat` report), `cfm edge panel …` (= `cfm dnat cpanel …`),
  `cfm edge realip …` (= `cfm realip …`), `cfm edge ipv6` (the IPv6 listen
  status of every engine). `cfm dnat` and `cfm realip` keep working
  unchanged. Docs: `docs/cli.md`.
- **`cfm edge check`: the edge's health checks on the CLI**, the same report
  as the MCP `edge_health` tool (engine version traps, origin 421 and
  premature-close storms, origin keepalive, a CDN caching the challenge,
  origin real IP, web DNAT order): every check with its severity and, for a
  non-ok one, the next step. `--json` prints the daemon's report as it came,
  `--window N` sets the access lines to scan. It exits 0 only when the overall
  verdict and every check are ok; a daemon that does not answer, a report it cannot read or an
  unknown verdict exit 1. Docs: `docs/edge-health.md`, `docs/cli.md`.
- **`cfm edge ipv6 on [engine]` / `cfm edge ipv6 off`: the IPv6 listen
  without the hand edit and the script path.** `off` sets
  `EDGE_LISTEN_V6 = off` in `/etc/cfm/cfm.conf` (the kill switch, node-wide)
  and runs the listen script's `render` for every engine, which removes the
  IPv6 listen files and reloads the edge. `on` removes a kill switch if there
  is one, then renders (only the named engine, if one is given): it never
  writes `EDGE_LISTEN_V6 = on`, which would let every edge start turn IPv6 on
  unconfirmed. It then prints the decision ("Now:"): exit 0 means the render
  ran, not that IPv6 came on. cfm.conf is rewritten in place (mode, owner and
  a symlink kept, comments and every other line untouched), read the way the
  script reads it (one reader, pinned to the script by the shared fixture),
  and the script gets that same file, never an exported `CFM_*` variable. A
  named engine the script does not find on the host is refused, nothing
  changed. The running daemon applies the edited cfm.conf, as after any edit.

### Fixed
- **`cfm realip` reads OpenLiteSpeed.** It read only LiteSpeed Enterprise's
  `httpd_config.xml`, so on an OpenLiteSpeed origin (DirectAdmin CustomBuild
  `webserver=openlitespeed`) it reported the trust missing whatever the
  config said, `cfm realip fix` printed the Enterprise WebAdmin steps, and the
  edge's IPv6 listen stayed off. It now reads `httpd_config.conf` and the files
  it includes (server level only), and names the files to edit
  (`/etc/openlitespeed/httpd-defaults.conf`, `httpd-accesscontrol.conf` on
  DirectAdmin). On DirectAdmin it gives the DirectAdmin way (a copy in
  `custombuild/custom/openlitespeed/conf/`, then `da build rewrite_confs`),
  and warns (in `cfm realip`, `cfm health` and edge_health) when the trust
  would not survive the next `rewrite_confs`, naming the live files that
  differ from what CustomBuild would install. CFM still does not edit the OpenLiteSpeed config.
- **`cfm dnat cpanel --priority -99 on` turned panel DNAT on at its default
  priority**: a flag before the subcommand was taken by the web DNAT flags.
  The panel and bypass commands now get their arguments untouched, and a word
  left after the flags (`cfm dnat --priority -99 on`, which printed the
  report and changed nothing) is refused with "flags go after the
  subcommand" (a word after `on` / `off`, `cfm dnat on extra`, is refused
  as an unexpected argument). The deprecated `--challenge <value>` is still
  accepted and ignored.
- **A bare `cfm dnat cpanel on` (or `cfm edge panel on`) went back to auto
  / -101**, whatever panel DNAT had been turned on with before, and
  overwrote the saved priority the daemon restores on restart: an `off` then
  `on` silently switched a fallback / -99 node to -101. `on` now saves the
  mode next to the priority and a bare `on` re-uses both; an explicit
  `--mode` takes its own default priority, `--priority` always wins.
  `cfm dnat cpanel status` and `cfm edge` show the mode it was turned on with.
  An unknown `--mode` (a typo such as `fallbak`, which went on at -101) is
  refused with nothing changed. With nothing saved, a bare `on` takes the
  daemon's default (`NFT_PANEL_DNAT_PRIORITY` when set) instead of saving
  -101 over it; a saved file that does not parse makes it refuse.

### Changed
- **The operator hints name `cfm edge realip` and `cfm edge ipv6`.** The
  messages, usage texts, `cfm.conf` and the docs say
  `cfm edge realip fix` / `cfm edge ipv6 on|off` (the runbook in
  docs/edge-ipv6.md is those two commands). After `EDGE_LISTEN_V6 = off` the
  listen script now says to remove that line (or `cfm edge ipv6 on`) instead
  of writing `= on`, which would let every edge start turn IPv6 on
  unconfirmed. `cfm realip` stays (scripts and installers call it; the
  installers' hints keep it, since they can run against an older cfm
  without `cfm edge`).
- **The hints say `cfm edge`.** The edge health checks (`cfm edge check`, the
  MCP `edge_health`, `whats_wrong`), `cfm realip` and `cfm health` now name
  `cfm edge realip fix`, `cfm edge on --priority …` and `cfm edge ipv6 on`
  (instead of the IPv6 listen script's path) as the next step, and
  `install-edge.sh` prints the switch and the rollback with `cfm edge` where
  the cfm has it (a bare `cfm edge panel on` re-uses the mode and priority
  panel DNAT had, so nothing needs noting beforehand), and the old
  `cfm dnat` steps on an older cfm (run from a checkout). `cfm dnat` and
  `cfm realip` work as before, and their own help is unchanged.

### Changed
- **The edge may listen on IPv6 by default.** It stayed IPv4-only unless
  `EDGE_LISTEN_V6 = on` until the per-IP defences grouped an IPv6 client by
  its /64 (now done: bans, the detectors', admin API's, web detector's and
  edge's counters). With no `EDGE_LISTEN_V6` in `cfm.conf`, a
  `cfm-edge-listen-v6.sh render` (by hand, or the edge installers' re-run)
  turns on `[::]:9080` / `[::]:9043` wherever the host can (a global IPv6
  address, free ports, the origin on IPv6) and the origin trusts the edge's
  IPv6 hop from `::1`, reloading the edge and confirming the listen;
  otherwise it stays on IPv4 as before. An edge start (a reboot, a restart,
  the edge's own package upgrade) and a cfm package upgrade never turn it on
  by themselves: they keep what a render approved. `install-edge.sh` now runs
  the new `prepare cfm-edge` (render's decision for cfm-edge alone, never a
  reload, and no new files while cfm-edge runs: that is `render cfm-edge`'s
  job), so a freshly prepared cfm-edge starts with IPv6 where the host is
  ready; the script also takes an engine name after the action. `cfm realip` (and its
  whats_wrong / edge_health finding) now asks for the `::1` trust on every
  IPv6-capable host, and exits 1 until it is there: run `cfm realip fix`
  (Apache / nginx; LiteSpeed needs `::1T` by hand) where it says so, then
  render. `EDGE_LISTEN_V6 = off` keeps a node on IPv4 and silences that
  finding. An existing `/etc/cfm/cfm.conf` keeps its old comment ("Off by
  default … `# EDGE_LISTEN_V6 = on`"): the default is now on, `off` the kill
  switch. `docs/edge-ipv6.md`.

### Security
- **The edge counts an IPv6 client by its /64.** The traffic-rule throttle
  (429), the login burst (rule 501, and its one resumed login a window), the
  `wp-login.php` HEAD probe and the XML-RPC POST burst (rule 512) counted the
  full address, so a client rotating inside its /64 never reached them. They
  now count the /64, except where it holds this node's own address or an
  `IGNORE_IPS` / `IGNORE_NETS` entry (counted per address, as the daemon
  does). A force unblock of any address of the /64 frees its throttle. The
  clearance cookie, the daemon's decisions and every allow or exact check
  stay per address. `docs/edge-ipv6.md` "IPv6 /64 grouping".
- **The web detector and the challenge server count an IPv6 client by its
  /64.** A client rotating its address inside its /64 stayed under every
  per-IP threshold: the 404 / 403 / WAF-403 / bot / malpath floods, the 40x
  combo, the request score, and the challenge rules (unique paths / hosts,
  `CHALLENGE_PATHS`, the rate and ratio thresholds, malformed requests, UA
  churn). They now add up the /64's addresses (per address where a ban would
  not take the /64), named by its busiest address. A ban takes the /64 as
  before. A challenge, which the edge applies per address, judges every
  address of the client seen in the window (its 16 busiest) on the client's
  counts, each through its own exemptions and gates (an excluded address
  shields no neighbour), one alert per client and rule notifying. The
  malformed and UA-churn challenges now read
  the request context (host, UA) their excludes match on: it was empty
  unless an earlier challenge rule was enabled. The vhost unique-IP count counts clients, so one rotating
  client no longer arms a vhost's automatic challenge. The challenge
  server's rate limits and abuse count hold the /64 too. `docs/edge-ipv6.md`
  "IPv6 /64 grouping".
- **The detectors and the admin API count an IPv6 client by its /64.** A
  client rotating its address inside the /64 any VPS or ISP line hands it got
  a fresh count per address, so it never reached a threshold. The login and
  service detectors (ssh, ftp, dovecot, mysql, cPanel, Proxmox, ngm, custom),
  the mail ones (exim, postfix: auth failures, rules, RBL hits, relays),
  ModSecurity, waf_security, the API-probe ladder (`cfm_endpoints`), the
  challenge cookie-discard detector, login_bruteforce, the admin API's login
  autoblock, login and password-change throttle, embed bootstrap limit and
  probe signals, and the MCP consent limit now count the /64, as an IPv4
  address behind NAT already is. Only where a ban would take the /64: a /64
  that holds this node, its gateway, an ignored, allowed or trusted proxy
  address (whose ban takes the address alone) still counts per address, so
  one address's alert never uses up its neighbours' or names an ignored one.
  The alert names the /64's address busiest now (plus
  `client=<the /64>`), never a neighbour whose one hit came last: that
  address is what the fleet report and the leniency checks get. The ban takes
  the /64 as before, allow lists stay exact, and an allowed address (narrower
  than a /64) in waf_security, cfm_endpoints, cookie discard or
  login_bruteforce keeps its /64 counted and banned per address by every
  section. The section cooldown
  follows what the ban took. The detectors' other /64 helpers (the login
  ledger, the CDN-cache finding, mail abuse) now use the shared key, which
  leaves Teredo and NAT64 per address. The kernel nft meters (flood, SYN,
  new-connection, ICMP, port flood, connlimit) stay per address: their
  packets' source can be spoofed. Webdetector scoring and the challenge
  server follow; `docs/edge-ipv6.md` "IPv6 /64 grouping".
- **A detector ban's notification shows the /64 it took.** The "Banned as:
  <the /64>" line never reached the mail or chat message of a detector's ban
  (the sink did not pass the banned element on to the notifier).
- **An automatic L7 ban of an IPv6 client takes its whole /64** (not a
  loopback, link-local, NAT64 or Teredo address: a /64 there is shared by
  unrelated clients, so those stay per address). The
  detector sections (waf_security, the web detector, logins…), the challenge
  server and the admin API's login autoblock, TTL and permanent, banned the
  one address, so a client rotating inside the /64 any VPS or ISP line hands
  it walked past every ban. The /64 now goes to a new set,
  `block_v6_clients`, with its own drops right after `block_v6_nets'` (an
  existing chain gets them placed there on upgrade, never on top of the
  self / allow accepts), so it never collides with the operator's own IPv6
  CIDRs. A /64 ban is only ever added or extended, an extend replaces it in
  one transaction, and the address is banned instead (no ban is lost) when
  the /64 holds this node's own address (a provider sharing one /64 between
  customers' VPSes) or its default gateway, an ignored address or network (`cfm.ignore`,
  `IGNORE_IPS` / `IGNORE_NETS`), an allowed one, a trusted proxy's range
  (Cloudflare's), or nft cannot write it. `cfm flush` empties
  `block_v6_clients` too. The edge bans the
  /64 too for clients behind Cloudflare (not where an allow or a trusted
  proxy range touches it), a TTL /64 ban survives a reboot or `cfm reset`
  (`ttlbans.json`; a permanent one, like a detector's permanent host ban, is
  not persisted; the boot restore writes them in batches, so a thousand land
  inside the edge's 30 s wait), and unblocking any of its addresses, or the
  /64 itself (`cfm unblock <the /64>`), frees the /64. The
  alert says `Banned as: <the /64>`. The kernel flood / port-scan autoblock
  stays per address (it counts packets whose source can be spoofed: a /64
  there would let a forged prefix ban someone else's), as do IPv4 and manual
  bans; counters and rate limits are still per address (next). Live netns
  run on both engines (and the kernel behaviour on earth's 4.18 and rigel's
  5.14). A downgrade leaves the set in place, but the older `cfm unblock` /
  `cfm flush` do not touch it; `docs/edge-ipv6.md` "IPv6 /64 grouping".
- **IPv6 link-local clients (`fe80::/10`) are never self at the edge.**
  `cfm_selfip.lua` counted them as the node's own, so a request from one
  skipped the WAF and the challenge (cfm.lua Step 0a). Harmless while the
  edge listened on IPv4 only; with IPv6 listening, a host on the same L2
  segment (a provider VLAN) could connect from any `fe80::` address it likes.
  Now refused as self, the node's own `fe80::` addresses included, and an
  `IGNORE_NETS` entry covering `fe80::/10` is ignored by design; loopback,
  `169.254/16` and the node's global addresses are unchanged (the panel
  edge's fallback, used without `cfm_selfip`, agrees).

### Added
- **`scripts/install-edge.sh` prepares cfm-edge as the node's edge** (EL
  8/9/10): installs the `cfm-edge` rpm from the repo cfm comes from, checks the
  cfm user, temp dirs, fallback cert, the shared Lua set and the Site Cache
  dirs, and tests CFM's config together with its sidecars from a staging
  dir (`cfm-edge -t`); only a passing set goes into `/etc/cfm-edge/`, a failed
  one changes nothing there (the package's placeholder is kept as
  `nginx.conf.pre-cfm`, a replaced CFM config as a timestamped copy). That adopts
  it: from then on every cfm upgrade keeps its config and sidecars current.
  It never touches the live edge (no `systemctl` start / stop / reload /
  enable, no `cfm dnat`, the IPv6 listen decision for cfm-edge only and
  without a reload; `check_install_edge.sh` pins it): it prints the steps for the operator, `cfm dnat off`, the
  systemctl swap from the engine running now, `cfm dnat on` when satisfied,
  and the way back.
- **The daemon knows cfm-edge**, CFM's own edge package (nginx.org nginx +
  the OpenResty Lua set, `chrismfz/cfm-edge`), as a third engine next to
  OpenResty and Angie: unit `cfm-edge.service`, `/usr/sbin/cfm-edge`, config
  and sidecars in `/etc/cfm-edge/`, logs in `/var/log/cfm-edge/`, Lua from
  the shared `/var/lib/cfm/lua/`. `cfm health` (a cfm-edge row next to
  OpenResty and Angie, `inactive` where it is not installed), `cfm dnat`,
  edge_health, the heartbeat (`edge = "cfm-edge"`), the edge log tools and
  `journal_tail` recognise it. Nothing changes on a node without it: every
  edge list keeps its order and gains a cfm-edge entry after the existing
  engines' (a missing unit or file is skipped as before). No node runs
  cfm-edge yet; its install script comes next. The agent file sync and the
  bridge's upload directories stay closed to it (nothing needs them).
- **The CFM package keeps a cfm-edge node's edge config current**, as it does
  OpenResty's and Angie's. On a host with `/usr/sbin/cfm-edge`, every
  install/upgrade tests and deploys `/etc/cfm-edge/nginx.conf` and its
  sidecars (`trusted_proxies.conf`, `challenge_waf_bypass.conf`, the panel
  listeners) with `cfm-edge -T`, installs the IPv6 listen guard's drop-in on
  `cfm-edge.service` and writes its IPv6 listen files to `/etc/cfm-edge`
  (same decision, `EDGE_LISTEN_V6`), reloads an active `cfm-edge.service`,
  and removes those files on package removal. Its config is
  `configs/cfm-edge.conf`, generated from `openresty.conf` by its paths only
  (`make cfm-edge-conf`; `make release` re-renders and commits it, and CI
  fails a stale copy), so a WAF / Site Cache / IPv6 change reaches cfm-edge
  without a second edit. Its logs (`/var/log/cfm-edge/`) are rotated by the
  cfm-edge package; CFM's hourly logrotate pass now runs that package's
  config too, so its size cap fires hourly as the OpenResty logs' does. The
  deploy summary now names every active edge and calls more than one
  ambiguous (it knew exactly two). Only an ADOPTED cfm-edge is touched (its
  `nginx.conf` is already CFM's, which `install-edge.sh` will put there): a
  host that merely has the cfm-edge rpm keeps the package's placeholder, so
  its config test never creates `/var/log/cfm-edge/*.log` files that the edge
  log tools would then prefer over the live edge's.
- **The edge can listen on IPv6 (`EDGE_LISTEN_V6 = on`; off by default until
  IPv6 /64 grouping).** The web DNAT
  redirect has always caught IPv6 (`table inet`), but the edge listened on
  IPv4 only, so an IPv6 visitor's connection to 80/443 was refused: browsers
  fell back to IPv4, IPv6-only clients failed. The two listener `server{}`
  blocks now include generated `cfm-listen-v6-http.conf` /
  `cfm-listen-v6-https.conf` (`[::]:9080`, `[::]:9043` ssl + quic) through a
  glob, so an absent file means IPv4 only. `scripts/cfm-edge-listen-v6.sh`
  writes them, where `EDGE_LISTEN_V6` allows it, only when the host has a global
  IPv6 address,
  nothing else holds the edge's IPv6 ports, the origin listens on IPv6 on 80
  and 443, the origin trusts the edge's IPv6 hop from `::1` (below), the live
  main config includes them and the engine's config test passes; otherwise
  the edge stays on IPv4 and the script says why (`status`). It runs,
  through `cfm-edge-listen-v6.service` and a drop-in on `openresty.service` /
  `angie.service`, before every edge start, ahead of the edge's own config
  test, so a host without IPv6 never fails to start on it; a package upgrade
  runs it too but only keeps or removes files, never turning IPv6 on and
  never reloading. The edge's IPv6 ports are judged from the kernel's socket
  owner (`/proc/net/tcp6`, `udp6`), never from the process names `ss` prints.
  A root listener on `[::]:PORT` is the edge's own (its accepted connections,
  owned by its workers, do not count); on a port without one, any socket not
  owned by root, in any state (a tenant's, `[::1]` included), keeps IPv6 off
  instead of making the edge's start fail, and the port is really bound first
  (`cfm realip v6-bindcheck`: a bound-only socket is invisible in `/proc`). A `render` that writes the
  files reloads a running edge at once and checks it listens on IPv6,
  removing them and reloading back if not (a failed reload leaves nginx on
  its old config, never down); one that removes live files reloads too.
  Off by default for now: per-IP defences key on the full IPv6 address, so a
  direct IPv6 client rotating inside its /64 would evade them, while an edge
  without IPv6 refuses it and the browser falls back to IPv4, where they
  hold; once they group IPv6 by /64 the default becomes automatic (one switch
  in the script and one in Go, pinned equal) and the key is not needed. The
  script and `cfm realip` read the key the same way (a shared fixture). On a
  node that does not set the key the edge stays on IPv4; the unit, the
  drop-ins and the include lines are installed everywhere and the script runs
  before every edge start. Verified on speedhost (OpenResty) and
  qualityweb (Angie) with a scratch edge. To turn it on: uncomment
  `EDGE_LISTEN_V6 = on` in `cfm.conf`, run `cfm realip fix`, then
  `sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh render`. Before a start, files a render approved are kept when only
  readiness is missing at boot (no global address yet, the origin not up
  yet, `cfm realip` unable to give a verdict), so a reboot does not silently
  drop IPv6; a definite "the origin does not trust `::1`" removes them.
  Behaviour change: a domain
  with an AAAA record whose vhost is not bound to that IPv6 address used to
  fall back to IPv4 (refused at the edge) and now gets the origin's default
  vhost over IPv6. Package removal removes the unit, the drop-ins and the
  files. The panel ports stay IPv4. `docs/edge-ipv6.md`.
- **`cfm realip` requires `::1` trust where the edge listens, or may and can
  listen, on IPv6.** An IPv6 visitor's origin hop comes from `::1`; an origin
  trusting only 127.0.0.1 would see every IPv6 visitor as `::1`, i.e. as
  localhost. The requirement starts as soon as `EDGE_LISTEN_V6` allows IPv6
  and the host can do it (a global IPv6 address + the origin on IPv6 on 80
  and 443), before the edge listens, so
  `cfm realip fix` writes the `::1` trust for Apache and nginx even where the
  127.0.0.1 trust came from a file CFM did not write (Imunify's
  `i360.remoteip.conf`); LiteSpeed needs `::1T` in its allow list by hand.
  On such a host with an origin trusting 127.0.0.1 only, `cfm realip`,
  `cfm health` and `edge_health` now warn ("the edge does not listen on IPv6";
  whats_wrong titles it "origin does not trust the edge's loopback"), `edge_ipv6` / `edge_ipv6_listening` in `--json`.

### Fixed
- **An OpenResty / Angie start no longer leaves empty cfm-edge logs that hide
  the live edge's.** On a node prepared with `install-edge.sh` whose edge is
  still OpenResty or Angie, the IPv6 listen check that runs before every edge
  start (`cfm-edge-listen-v6.service`, which checks every engine) config-tested
  the idle cfm-edge once it had IPv6 listen files, and `nginx -t` creates
  every log it names: each start left fresh empty files in
  `/var/log/cfm-edge/`, and `edge_error_tail`, `ip_forensics` and whats_wrong,
  which read the newest edge log, read those instead. The check now removes
  the empty files its cfm-edge test created (never one that was there before
  or has content, and nothing while cfm-edge may be running), and runs that
  test with `-e /dev/null` where cfm-edge offers it (nginx >= 1.19.5), so a
  test warning does not fill `/var/log/cfm-edge/error.log` either; so do
  `install-edge.sh`'s own config tests (their messages still print).
  `install-edge.sh`'s own cleanup now also keeps the logs of a cfm-edge whose
  unit is still starting or reloading or that runs outside systemd, and
  follows a symlinked `/var/log/cfm-edge`.
- **A cfm upgrade no longer leaves empty cfm-edge logs that hide the live
  edge's.** On a node prepared with `install-edge.sh` whose edge is still
  OpenResty or Angie, the package deploy's cfm-edge config tests created
  fresh empty files in `/var/log/cfm-edge/` on every upgrade (`nginx -t`
  creates every log it names), and `edge_error_tail`, `ip_forensics` and
  whats_wrong, which read the newest edge log, read those instead of the live
  edge's. The deploy now removes the empty files its tests created (never one
  that was there before or has content, and nothing while cfm-edge runs), as
  `install-edge.sh` already did for its own tests.
- **CFM's log rotation names every generation by date and time, on every
  run.** On EL the distro's daily logrotate applies `/etc/logrotate.conf`'s
  global `dateext` (`access.log-YYYYMMDD`), while CFM's hourly pass runs
  `logrotate-cfm` alone and numbered them (`access.log.1`, `.2`, …). `rotate N`
  counts per naming scheme, so a log kept up to twice that (14 generations of
  a 2G cap for the edge, 28 for `/var/log/cfm`), and a second dated rotation on one day failed with `destination …
  already exists, skipping rotation` (logrotate exit 1). Every block now sets
  `dateext` + `dateformat -%Y%m%d-%H%M%S` itself (not globally: the hourly
  pass reads `/etc/logrotate.d/cfm-edge` in the same invocation), so both runs
  name generations alike and never collide. Generations already on a node
  (numbered `.N`, and on EL the date-only `-YYYYMMDD`) no longer match and are
  never expired: remove them by hand once they pass the old retention
  (`docs/log-rotation.md`).
- **Removing a CIDR a set does not hold no longer fails on the exec engine.**
  nft (1.0.4 on EL8, 1.0.9 on EL9) answers a delete from an interval set with
  `element does not exist`, which `RemoveBlockNet` / `RemoveAllowNet` /
  `RemoveIgnoreNet` did not take as done: `cfm unblock <cidr>` of a network
  not banned reported an error. Found by the live netns test of the /64 bans
  (every IPv6 unblock now removes its client's /64).
- **Edge: the origin hop works for an IPv6 destination.** It failed every
  request with a 500, twice over. The origin URL was built as
  `https://<addr>:443`, which nginx reads as host `2001` plus an invalid port
  (`invalid port in upstream`; the opt-in keepalive balancer hit the same
  parse in `set_current_peer`). And once that parses, the server-level
  `proxy_bind 127.0.0.1` cannot be bound on an IPv6 socket. An IPv6 address is
  now bracketed (`cfm.lua` origin pass, `cfm_origin_ka.lua`, the balancer
  fallbacks, the `$cfm_origin_addr` map in `openresty.conf` / `angie.conf`),
  and every origin location binds the loopback of its upstream's family
  (`$cfm_pass_bind` / `$cfm_origin_bind`: `::1` for IPv6; the local IPv4
  upstreams keep `127.0.0.1`). The origin then sees an IPv6 visitor's hop
  from `::1`, which an origin trusting only `127.0.0.1` treats as localhost
  (`Require local`, cPanel's server-status, apps that trust localhost, one
  bucket for every login limiter): `cfm realip` now requires the `::1` trust
  wherever the edge listens on IPv6, a hand-added `listen [::]` included
  (below). `$cfm_pass_bind` is a `volatile` map, so an early read of it can
  never pin an IPv6 hop to `127.0.0.1`, and `check_origin_ka_config.sh` now
  also fails an origin `proxy_pass` through another variable, a second map
  for these variables, and a changed server-level bind.
  IPv4 behaviour is unchanged. Found by an operator who added `listen [::]`
  by hand; the reference confs still listen on IPv4 only (IPv6 listening
  comes separately: a listen on a host without an IPv6 stack fails the config
  test). Not yet run against a real IPv6 origin.
- **`IGNORE_NETS` IPv6 networks now bypass the edge too.** They were written
  to the Lua cache as nothing (only exact IPv6 addresses were), so an IPv6
  network the Go engine ignored was still WAF-checked and challenged at the
  edge, including clients behind Cloudflare, which reach the edge with their
  own IPv6 address. `cfm_ignore_nets.lua` gains `v6_ranges`. **This widens an
  exemption on upgrade:** an IPv6 CIDR already in `IGNORE_NETS` now also gets
  the edge's self-origin hard bypass (ahead of the edge ban store, so it skips
  edge bans too), skips the edge WAF, the challenge and the panel WAF, and
  sees the Site Cache debug stamp, exactly like an IPv4 entry. Review those
  entries before upgrading (none on our own nodes as of 2026-11-19). An
  IPv4-mapped client (`::ffff:a.b.c.d`) never matches an IPv6 network, as in
  the Go engine.

## 2026.11.18

### Fixed
- **Abuse shadow: an integration's API calls no longer read as a rate
  outlier.** `rate_outlier` (log-only) counted every dynamic request, so a
  stock or ERP bridge polling a quiet shop's WooCommerce REST API logged
  `verdict=would_challenge` every hour (vol2.gr's e|connect bridge, 24-31× the
  shop's median). Server-to-server endpoints (WooCommerce REST, payment
  webhooks, courier tracking: the narrow list a vhost challenge already
  exempts) no longer count toward it. Nothing was ever blocked; this keeps the measurement honest
  before the signal is considered for enforcement.

### Fixed
- **ChallengeV2: a quiet `cpanel.`/`webmail.`/`whm.` subdomain is at v2 from
  its first solve.** The default `CHALLENGE_VHOST` list is wildcards, and the
  tick noted a matching host as `vhost_config` only while it had traffic in
  the window, so the first visitors after a quiet spell solved the always-on
  panel challenge at v1 and got a cookie: 16 solver-farm solves in seven hours
  on two nodes. The tier resolver now reads the list itself: a listed host
  under a live vhost challenge is `vhost_config` with or without a note. A v1
  pin still decides, and the list alone, with no live challenge, arms nothing.
- **`[modsec]` no longer watches a file that isn't there.** The stock
  `LOG_PATH = /var/log/apache2/error_log` is cPanel EA4's real path, but
  DirectAdmin, Debian and nginx hosts have no such file, and because the path
  was explicit the candidate scan never ran: on 3deers, avglb, saf (Apache
  running) and watchdog the ModSecurity detector tailed nothing. In
  `MODE = auto` a `LOG_PATH` that does not exist is now logged and the scan
  (now including EA4's path) runs instead, so a live `detectors.conf` that
  kept the old line is fixed by the upgrade. The stock line is now
  `LOG_PATH = auto`, and a quiet host with no denials yet tails the first
  error log that exists instead of nothing, re-checked every 10 minutes until
  one shows denials; a log that appears after the start is picked up without
  a restart. `MODE = file` still pins the path as given.
  `detectors_srcresolve` now reports the file it tails.
- **`ngm_auth` counts the NGM credential failures it was missing.** The
  step-up re-auth failures (`PASSWORD_CHANGE_FAIL`, `MFA_DISABLE_FAIL`,
  `RECOVERY_SET_FAIL`: a logged-in session guessing the password) now count
  like a failed login, except their account-disabled / suspended refusals.
  `DYNDNS_DENY` and `API_ACCOUNT_DENIED` stay uncounted: NGM logs a suspended
  account's valid dyn-DNS token as `badauth` too. A fixture of NGM's event
  names pins the allowlist.
- **`[waf_security]`: a `RULE_<id>` above 1 counts that rule's own hits.**
  The other rules of its family used to fill its count, so `RULE_329 = 2`
  under a family at 5 fired on 329's first hit after one other RCE hit. Still
  one alert per IP and family until the family has been quiet for a window. Thresholds 0 and 1, which
  every shipped config uses, behave as before.

### Changed
- `configs/cfm.blocklists` lists the fleet blacklist `MYBLOCK`, commented
  out. It was never provisioned: 8 nodes added it by hand (speedhost as
  `MYIP_BLOCK`), and 3deers, avglb, saf and watchdog do not pull it.
- The stock `[webdetector]` documents `IP403WAF_COUNT` (WAF-origin 403 flood,
  0 = off), commented out at its default.

### Security
- **Drupal render-array injection blocked (rule 10030).** A request that
  sends a Drupal render-array callback key (`#region_callback`,
  `#post_render`, `#pre_render`, `#lazy_builder`, `#access_callback`) as a
  parameter name or a JSON key, also in a chunked or large body, is blocked
  and its source banned (the words in
  text, such as a search or a code sample in a post, never match): the shape of
  SA-CORE-2026-014 (CVE-2026-108097, fixed in Drupal 10.6.19 / 11.3.19 /
  11.4.10) and of Drupalgeddon2 (CVE-2018-7600), which reached a site with a
  200 this week. Drupal builds those keys itself, so no real request sends
  one; 7 days of every node's logs found them only in attacks. It matters
  most for Drupal sites past end of life (8.x, 9.x), which get no core patch.
- **The admin token's source-IP binding now also applies at `/mcp`.** With
  `ADMIN_TOKEN_IP_BINDING = enforce`, the admin token opens the read-only MCP
  endpoint only from the sources it opens the API from; elsewhere it gets
  `403`, the same audit line and the same `ADMIN_TOKEN_FOREIGN_IP` alert.
  `MCP_TOKEN` and OAuth tokens are unaffected.
- **Stricter MCP OAuth.** A token request that names a different client than
  the one a code or refresh token was issued to is refused, and dynamic
  registration accepts only redirect URIs with a host and no user part.
- **The control plane answers `404` to a path carrying an encoded `/` or `\`**
  (`%2F`, `%5C`), before any auth decision. No CFM client sends one.
- **A tenant's MySQL lock graph shows only its own connections.** The scoped
  `mysql/user-summary` view listed other accounts' waiting connections (user,
  client host, state; never query text) under a lock group whose blocker was
  the tenant's.
- **`history/events` returns at most 5000 rows per call**, for every caller
  (CLI `--limit` and the MCP `detection_history` tool included), so one
  request can no longer hold the history store for an unbounded query.

### Fixed
- **A tenant's history summary no longer counts the server's mail and backup
  rows.**
  `history/summary` `total_events`, and the detector summary inside
  `host-access-history`, left the server's `mail_*` / `backup_*` rows in the
  count for a tenant whose sites include the server's hostname, although the
  rows themselves were already hidden from it. The operator's view is
  unchanged.

### Security
- **Hardened /cfm-admin path normalisation in the auth middleware**, and in
  the edge configs' `/cfm-admin/` locations, which now also set
  `X-Forwarded-Host` themselves on every hop to the daemon.
- **Tightened the CSRF and auth checks of the cfm-admin API** (defence in
  depth), and `/api/v1/cpanel/user-info` adds failure detail only for the
  plugin's own local call with `X-CFM-Debug: 1`.
- **Scoped traffic-rule and Challenge Access-Control lists name only the
  caller's own sites.** An entry the operator shares across several tenants'
  sites shows each tenant only its own, as the rules export already did.
  Rule get and simulate show the same view, without the entry's free-text
  note; get no longer refuses a rule the list shows. The exclude, HTTP/3
  and ClamAV signature-ignore lists likewise show a tenant only its own sites
  in each entry's `scope_hosts`.
- **More cfm-admin API checks (defence in depth):** the same-origin check
  tells ports apart, so another service on the same host is another origin;
  public routes are matched exactly; every web-detector route requires an
  admin or scoped identity; a logout another site started ends no session.

### Fixed
- **A tenant can remove a host exclude on its own site that another account
  wrote** (a domain that moved between accounts), when its own account holds
  that host; the operator's ClamAV and challenge host entries stay the
  operator's to remove. Such an exclude used to keep
  applying with nobody able to remove it, the operator included, through the
  challenge and ClamAV endpoints.
- **Scoped top lists (top-short, suspicious, long-top) return up to the
  requested number of the tenant's own rows**, instead of filtering a list
  already cut to that number across all sites.
- **A tenant's archival host scan can no longer take both scan slots**, and
  its answers no longer name the node's log files.

### Removed
- The web detector's unused standalone HTTP server (`ServeHTTP` /
  `ServeHTTPWithContext`; `API_LISTEN` has been ignored for a long time).

### Changed
- **The MCP server's instructions name every tool.** The guidance an MCP
  client (Claude) reads when it connects listed only the first ~20 tools;
  the edge, host, MySQL, mail, cfm-lsm, Site Cache and log tools were
  missing, so a model had to discover them by listing. It now names all 62
  by group. The tools themselves are unchanged.
- **License: CFM moves from Apache 2.0 to the Functional Source License,
  Version 1.1, ALv2 Future License (FSL-1.1-ALv2).** Running CFM on your own
  servers, including to protect your hosting customers, stays free; offering it
  to others as a competing commercial product or service needs a commercial
  license. Each version becomes Apache 2.0 two years after its release, and
  every version released before this change stays Apache 2.0. The cfm-lsm BPF
  programs are GPL-2.0-only, now stated explicitly. The packages ship
  `LICENSE`, `NOTICE` and the GPL text (`/usr/share/doc/cfm/` in the .deb,
  `/usr/share/licenses/cfm/` in the .rpm), and the rpm's `License:` field,
  which wrongly said MIT, now names both licenses (the .rpm drops the .deb's
  `/usr/share/doc/cfm/` copy, which `make release` used to leave in the shared
  staging tree and which failed the rpm build). See `NOTICE` and README §9.
- **`SSLCOLLECTOR_SOCK_PATH` is fixed at `/var/run/sslcollector.sock`.** The
  edge has only ever connected to that path, so a node that set another one
  silently stopped delivering certificates to the edge. The daemon now ignores
  any other value and logs a warning (once per value), and `cfm config test`
  lists it under "ignored values"; the socket stays where it always was.

### Fixed
- **`edge_health` advice names only real checks.** Check B's critical advice
  pointed at an `origin-config-invariant` check and check A's summary at an
  "edge_health Tier-2", neither of which exists; both now say what to check in
  the live edge conf. `whats_wrong` shows check H (`web-dnat-order`) under a
  title instead of its raw id.
- **nftlib: `cfm dnat cpanel status` prints the panel chain's own priority**
  (it printed the web redirect's `NFT_DNAT_PRIORITY`). It and `cfm dnat` now
  also list the source-IP bypass accept rules (`cfm.dnat_cpanel_bypass`,
  `cfm.dnat_bypass`), as the exec engine already did.
- **`cfm ssl stats|scan|dump` no longer rewrite the daemon's `dump.json`.**
  The CLI's own scan only reads the cert files now.
- **`/api/v1/webdet/suspicious` uses the `MIN_SCORE` default (0.60)** when no
  score floor is configured, not 0.50.

### Security
- **A `--` in one query parameter no longer hides the next ones from the
  SQLi rules.** `?x=--&id=1'+union+select+1,2,3` read as clean, because the
  SQL-comment strip removed everything after the `--`, other parameters
  included. A comment now ends at its parameter's `&` (and a `--` in the path
  at the `?`). Path and query only: request bodies are read as before.
- **MySQL executable comments in the query are read as SQL.**
  `/*!11110extractvalue*/(` is run by MySQL, but the WAF deleted it with the
  comment, and scanners' `procedure analyse` probes using it reached sites on
  several nodes. Its content is now kept, so rules 301 and 309 see it.
- **More SQLi and PHP probes blocked in the query** (rules 301 and 332,
  already armed for autoblock): `' order by 3--`, `procedure analyse(`,
  `') and ('x'='x`, `1 and 1=1`, Oracle's `utl_inaddr.get_host_address(`,
  and `${@var_dump(md5(N))}`. Measured over 8 days of every node's logs:
  every match was a scanner.

### Fixed
- **Config files cfm-web distributes now take effect without waiting for a
  restart.** The agent wrote the files cfm-web pushes (Admin → Configs →
  targets, e.g. the SpamAssassin `custom-keywords-rules.cf`,
  `mailfromfilters.cf`, `myip.cf`) but never ran the target's
  `post_update_command`, so spamd kept the old rules until its next restart.
  The agent now runs it after the write, once per action, but only if it is
  one of a fixed allowlist (`systemctl restart spamd`, `systemctl reload
  spamd`, `/scripts/restartsrv_spamd`), with no shell: cfm-web holds every
  node's token, and running any command it names would make a compromise of
  it root on the whole fleet. Anything else is refused and logged
  (`[files] REFUSED post_update_command`). Every action runs as a `systemctl`
  job (cPanel's restartsrv too), so a cfm restart mid-command cannot leave
  spamd stopped. For the same reason only `.cf` rule files are accepted under
  `/etc/mail/spamassassin/`, with `loadplugin` by Perl package name only (a
  plugin file path is Perl run as root; the distributed `myip.cf` loads SPF,
  DKIM, DCC and HashBL by name and is unaffected) and `include` only inside
  that dir; a refused version is logged once and not downloaded again. A change there is
  linted first (`spamassassin --lint`, the cPanel copy or the system one): a
  problem the new files introduced, one the lint before the write did not
  report as often, rolls them back (old content and mode) and skips the
  restart. When several files changed at once the set is halved until the
  file at fault is found; only it is parked (not downloaded or applied again
  until cfm-web sends a different version). Problems that were already there,
  also when the update moves their line number (a `dcc_*` line with the DCC
  plugin off, a missing Hashcash plugin), do not block it, and a lint that
  cannot run (a timeout on a loaded box) defers the change, and the files
  not judged yet, with a growing delay (1 min doubling to 1 h) instead of
  judging it; they are not downloaded again meanwhile. After a spamd action
  the agent checks that spamd is active again: if it is not and the sync
  wrote SpamAssassin files, those are rolled back and parked and spamd is
  restarted on the old ones; an action that still fails is retried on later
  syncs (at most every 5 min) instead of being forgotten once the files
  match. The sync now runs off
  the work loop, so a lint and restart never delay unblocks or policy pulls.
- **WAF rule overrides in `/etc/cfm/cfm_waf_config.lua` now apply.** The docs
  and several release notes (2026.09.22, 2026.10.09, 2026.11.14) told
  operators to set or revert a rule's mode there, but nothing read that file:
  the edge workers run as `cfm` and cannot read root-only `/etc/cfm`, and the
  edge only looks in its own Lua directories. An override written there never
  took effect. That includes the 2026.10.09 advice to disable
  `rule_form_relay_sppb_contact` until the upgrade. (No node had such a file.)
  - The daemon now copies the file within ~5 s to
    `/var/lib/cfm/lua/cfm_waf_config.lua` (`root:cfm 0640`), as it already
    does for the IGNORE_NETS and self-IP lists. Deleting the `/etc/cfm` file
    removes the copy.
  - **Reload the edge after an edit**: the workers load the file once. The
    daemon log says `[wafconfig] … reload the edge to apply it`.
  - A file someone placed in `/var/lib/cfm/lua/` by hand is kept, and is
    moved aside as `cfm_waf_config.lua.handplaced.<time>` only when an
    `/etc/cfm` file appears.
  - A file that fails to load (a syntax error, no `return`, not a table)
    now logs `[cfm_waf] cfm_waf_config.lua ignored, WAF overrides NOT
    applied: …` in the edge error log. It used to be skipped silently.

### Security
- **A solve that nothing asked for no longer banks a clearance cookie.**
  - The case: the solver farms open the challenge page on each new IP while
    the site is NOT challenged, solve it, and keep the cookie. When the
    site's automatic v2 challenge came back, that cookie walked the IP past
    the v2 check. On 2026-11-18 one titan shop had 395 such solves in a
    morning after its challenge ended; over two to three days four nodes had
    6 333, 97% of them the two convicted farm fingerprints.
  - Now: a web solve that no challenge covered when it was verified
    (`src=-`) is scored at v2 (`v2=unsolicited` on the solve line). One that
    fails gets no cookie and goes on to the page it asked for. Nothing is
    challenging it, so a person who lands there (an expired challenge, an old
    tab) sees no difference. The panel ports are not affected.
  - The solver-farm detector and the `challenge_score` shadow scorer still
    count these withheld solves, once per IP and site per hour: the farms'
    pre-solves are what they look for. The Under-Attack solve rate and
    `challenge_cookie_discard` see only solves that earned a cookie.
  - Knob: `[webdetector] CHALLENGE_V2_UNSOLICITED = 0` turns it off.
- **An automatic v2 challenge no longer drops to v1 while it is still being
  served.**
  - What happened: the v2 tier of an automatic site challenge had to be
    renewed by every webdetector run within minutes. When a run timed out,
    the challenge stayed but its tier fell to v1. A farm IP was rejected at
    v2 and passed three seconds later. Separately, a `uniqpaths_short`
    challenge lost its v2 tier as soon as the burst ended, while it ran out
    its time at v1.
  - Now the tier lasts as long as the challenge it belongs to (an hour at
    most), and ends when the challenge or its source ends.

### Fixed
- **Socket.IO and SignalR apps no longer lose their connection to rule 601.**
  Their long-polling POSTs separate messages with the 0x1E byte (Socket.IO
  under any path, ASP.NET SignalR, json-seq), and rule 601 (control
  characters) answered such a POST with a challenge the app could not solve.
  It is framing there, so 601 no longer counts 0x1E in a body (the query
  keeps it); every other control byte still counts. Seen on speedhost (a CRM's live updates);
  `docs/waf.md` FP case 13.
- **The subnet challenge (`CHALLENGE_SUBNET`) no longer re-issues the same
  challenge every 10 seconds.**
  - What happened: while a /24 stayed over its thresholds, every member IP
    was challenged again on every 10-second pass, although each challenge
    lasts `CHALLENGE_SUBNET_TTL` (20–30 min). Each pass wrote a history row
    and an alert per IP. On qualityweb (2026-11-18) two Baidu /24s on two
    sites made about 31 000 `challenge_issued` rows an hour for the same 200
    IPs, and the webdetector run timed out about 270 times a day.
  - Why it matters beyond the noise: a run that times out stops refreshing
    the automatic v2 tier of challenged sites, so for a few minutes at a
    time their challenge was held only to v1. A farm IP was rejected at v2
    and passed three seconds later.
  - Now: a new member of a hot subnet is still challenged within about 10
    seconds. One already challenged is refreshed only once half its
    challenge has run.
### Added
- **`make waf-corpus`: detection and false-positive numbers for the WAF before
  a change ships.** It runs BlazeHTTP's labelled corpus (~33 k benign and ~650
  attack raw-HTTP requests, fetched at a pinned commit, never vendored) through
  the real in-path WAF under LuaJIT, no nginx needed, in about 30 s, and reports
  per rule what it caught, what it flagged on benign traffic and which attacks
  passed. `--out` / `--baseline` list the samples a change moved. Baseline
  today: 32.0% of attacks met with a block or challenge, 0.60% of benign
  requests (178 of those 199 are rule 601 on binary or compressed telemetry
  bodies, most declared `text/plain`). Hit-rates on live traffic cannot show what the WAF
  misses; this can. `docs/waf.md` "Labelled corpus (BlazeHTTP)".

### Added
- **The malpath list catches the dev-tool and credential probes it missed.**
  `webdetector_malpaths.txt` gains 189 entries, all measured on the fleet's
  edge logs (9 days, ~300 M requests over the 8 edge nodes), and drops 35 that
  another line already covered (the first match wins, so they were dead): 152
  lines become 306. Almost every 200 on the new entries was a site's catch-all
  page; the exceptions were tenants' real composer manifests (see below). They
  feed both the per-IP malpath challenge and the MALPATH flood ban.
  - VCS directories as a whole (`/.git/`, `/.svn/`, `/.hg/`, `/.bzr/`; only
    `/.git/config` and `/.git/HEAD` were listed), `/.github/`, IDE folders.
  - Cloud service-account / API key files (`/key.json`, `/gcp-key.json`,
    `/google-credentials.json`, `/sa.json`, `/firebase-*.json`, … — up to
    1 500 distinct IPs a node), credential directories (`/.aws/`, `/.ssh/`,
    `/.docker/`, `/.kube/`, `/.azure/`, `/.config/`), `.env`-style and token
    files, private keys, shell / git dotfiles and mail-relay configs.
  - AI-tool key stores (`/.claude/`, `/.cursor/`, `/.openai/`, `/.gemini/`,
    `litellm.yaml`, …), CI / build / monorepo files and directories.
  - The cPanel `error_log` PHP writes into the docroot, `/_ignition/`,
    composer manifests (four tenant hosts served a real
    `composer.json` / `vendor/composer/installed.json`, now challenged),
    `.NET` / Java probes, WooCommerce logs, UpdraftPlus
    backups, whole-site archives (`/backup.zip`, `/www.zip`, …), editor
    backups of `index.php`, and the `/.well-knownold/`, `/.bod/` and
    `/.trash…/` webshell stashes.
  Kept out on purpose, with the reason in the file: names a site may really
  serve (`/config.json`, `/settings.json`, `/phpmyadmin`, `/server-status`,
  `/cgi-bin/`, …) and the owner's own workflows, which the challenge and its
  cookie revoke would cut off after the first logged hit (Duplicator's
  `/installer.php` and `/dup-installer/`, All-in-One WP Migration's
  `/ai1wm-backups/` download link, `/wp-admin/install.php` and
  `setup-config.php` of a fresh install, `/adminer`). An unmodified list is refreshed
  by the upgrade; a locally edited one is not (rpm writes `.rpmnew`).

### Removed
- **`/etc/cfm/webdetector_challenge_paths.txt` is gone.** `CHALLENGE_PATHS`
  has read `webdetector_malpaths.txt` since 2026-03-12, so the file was read by
  nothing, yet it still shipped and was still the code default: a
  `detectors.conf` without `CHALLENGE_PATHS_FILE` armed the check with no
  rules. The default is now `webdetector_malpaths.txt` (one constant for the
  daemon and the config reader), and a config that still names the old file
  reads the malpath list instead, with a log line. On upgrade rpm removes an
  unmodified copy and keeps an edited one as `.rpmsave`; the deb does the same
  through `dpkg-maintscript-helper rm_conffile` (an edited copy is kept as
  `.dpkg-bak`).
- **The web detector's malpath matching no longer slows down as the list
  grows.** Every ingested access-log line was checked against the malpath
  list (`configs/webdetector_malpaths.txt`) twice, once for the
  `CHALLENGE_PATHS` challenge and once for the `MALPATH` flood counter, each a
  linear substring scan under the engine lock. Both now use one Aho-Corasick
  matcher built when the config loads, shared when the two read the same list
  (the default): one pass over the path per line. Same answers as before: a
  substring of the lower-cased path without its query, the first matching
  entry in file order (so `N:pattern` thresholds count the same rule), cPanel
  session paths skipped. Measured on a typical path: 3.1 µs → 0.1 µs per line
  at 152 entries, 6.4 µs → 0.1 µs at the 306 the list now holds.
  The list file is also read once per config load instead of twice when
  both keys name it. A list so large that the matcher's table would pass
  16 MB (an operator's own, tens of thousands of entries) keeps the linear
  scan.

## 2026.11.17

### Changed
- **Flood autoblocks are a 72 h ban by default, never permanent unless you
  ask.** A `cfm.conf` with no `THROTTLE_MODE` line (or a blank one) used to
  make every syn / portflood / pps / connlimit / new / icmp autoblock, and
  the cfm-admin login brute-force autoblock, a PERMANENT ban: written to
  `cfm.deny` and reported to the fleet API. It is now `ttl`, and
  `THROTTLE_TTL` defaults to 72 h (was 24 h; the reference `cfm.conf` ships
  `"259200"`). `THROTTLE_MODE = "permanent"` still means permanent. Existing
  confs keep their own lines: an upgrade does not rewrite `/etc/cfm/cfm.conf`,
  so a node that says `permanent` stays permanent until you edit it.

### Fixed
- **A WooCommerce sync no longer gets challenged, then banned.** Requests to
  WooCommerce's authenticated REST API (`/wp-json/wc/v1`–`v3`, legacy
  `/wc-api/v1`–`v3`, at the site root or one install directory down) no longer
  count toward the per-IP challenges (`CHALLENGE_UNIQPATHS_IP`,
  `CHALLENGE_ERR_RATIO`, `CHALLENGE_RPS_TOTAL`, `CHALLENGE_RPS_4XX/5XX`,
  `CHALLENGE_POST_RATIO`): they leave the IP's total for those triggers, and
  the IP's other requests decide alone. So the error and POST ratios are now
  taken over those other requests (API 200s no longer dilute them), and an IP
  that sends only these calls is not checked by `CHALLENGE_HTTP10` either. A
  product sync to kiamaia.gr (mars, 2026-11-17) writes a new
  `/products/<id>/variations/<id>` per request, and some come back 404: it was
  put under a challenge it cannot solve, the challenge page's 403s fed
  `403_flood`, and the IP was banned every 30 s while the sync ran. The Store
  API (`/wp-json/wc/store/…`, cart and checkout, no credentials) and every
  other route keep every challenge; a marker mid-path, an escape or a
  credential route never matches. Nothing else changes: no challenge or ban
  already on the IP is lifted, and the WAF, the 403/404/40x counters and
  `agent_flood` count these requests as before.
- **The L4 flood autoblock no longer bans verified crawlers and Meta's
  link-preview proxies.** Meta's `fwdproxy-*.fbsv.net` addresses (Facebook
  link previews, `facebookexternalhit`, the in-app browser) tripped
  `portflood_443_tcp` and `SYN flood` and were banned permanently into
  `cfm.deny` on two nodes (59 addresses, May-June 2026; one reached the fleet
  blacklist), breaking link previews and in-app visits for every site there.
  The syn / portflood / pps / connlimit / new / icmp autoblock and the
  port-scan autoblock (both engines) now skip an FCrDNS-verified good bot
  (Googlebot, Bingbot, Applebot, Yandex, Meta), as the web detector's own IP
  bans already did; the flood meters still drop its excess packets. A PTR
  that does not forward-confirm (spoofed) is blocked as before. A
  forward-confirm that does not complete skips that crossing, so one DNS
  blip cannot ban a real crawler, but the third such crossing in a row bans:
  an address's PTR is its owner's to set. The forward-confirms spend a
  budget of 5 s of resolver time per minute (they run under the autoblock
  lock, and fake crawler PTRs cost an attacker nothing); past it an address
  without a cached verdict is blocked as before, and one line is logged
  (`[autoblock][goodbot] forward-confirm budget … spent`). A crawler's
  verdict lasts 30 min, and an expired one is still honoured for 24 h when it
  cannot be re-verified right then, so spending the budget cannot get a
  known crawler banned; a full verdict cache drops "not a crawler" entries,
  never verified ones. It needs PTR
  enrichment (the PTR comes from the enricher). The skip is logged (`[autoblock][ignored] …
  FCrDNS-verified good bot meta`), not notified: a crawler re-crosses the
  threshold every window. The startup `[config] throttle:` line now ends in
  `goodbot_exempt=true|false`. Kill switch: `THROTTLE_GOODBOT_EXEMPT = 0` in `cfm.conf`. Existing
  bans are not lifted: unblock them (`cfm unblock <ip>`).
- **MySQL governor: it now starts when MySQL comes up after the daemon.**
  The governor connected once, at daemon start, and never again. When
  MariaDB started after CFM (orion, 2026-11-17: CFM at 14:53:09, MariaDB at
  14:53:32), the governor stayed off until the next CFM restart: no
  `mysql_governor` kills in `enforce` mode, and `cfm mysqltop` failed with
  `invalid character '<'` because its unregistered routes fell through to the
  web UI's HTML page. The governor now retries in the background (every 5 s
  doubling to every 5 min while credentials exist but the connect fails;
  every 5 min, a file check with no connection, on a node with no
  credentials) and stops once it connects or the daemon shuts down. Each
  connect is bounded to 5 s, and none of it runs inline at startup: the API
  comes up whatever the database does. `cfm.service` stays free of any
  ordering on `mariadb`/`mysqld`, so a node without a database waits on
  nothing.
- **`[mysql_governor] ENABLED = 0` is honoured.** The detectors manager
  never calls a disabled section's factory, so the governor saw "no section"
  and started anyway with the built-in defaults (monitor mode, polling the
  processlist every 5 s). A disabled governor (every instance disabled, if
  there are several) now makes no connection, and re-enabling it in
  `detectors.conf` starts it within 5 minutes, without a restart. Removing
  the section falls back to the built-in defaults instead of keeping the last
  parsed config. A `detectors.conf` that cannot be read on first load holds
  the governor (it used to start with the defaults) and it starts within
  seconds of the file reading; removing the file while the daemon runs
  changes nothing.
- **`/api/v1/mysql/*` answers a JSON 503 while the governor is not running**
  instead of the web UI's HTML: `{"error":"mysql governor not running: <state>",
  "reason":…}` with `<state>` one of `starting`, `no credentials`,
  `disabled`, `held`, `connect failed`, `failed` (README, MySQL governor),
  and a `Retry-After` of the next connect attempt. Scoped callers get only
  `{"error":"mysql governor not running"}`. `cfm mysqltop` shows the reason;
  the MCP `mysql_pressure` tool shows the state (never the reason);
  `whats_wrong` lists a governor that is off by design or still starting
  (`no credentials`, `disabled`, `starting`) as `unavailable`, and one that
  is held, cannot connect or failed to initialise as an error. The CLI names a non-JSON answer from an older daemon
  instead of failing in the JSON parser, and a 401/403 reads as the token
  problem it is. The startup log no longer says "no working credentials
  found" when the credentials were found and the connect failed: it names the
  credential source and the connect error.
### Added
- **WAF rule 417 scores PHP source in the whole POST body (logonly).** Rule
  404 reads only a body's first 2 KB. PHP saved through a form field lands
  past it: a plugin-editor save with an eval of a request header at line 32
  (orion, 2026-11-15), and a file manager's put of a shell whose comment
  header fills the first 2 KB (rigel, 2026-11-17). Both reached the disk.
  Rule 417 runs 404's scorer over the whole body the edge reads (32 KB), and
  only when 404 found nothing and the raw body holds something a score can
  come from (`<?`, `$_`, a callable's or webshell's name, or an escape of
  one). It also reads a multipart body's text fields at any size (404 reads
  no multipart body) and a JSON body's `\u00XX` escapes. Logonly through
  burn-in, since a whole legitimate plugin saved through an editor is scored
  too. See `docs/waf.md`, "Rule 417".
  Rule 404 (challenge_v2) changes with it in two narrow ways. It now reads a
  body by its media type, as PHP does: an urlencoded body whose Content-Type
  carried `multipart/form-data` in a parameter escaped both rules. And a body
  scoring on `assert(` / `popen(` / `proc_open(` alone is no longer dropped
  before scoring.
- **Imunify360 RBL locks now reach the fleet list.** On a cPanel node with
  Imunify, a mail login from an address on Imunify's global RBL is refused
  before any password check, and dovecot logs it as `user_disabled`. CFM's
  dovecot detector only counted password failures, so it never banned these
  sources or reported them. On earth that was ~1 200 addresses in three days,
  and none of a 25-address sample was on the fleet list. The detector now counts `user_disabled`
  logins per IP (`USER_DISABLED_IP = 2` in `USER_DISABLED_WINDOW = 24h`). It
  bans them for at most `USER_DISABLED_BLOCK_TTL = 24h`, even though the
  section's `BLOCK` is permanent, and reports them to cfm-web. GR/CY addresses
  get the section leniency. No mail is sent per ban unless
  `USER_DISABLED_NOTIFY = 1`; the alert log still records each ban, as
  muted. A detector can now cap one finding's ban (`core.ExtraMaxBlockTTL`)
  and skip its mail on the block path (`core.ExtraNotify`).
  See `docs/DETECTORS.md`, "dovecot_auth — logins refused as user_disabled".
- **WAF rule 530 measures WooCommerce add-to-cart crawling (logonly).**
  A `GET ?add-to-cart=<id>` makes WooCommerce write a session and a cart, and
  crawlers follow those links on every listing. On 2026-11-17 the fleet served
  ~265 000 of them a day, uncached at 1-3 s each, ~85% to self-declared
  crawlers (meta-externalagent the largest). The rest came from rotating
  residential addresses that Imunify360 flags behind the edge. Rule 530
  (`WAF_CART_CRAWL`) tags each one `CRAWLER`, `NO_REFERER` or `XSITE`. It
  stands down for a shopper's click (same-site Referer or Fetch Metadata) and
  for a cart or login cookie. Logonly: nothing is blocked, and the family has
  no block rule, so `waf_security` never arms it. Its pushes are kept to one
  per client and tag an hour, so the burn-in adds no flood of history rows.
  See `docs/waf.md`, "Rule 530".

### Security
- **WAF rules 601 (control characters) and 611 (bad UTF-8) read a body by its
  media type, as PHP does.** They skipped any body whose Content-Type line
  merely mentioned `multipart/form-data`, so
  `application/x-www-form-urlencoded; x=multipart/form-data`, which PHP
  parses into `$_POST`, hid control bytes and overlong UTF-8 from both. The
  check now takes the media type (the Content-Type up to its first `;`, `,`
  or space, every Content-Type line joined as Apache hands them to PHP), in
  one helper; 601 had its own copy of the substring test. A parameter can no
  longer change the answer either way: `image/jpeg; x=text/plain` is no
  longer read as text. Rule 404's 2 KB head pass shares the helper and now
  reads such a body too. 601 ships at `challenge_v2`, 611 disabled. The
  upload rules' (401 / 402 / 414 / 415) multipart gates stay substring tests:
  they over-read, and miss no body PHP parses as multipart.
- **The dovecot detector no longer takes the address or the verdict from the
  username.** Before, a username such as `rip=203.0.113.50,a@b.gr` made it ban
  the address in the username instead of the client's, and report it to the
  fleet. A noise phrase in the username also hid a password failure. It now
  reads both only from the server's text: on a login line, the reason before
  `user=<` and the last `rip=`; on an auth-worker / passwd-file / pam line,
  the last `(user,IP,<session>)` tuple.

### Fixed
- **The Apache TSV fallback log no longer fills the disk on cPanel.**
  `access_cfm_tsv.log` (the web detector's file source when the edge socket
  is off) lives in `/var/log/apache2/`, which CFM left to the distro's
  logrotate. cPanel has none there: cpanellogd renames the log at 2 GB and
  never deletes the copies, which had reached 316 GB on titan, 207 GB on mars
  and 175 GB on orion. The hourly `/etc/cron.hourly/cfm-logrotate` now deletes
  those copies (`<name>.YYYY_MM_DD[.NN]` only) after a day and, past 512 MB,
  keeps one compressed copy of the live file (`<name>.cfm-prev.gz`) and
  truncates it. A distro logrotate generation or an operator's own copy is
  left alone. It also covers `/var/log/nginx/access_cfm_tsv.log`
  (`nginx-cfm.conf`), and runs on a node without `logrotate-cfm`.
- **`detectors.conf`: a quoted value with an inline comment now reads as the
  value.** `BLOCK = "15m"   ; stage 3 …` was read as the text `15m"   ; stage
  3 …`, an invalid TTL, so the section's block mode was silently `no`. The
  stock `[cfm_endpoints]` (and `[api_abuse]` on older configs) shipped exactly
  that line: its stage 3 never banned on any node. String keys read the same
  way (`MODE`, paths, lists) were affected too; number, on/off and duration
  keys were not. The parser now takes the text between the quotes when only a
  comment follows; every other value reads as before. The stock file no longer
  quotes those lines, so an older daemon reads it right too. A node whose
  config carries such a `BLOCK` starts banning with this release.
  A secret key whose value this changes (`CHALLENGE_TOKEN`, …) is logged once,
  by name and never by value, so a token that changed under its consumer is
  findable.

### Changed
- **`[webdetector] AGENT_COUNT` ships as `35` (was `20`).** The 7-day read of
  the 8 edge nodes (2026-11-17): ~5 800 `agent_flood` bans, 85% Go-http-client
  scanners and 10% Bytespider and similar crawlers; the few Greek site owners
  it caught were developers running curl against their own WordPress. Nodes
  keep their own `detectors.conf` value until it is edited.

- **The proxied IP filter's log line names the client's country and
  network.** Each `[proxied_ipfilter]` line in `cfm.log` now ends with
  `cc=` / `asn=` / `asn_name=` from the node's GeoIP database (read when the
  line is written, no DNS). The week of log mode before any enforce is read
  for two things: a Greek visitor on a block list (the likely customer), and
  a foreign one on a network that serves real users (Google, Microsoft,
  Meta, a CDN) rather than a scanner's host. The first read found Meta's
  forward proxies permanently on two nodes' local block list.
- **WAF rule 10029 (Fabrik list-filter eval, CVE-2026-67282) blocks.** A
  14-day read of all 8 nodes found `[eval]=0` only from real users (that
  stays logonly) and a set `[eval]` only from the attacker who defaced
  dmkomotinis.gr. The rule's family `WAF_CVE` is armed, so the first probe now
  bans the address before any payload is sent.
- **WAF rule 415 names the uploaded file's extension in its tag**
  (`UPLOAD_PHP_TAG_DEEP:<ext>`). Its burn-in had two hits on admin media
  uploads, and the log could not say what file they were.
- **`[webdetector] BLOCK` ships as `12h` (was `2h`).** The 2026-11-17 read
  of the 8 edge nodes found 99% of the web detector's 403 / 404 / 40x bans on
  cloud scanners, the same Microsoft and Google addresses banned up to 51
  times a week at the 1h several nodes ran. Every such ban is also reported to
  the fleet blacklist (MYBLOCK), which a short TTL barely outlives. Existing
  nodes keep their own `detectors.conf` value (a conffile) until it is edited.
  The stock file now also ships `[webdetector.leniency]`: a GR/CY client
  (country only, no ASN) is held 15m and not reported to cfm-web, so a local
  customer is neither held 12h nor banned on every node. A node keeping its
  own `detectors.conf` adds that section (or a `detectors.d` overlay) itself.

### Added
- **WAF rule 10029: the Fabrik list-filter eval (CVE-2026-67282), logonly.**
  The Joomla Fabrik flaw behind the dmkomotinis.gr compromise (earth,
  2026-11-12): an `[eval]` index set on a list-filter field makes Fabrik run
  the filter value as PHP. The rule logs any request field (query or POST)
  with an `[eval]` index on a Fabrik request; `[eval]=0` is logged under its
  own tag. Fabrik's own list filter never sends `[eval]` (7 days of all 8
  edge nodes' access logs: only the attacker did). Logonly for a burn-in; the
  file-writing payloads are already blocked by rule 332. Update Fabrik to
  4.7.2+, which also fixes CVE-2026-66915.
- **`edge_health` check H, `web-dnat-order`: is web traffic reaching the
  edge?** A connection is NAT'd once, by the first nat chain that rewrites it.
  Imunify360 DNATs its sets to WebShield at priority -100, and CFM's web
  redirect defaults to -99 ("Imunify first"). On a cPanel node that set holds
  Cloudflare's ranges, so every Cloudflare visitor bypassed the edge's WAF,
  challenge and edge bans. earth sent ~29% of its web requests to WebShield
  for months; the edge saw 235 Cloudflare requests an hour. The check warns
  when a non-CFM DNAT of tcp/80 or 443 runs before CFM's redirect AND
  WebShield served 100+ requests in the last 15 min, and names the fix
  (`NFT_DNAT_PRIORITY = -101`). The warning reaches `whats_wrong`.
- **The fleet blacklist and the node's own IP lists now reach visitors behind
  Cloudflare (log mode).** nft sees only the proxy's address, so cfm-web's
  blacklist (~270k addresses), `cfm.deny` and the TTL bans never applied to a
  Cloudflare visitor: on earth, addresses other nodes had banned for WAF hits
  got 200s through Cloudflare. The lists now also live in the daemon's memory
  (~1 MB, never in the edge's Lua), and the edge's per-request decision asks
  them, allows first as in nft. `[webdetector] PROXIED_IPFILTER_FEED` /
  `PROXIED_IPFILTER_LOCAL` = `log` (default: a line per client in `cfm.log`
  naming the lists it is on), `enforce`, `off`. An unblock lifts it at once.
  On the
  nftlib engine, reading a set no longer holds the backend's write lock, so a
  dump never delays a ban. See `docs/proxied-ipfilter.md`.
- **Under attack, a "Continue" button for the visitors the challenge cannot
  tell apart** (`CHALLENGE_V2_CONFIRM`,
  `docs/targeted-challenge-design.md` §4).
  - What: while a vhost is UNDER_ATTACK, a solve that passed the humanity
    check with no mouse, touch or key input at all, from a visitor outside
    the audience (`CHALLENGE_V2_CONFIRM_AUDIENCE`, default GR,CY; a
    datacenter network counts as outside), gets no clearance on its first
    try. The page shows one Continue button instead, and the click passes;
    a second try that carries the token but still no click is asked again.
    Nobody is rejected by it. It waits for a hidden tab to be seen again,
    works from the keyboard, and lets the visitor click without solving
    again for up to 5 minutes (bounded by the challenge cookie, 300 s from
    when it was set; past it the page starts a fresh challenge).
  - Why: E4 read 7 (2026-11-17). The `c28caa00` farm answered `linux_sw`
    within a day by passing at score 0 from residential proxies, with no
    input on 9 solves in 10. No score can reject that. The click costs the
    farm a second round trip on every solve, and its approach is measured.
    It is not a wall: a farm that scripts the click (or reports one) passes.
  - Default `manual`: only while an override holds the vhost UNDER_ATTACK
    (`cfm webtop attack on <vhost>`, the cfm-admin Under-Attack toggle, or a
    cPanel user on their own vhost). A verified search-engine crawler is
    never asked (it cannot click). `auto` also covers the detector's
    automatic entry; `off` turns it off.
  - Logs: `result=v2_confirm` when the button is shown, and
    `v2_confirm=clicked v2_confirm_ms=<ms>` on the solve line and history row
    (withheld from cPanel users with the other `v2_*` keys).

### Changed
- **The web detector's 403 counters no longer ban a site's own admin, or a
  visitor a traffic rule already blocks.** `403_flood` (`IP403_COUNT`) and
  `40x_combo` (`IP40X_COMBO`), and the per-IP `CHALLENGE_RPS_4XX` /
  `CHALLENGE_ERR_RATIO` challenges, skip two more kinds of 403. (1) The small
  403 (up to 128 bytes) that WordPress or a plugin itself gives to
  `admin-ajax.php` when the Referer is a `/wp-admin/` page of the same site.
  This is an open admin tab still polling after its session expired: on titan
  a shop's admin was nft-banned for an hour, both of their sites with them. A
  login-type `action` and an origin WAF's block page (ModSecurity, Imunify,
  Wordfence) keep counting. (2) The edge's
  403 for a request that only a traffic rule blocks, now logged as
  `up=cfm_block_rule`; IP, vhost, WAF and edge-ban blocks stay `cfm_block`. On
  rigel a rule blocking WhatsApp's fetcher on one shop turned a shopper's
  link-preview retries into a ban of their home IP. Both requests still count
  in the IP's total, so they dilute the 403 share. The second needs the new
  `cfm.lua` (older edges keep writing `cfm_block` for rule blocks); the conf's
  focused-log map also matches `cfm_block_rule`.
- **WAF tier review of 2026-11-17: five rules move to block, one ban is armed.**
  From 7 days of `cfm.waf.log` and edge `access.log` on the 8 edge nodes.
  A block is also enforced on the cPanel / WHM / webmail ports for what that
  gate reads (it reads no body); cPanel's own API and session paths pass it
  before the WAF.
  - 332 (PHP code in the query) and 416 (a PHP file as the raw POST / PUT
    body), logonly since 2026-11-13: every hit was an exploit (332: 44 from 34
    IPs — ThinkPHP, pboot, Drupal, Fabrik-style eval; 416: 289 from 269 IPs —
    the PHPUnit `eval-stdin.php` sweep and a PUT dropper). 332 is armed with
    `WAF_RCE` (6 h ban + alert). 416's ban is held (`RULE_416 = 0`).
  - 303 (`__proto__` prototype pollution), 307 (XXE) and 438 (a base64
    `<?php` opener in a POST body), challenge_v2 until now: 303 is the
    React2Shell sweep (~19 000 hits from ~5 800 IPs, not one solved a
    challenge), 307 85 hits from datacenters, 438 14 exploit hits (Bricks,
    WP Project Manager). 438 is armed with `WAF_BACKDOOR`. 303 and 307 keep
    their bans held (`RULE_303 = 0`: ~830 bans and alerts a day armed;
    `RULE_307 = 0` through a burn-in).
  - What stays below block: 303's `constructor` + `.prototype` leg (plain
    JavaScript source carries it; all the measured hits were `__proto__`)
    and a 307 match without an external entity declaration
    (`<!ENTITY x SYSTEM|PUBLIC "…">`; an Illustrator SVG's internal
    entities matched the old test) stay challenge_v2. 416 skips a PUT /
    PATCH on a cPanel Web Disk host (`webdisk.<domain>`, under the same
    gates as the panel proxy hosts: proxysubdomains on, tenant override off),
    the customer's own WebDAV upload, as it skips Nextcloud's `/remote.php/`.
    A 307 block also covers a DOCTYPE naming an external DTD by SYSTEM.
  - The held block rules (303, 307, 416) now run after every armed block
    rule, so a request that also carries an armed payload keeps that rule's
    ban and alert.
  - 10019 (TranslatePress id lookup, CVE-2026-19632) is armed: 87 hits in a
    week, all from datacenters, none from Greece or a home network.
    `RULE_10019 = 0` holds it again.
- **`attack on` now arms the vhost's challenge, holds for a TTL and survives
  a reload** (`cfm webtop attack on <vhost> [--ttl 6h]`, the cfm-admin
  Under-Attack toggle, the `vhost/attack` API).
  - What:
    - when no manual challenge covers the vhost, `attack on` arms one for
      the same window (reason `under_attack`, the node's default tier);
    - every override holds for a TTL: the call's `ttl`, else
      `UNDER_ATTACK_OVERRIDE_TTL` (default 6h). A cPanel user's override
      also defaults to 6h now (it was always 24h), and can be set up to 24h.
      The challenge it armed expires with it;
    - it is saved to `/var/lib/cfm/webdetector_attack_overrides.json` and
      restored after a `detectors.conf` save, a reload or a restart;
    - the challenge it arms follows the vhost's tier pin (a v1 pin gives a
      v1 challenge); with no pin it gets the node default. A pin set
      afterwards does not change it, nor does a second `attack on`: use the
      cfm-admin Tier picker. The reply and the CLI show the tier visitors
      actually get;
    - when a manual challenge you set yourself already covers the vhost, it
      stays as it is and the override is cut to its expiry at that moment
      (`ttl_clipped`): to hold it longer, extend the challenge and run
      `attack on` again;
    - refused: a wildcard host, and `attack on` for a vhost in `cfm.allow`
      (it could not be challenged);
    - `attack off` removes only the challenge its `attack on` armed (so does
      a `cfm.allow` bypass of the vhost). A manual challenge you set yourself
      stays, even one you gave the reason `under_attack`. An exclude or ignore no longer ends an `attack on` early: the
      challenge it armed wins over them, like any manual challenge.
    - a reload sends no second "under attack" alert, and one right after
      `attack on` (before its first alert) no longer loses it.
  - Why: before, `attack on` challenged nobody by itself (a second command
    was needed), an admin override never expired, and any config reload
    dropped it without a word.
  - The detector's automatic entry still arms nothing.

### Security
- **cfm-admin logins: goauth updated to its audited release.** The session
  library behind the cfm-admin login was audited and fixed. What changes on a
  node:
  - **Changing a password, deactivating or deleting a user ends that user's
    open sessions** within a few seconds (`cfm auth user ...` included).
    Before, a session stayed valid until
    it expired (8 hours), so a stolen one survived the password reset meant
    to stop it. The tab you change your own password in stays logged in.
  - **Starting a TOTP enrollment no longer switches MFA off.** It used to, at
    once and without asking for anything, so an open session was enough to
    remove someone's second factor. The new authenticator now replaces the
    old one only when its code is confirmed, and Settings asks for the
    account password to start (not needed in the 10 minutes after an MFA
    login).
  - **An authenticator code works once**, and MFA codes are limited to 5
    tries per user per 15 minutes. Right after enrolling, log in with the
    next code, not the one used to confirm.
  - **The password change in Settings is rate limited**
    (`/api/v1/me/password`): wrong current passwords back off, throttle and
    lock, by the login's rules but counted separately, so a locked login
    does not stop a logged-in owner from changing the password. It had no
    limit. Settings also no longer posts the passwords to a second URL that
    was not an API endpoint.
  - **TOTP enrollment start answers `409` while
    `AUTH_MFA_LOGIN_VERIFY_ENABLED` is off.** With that switch off an
    account with TOTP cannot log in, so enrolling would lock its owner out.
    The MFA rollout checklist now says the same about the switch's rollback.
  - **The TOTP secret no longer leaves the node during enrollment.** The
    Settings page drew the enrollment QR code by sending the `otpauth://`
    URI, which contains the secret, to `api.qrserver.com`, on every
    enrollment. The QR is now made by the daemon and sent with the
    enrollment answer; the page contacts no other host. **Anyone who enrolled
    an authenticator through Settings before this release has had that secret
    sent to a third party: re-enroll those accounts** (Settings → Start
    enrollment; the old authenticator works until the new one is confirmed).
  - Login no longer shows by its response time whether a username exists.
  - Session tokens are stored hashed in the auth database. Open sessions
    survive the upgrade; a downgrade to an older package logs everyone out,
    and so does running `cfm auth ...` from the new binary while the old
    daemon is still up (a package upgrade restarts it, so this needs a manual
    binary swap).

### Removed
- **`AUTH_MFA_TOTP_ENROLL_ENABLED` and `AUTH_MFA_TOTP_PILOT_USERS` are retired.**
  They were meant to keep TOTP enrollment off, or limited to pilot users,
  during the MFA rollout. The check matched `/mfa/totp/enroll/*` while
  enrollment is served at `/me/security/mfa/totp/enroll/*`, so it never
  applied: enrollment has been open to every cfm-admin user on every node,
  including those with `AUTH_MFA_TOTP_ENROLL_ENABLED = false`. Nothing changes
  in behaviour. The keys are still accepted in `cfm.conf` and ignored, the
  daemon logs a note at start when either is present, and they are gone from
  the reference config. `AUTH_MFA_LOGIN_VERIFY_ENABLED` is unchanged.

### Fixed
- **Two challenge false positives from the 2026-11-17 tier review.**
  - Rule 701's `SSRF_DWORD_IP` fired on any 10-digit number after `://`, so a
    shop admin searching `https://4932498770` (a phone number pasted into the
    WordPress link box) was challenged. It now fires only on a value an IPv4
    address can be (≤ 4294967295).
  - Rule 601 (control characters) challenged the WordPress Optimization
    Detective beacon (`…/optimization-detective/v1/url-metrics:store`, the
    Performance Lab plugin), which visitors' browsers post on every page
    (enateam.gr, Greek visitors, all week). That route is no longer read by
    601; other routes on the same site still are.
- **`cfm realip` now reads nginx per site, so cPanel ea-nginx nodes are
  judged correctly.** nginx takes the client from each `server{}`'s own
  `set_real_ip_from` list when it has one, and cPanel's ea-nginx gives every
  vhost one (`cloudflare.conf`, Cloudflare's ranges only). The check read only
  the http-level settings. On earth it warned "logs 127.0.0.1 for every
  visitor" while the sites logged real IPs, because Imunify360's
  `server-includes/imunify360-webshield.conf` trusts 127.0.0.1 in every site
  block. Worse, `cfm realip fix` would have written an http-level file that
  reaches no vhost and turned the check green. Now each site `server{}` must
  trust the edge (`servers` / `untrusted_servers` in `edge_health`
  evidence). On cPanel the fix writes `/etc/nginx/conf.d/server-includes/cfm-realip.conf`,
  which every site block includes. Elsewhere, when every untrusted block keeps
  its own list, it names those blocks and leaves the change to the operator
  instead of writing a file that changes nothing. cPanel's proxy-subdomain
  blocks (`cpanel.` / `webmail.` / `whm.` ...) proxy to cpsrvd and are
  reported but not counted. On earth they are where 127.0.0.1 shows, in
  ea-nginx's own log only.
- **Edge: a cert name the daemon dropped is no longer served until a
  reload.** The edge's per-worker cert store only ever added names from the
  sslcollector list. When AutoSSL replaced a new account's cPanel self-signed
  placeholder (`dom` + `www.dom`) with a wildcard (`*.dom` + `dom`), the
  stale `www.dom` entry stayed, and an exact name outranks a wildcard:
  `www.` kept serving the self-signed cert until the edge was reloaded
  (spoolbox.gr on rigel, 2026-11-17, while `cfm ssl dump` showed the right
  cert). A list now replaces the store, but only a list the daemon marks
  complete. A list missing a cert the daemon could not read is merged as
  before, as is a list under two thirds the size of the last one taken; that
  shrink is taken only if it lasts an hour. A name whose new PEM is missing or
  does not parse keeps its old pair. An error loading the snapshot, or a
  `/stats` answer that is not a JSON object, no longer stops a worker from
  ever fetching or polling again.
- **sslcollector: a cert whose key file is missing is no longer indexed, and
  a cert file with no PEM in it no longer crashes the daemon.** A dangling
  Virtualmin `ssl.key` symlink was indexed, then left out of every list the
  edge fetches, so every list was marked incomplete and the edge could never
  drop a stale name on that node. A non-PEM cert file made the cert scan
  panic. A cert or key caught mid-rewrite during a scan now keeps its
  previous entry for up to 10 minutes instead of leaving the list at once,
  so the edge does not drop that site's cert while it is being renewed.
- **No CFML-OBS-004 (ptrace) alerts for a tenant's own `killall`.** Like
  `pgrep` and `pkill`, `killall` reads `/proc/<pid>/stat` for every process
  it scans, and each read raised OBS-004 (`ptrace=read sameuid=1`). It
  showed up on orion the minute cfm-lsm first attached there. An attach
  still reports, whatever the comm.

## 2026.11.16

### Fixed
- **cfm-lsm runs again on CloudLinux 8 (lve 4.18).**
  - What: on earth, mars, orion and virgo cfm-lsm attached no policy at
    all. It retried every 30 minutes with `pin link
    …/cfm_bpf001: perf event ioctl pin: not supported`, while
    `cfm lsm status` showed every policy as "would-attach".
  - Why: CFML-BPF-001, CFML-EXEC-007 and CFML-EXEC-008 attach to syscall
    tracepoints. A kernel without BPF perf-event links (upstream 5.15) gets
    an ioctl attachment that cannot be pinned, and one failed pin rolled
    back the whole load.
  - Now: those three policies are reported unavailable on such a kernel,
    like CRED-002/003 already are there, and the rest of cfm-lsm attaches
    on the next auto-enable try. No operator action is needed. Kernel
    module loads remain covered by kernsec.
- **Far fewer CFML-OBS-004 (ptrace) mails from tenants listing their own
  processes.**
  - What: `pgrep`, `pkill`, `pidof` and `cloudlinux-stat` (CloudLinux's
    per-user statistics tools) no longer raise OBS-004. Each read of
    `/proc/<pid>/stat` goes through the kernel's ptrace check, so one
    tenant's `while pgrep …; sleep 20` loop sent ~150 mails a day from
    rigel, and the CloudLinux statistics tools ~800 alerts a month from
    titan. All are same-uid reads of the tenant's own processes.
  - How: the OBS-004 comm allowlist (with the existing `ps`, `cpanel`,
    `cpapi2`, `uapi`, `cloudlinux-cli-`, `lve_suwrapper`) now ships in
    the binary, scoped to OBS-004 only. Until now it lived only in the
    reference `lsm.conf`, which an upgrade never replaces. A PHP worker
    (`lsphp`) reading a sibling still reports.
  - Also: a comm match now only hides a ptrace READ. An attach
    (`ptrace=attach`) always reports, whatever the comm, so a webshell
    that renames itself `pgrep` or `ps` can't hide a real attach. This
    includes your own `allow_comm` lines: to silence a known attach (you
    gdb'ing a tenant's worker), use `exclude_user` for that account.

## 2026.11.14

### Changed
- **A manual vhost challenge is armed at v2 unless you say v1.**
  - What: `cfm webtop challenge add <vhost>` without `--rung` now arms
    ChallengeV2, the same page with the humanity check at verify. So do the
    cfm-admin Tier picker and the customer panic button on their new
    "Default" option, the live view and the bots page. `--rung v1` (or
    Standard) still arms the plain challenge. Arming a vhost without a tier
    keeps the tier of a manual challenge already on it (or on its apex, for
    a `www.` host).
  - Why: the automatic vhost challenges have run at v2 since 2026-10-22. A
    fleet read on 2026-11-14 (11 729 rejects, 13 nodes) found the rejects
    under manual v2 arms all from one farm fingerprint, and no reject from a
    likely human.
  - Wildcard hosts (`*.example.com`) stay v1, because the v2 check cannot
    match them yet; the CLI and the page say so.
  - Knob: `[webdetector] CHALLENGE_V2_MANUAL = 0` turns the default back to
    v1 node-wide. It is also v1 while `CHALLENGE_V2_PASSIVE = 0`.
- **WAF rule 102 (`rule_long_path_segment`) now challenges at v2**, the last
  WAF rule still at the plain challenge.
  - Why it was held: a JS-rendering crawler such as Googlebot could fail the
    v2 check and be refused.
  - Why that no longer applies: Google's and Bing's crawlers never reach the
    WAF, since the bypass list skips it for them, in a lockdown too. Over 7
    days the rule fired 11 854 times on 4 nodes and none of those hits came
    from a crawler range. Most of them (11 757) were Amazonbot looping on
    one Joomla feed URL, which the plain challenge already stopped.
  - To revert on a node: `rule_long_path_segment = "challenge"` in
    `/etc/cfm/cfm_waf_config.lua`.

## 2026.11.13

### Added
- **WAF: PHP code in the query string (rule 332, `WAF_RCE:PHP_ARGS_*`) and
  a PHP file posted as the raw body (rule 416,
  `WAF_PHP_WEBSHELL_BODY:BODY_IS_*`), both logonly.**
  - The case: on 2026-11-12 a Joomla site on earth (dmkomotinis.gr, Fabrik
    3.10) was compromised through the listfilter eval
    (`…[value]=$h=fopen('up.php','w');fwrite(…)&…[eval]=1`). The dropper it
    wrote took yavuzshell.php as `application/octet-stream`, at six paths.
    Every request reached the origin with nothing logged at the edge: rule 320
    reads only shell / jndi markers, the body scanners never read the query,
    402 reads multipart only and 404 reads textual types only.
  - Rule 332 fires on a call to a file writer or code runner together with
    something only PHP source carries, in the same parameter: `<?php`, a
    superglobal, a decoder, `$x=`, `;return`, `'.'` or a `chr()` chain. It
    reads the query only, not a POST form.
  - Rule 416 fires on a non-multipart POST, PUT or PATCH body that opens
    with a PHP tag, whatever its Content-Type says.
  - A 7-day read of the edge logs on all 8 edge nodes found about 150
    matching 332 requests, from more than 10 exploit families (Fabrik,
    ThinkPHP, SPIP, Magento, ThinkCMF, Drupal, pearcmd), most of which reached
    the origin, and no legitimate one. A static page linking
    `?v=<?php echo rand(…); ?>` is why a PHP tag alone does not count.
  - Logonly through a burn-in of a few days, then promote. A block promotion
    of 332 arms `WAF_RCE`'s autoblock. See `docs/waf.md` "Rules 332 and 416".

### Fixed
- **A blocklist feed apply no longer unblocks the feed's addresses while it
  runs.** Each set was replaced by a flush and then batches of adds, each its
  own nft run (exec engine) or netlink transaction (nftlib), and every feed
  apply rebuilds the eight unions the base rules drop on
  (`block_ext_v4_hosts`, …) the same way. So on every hourly apply of every
  feed those unions were empty and then partly filled for the whole refill:
  ~4.5 s for a 1M-address set on the exec engine, with MYBLOCK at ~215 000 on
  virgo and growing. Both engines now replace a set in ONE transaction (the
  flush and every add commit together), so a packet sees the old content or
  the new. Measured in a netns as root, 1M addresses: ~3 s per set on either
  engine, and a prober asking the kernel ~300 000 times
  during the apply never found a kept address missing (the old code: 53 901
  misses at 200k). nft and nftlib raise their netlink socket buffers for the
  batch (nftlib also its receive buffer: a million-address batch's ACKs
  overflowed it), so even 2M addresses fit. A batch too large for its socket
  buffer (in an unprivileged user namespace), or an exec-engine run that hit
  its deadline, changed nothing, and the old batched write runs, logged (`too
  large or too slow for one transaction` / `one batch failed`). Any other
  refusal (an element nft or the kernel rejects, overlapping intervals) now
  leaves the set with its old content and logs the error (nftlib also returns
  it from the feed apply; the exec engine's feed apply ignores set-write
  errors, as before): the batched write would flush the set and stop at the
  bad entry, unblocking every address after it until the next apply.
- **An unchanged feed apply no longer rewrites the unions.** The exec engine
  now skips a permanent set whose content is the same as at its last write,
  as nftlib already did (1M addresses: ~1 s for the whole apply, from ~6 s).
  Both engines skip only while the kernel still holds one of the set's
  elements (a single netlink lookup, ~0.1 ms): nftlib's skip trusted its
  memory, so after `cfm reset` from the CLI, which recreates the table in
  another process, an unchanged feed left its union empty until the feed
  changed.
- **`cfm search` / `cfm which` / unblock lookups no longer time out on a node
  with a large fleet feed.** To find the table's sets the nft lookup dumped the
  whole `inet cfm` table, every set element included, with a 5 s deadline.
  With MYBLOCK at ~215 000 addresses that is megabytes of JSON, and on virgo
  (nft 1.0.4, a feed apply in progress) it ran out of time: the nft source was
  reported as "cannot read … (maybe needs sudo?)". The lookup now lists only
  the sets (`nft -j -t list sets`: 5 ms with a 1M-address feed, against 32 s
  for the table) and reads the manual sets before the feeds. A feed is read
  once, from its union (`block_ext_v4_hosts`, the set the rules drop on), and
  named after the feed; its per-feed copy is read only when a union holds
  several feeds. Each dump ends at the caller's deadline, or after 15 s.
  Measured, a manual ban plus one feed: 1.5 s at 215k addresses, 5.5 s at
  500k, 17 s at 1M (near the limit).
- **An IP lookup no longer dumps the fleet feeds: it asks the kernel.**
  `cfm which` / `cfm search`, the unblock report and the agent's locate
  found an address by dumping every set with `nft -j list set`, so at 1M
  addresses one feed's dump (~16 s) passed its 15 s deadline and the answer
  came back "incomplete". `nft get element` is no better (it loads the whole
  set first). For an IP (not a CIDR) both engines now send single-element
  netlink gets (`NFT_MSG_GETSETELEM` without a dump), which the kernel answers
  with one lookup in the set, a few more for an interval set's prefix or
  range. Measured in a netns as root, a manual ban, a 1M-address feed and
  50 000 prefixes: 4.8 ms on the exec engine, 1.1 ms on nftlib. The answers
  are the dump's (same set, prefix or range, feed name). A CIDR query is an
  overlap no lookup answers, so it still dumps its family's sets, and so does
  a set the kernel cannot answer for. That includes an IP that sits exactly
  where an interval ends and another may start: a 4.18 kernel can answer
  "absent" there (it stops at the end element sharing the key). An
  interval's end takes several gets, so each address in an interval set is
  looked up between two reads of the ruleset generation and looked up again
  (up to five times, with a short pause) if a transaction committed in
  between, such as a feed replace or any ban; an answer never mixes old and
  new content.
- **A set the lookup could not read is reported, not taken as "not there".**
  A set dump that failed or timed out was skipped silently, so an IP in that
  set (a MYBLOCK ban, say) read as not blocked. The answer is now marked
  incomplete and names the set.

## 2026.11.11

### Fixed
- **The notifier no longer rewrites its whole history on every alert.**
  Each alert re-read, re-parsed and rewrote `notify.log.jsonl` (up to
  100 000 rows, `MAX_ENTRIES`) to apply the retention. On mars that took 60%
  of the daemon's CPU on 2026-11-11, once `login_bruteforce` was armed, and
  it slowed every other handler (`GET /nginx/edgeban` among them). The
  retention now runs every 5 minutes as before, and on an alert only every
  1 000 rows (a storm), so the file never outgrows `MAX_ENTRIES` by more than
  that. A prune itself reads only the time of each row: 565 → 342 ms for
  100 000 rows.
- **The edge no longer 429s Meta's ads crawler on a landing page's css/js.**
  `meta-externalads` renders an ad's landing page and fetches every
  stylesheet and script on it at once (~80 on a WordPress page). Those
  counted against the crawler page budget (10 r/s, burst 100): on one shop
  it 429'd 395 of 1 946 such fetches in a day (2026-11-11), and Meta reads a
  landing page that fails to render as unavailable. A Meta crawler's css,
  js/mjs, source-map and font requests now take the image budget (50 r/s,
  burst 200, 30 connections) with the images; pages keep theirs. A script
  path (`/x.php/a.js`) is still a page. A test keeps every extension the
  static-asset location serves on that budget. The 30-connection cap is now
  shared by images and css/js: watch `limit_conn_status=REJECTED img=1` in
  `throttle.log` after deploy.

## 2026.11.10

### Added
- **The challenge log and history rows name the software-renderer family.**
  When a software renderer is detected, `sig=` (and `payload.sig` on the
  history row) carries `rf:` with a short family name (`swiftshader`,
  `angle-swiftshader`, `llvmpipe`, `softpipe`, `swrast`, `mesa-offscreen`),
  never the raw renderer string. Scored by nothing; it lets the weekly reads
  tell automation stacks apart. A solve that reports only a software
  renderer now has a `sig=rf:…` field where it had none. Stripped for scoped
  (cPanel) callers with the rest of `sig`.

### Changed
- **ChallengeV2: a desktop Linux UA on a software renderer now scores +20
  (`linux_sw`).** The convicted farm fingerprint `c28caa00` stopped faking
  its device and passed v2 at exactly hs 90 (an X11 Linux Chrome UA,
  SwiftShader, no input): 85 684 farm passes on four nodes in the 3-10 Nov
  read, against 23 Greek/Cypriot consumer-ISP solves, all on the farm's own
  fingerprints. That profile now scores 110 and is rejected wherever v2 is
  armed. Linux with a software renderer and real input scores 80 and still
  passes, and Windows/Mac scores are unchanged (an RDP user's 90 still
  passes). The real-input rescue is unchanged: a Linux visitor with a
  software renderer, a window size reported as 0×0 and real mouse input
  scores 120 but is rescued exactly as before (the rescue now takes a score
  of at most 100, not counting linux_sw's share, so at most 120 for a
  desktop Linux solve), so at the default fail score (any
  `CHALLENGE_V2_FAIL_SCORE` above 80) `linux_sw` never fails a solve on its
  own. It never fires for Android, ChromeOS, a mobile UA, smart TVs,
  Chromecast, Tesla or the Puffin browser (an Android tablet in desktop-site
  mode sends a Linux UA; only its hardware GPU keeps it clear), and counts
  once with the other device-claim tells. Unarmed vhosts show the farm profile as
  `would_v2` at 110. The farm can switch to a Windows UA, so this buys time
  rather than closing the gap. Kill switch: `[webdetector]
  CHALLENGE_V2_HW_TELLS = 0` (turns off `linux_sw` with `mobile_hw_lie` /
  `mac_hw_lie`).

### Changed
- **`login_bruteforce` is armed, at 4 failures per site or 3 sites.** After
  the 6-10 Nov dry run (~2 600 would-be bans on eight nodes, nearly all
  datacenter networks) it now bans for 3 days and reports to cfm-web
  (`DRY_RUN = 0`, also for a written section without the key). The
  thresholds go from 5 and 5 to 4 failures on one site, or failures on 3
  sites, within an hour: botnets were sending 4 tries per address, or trying
  3-4 sites, to stay under 5. On virgo, mars and titan's Apache logs that
  catches 17-42% more addresses, none Greek or Cypriot. The GR/CY tier
  (10 minutes, not reported) is unchanged; it adds Cloudflare, below. In an IPv6 /64
  with several failing addresses, the worst one needs more than half of `SITE_FAILS` on
  one site (3 of 4), or the alert only logs: two colleagues who mistyped
  twice each are not banned, and an attacker alternating two addresses is
  banned on its second round. A garbled `DRY_RUN` (`y`, `dryrun`) keeps the
  dry run, with a warning. A `detectors.conf` that writes `DRY_RUN = 1` or
  its own thresholds keeps them: a node whose `detectors.conf` came from
  the previous reference config is NOT armed until it is edited (and its
  leniency block needs Cloudflare's 13335 added, below).
- **A banned client behind Cloudflare is now blocked at the edge.**
  `[webdetector] EDGE_BAN_MODE` defaults to `enforce`: the edge answers 403
  to a proxied client the web detectors, the WAF autoblock, modsec,
  `login_bruteforce` or a manual ban have banned, which the nft drop never
  sees. It used to only log `would_block edge_ban`: mars had 171 such
  addresses on 2026-11-10, none Greek or Cypriot. `EDGE_BAN_MODE = log`
  brings the logging-only mode back; a `detectors.conf` that writes `log`
  keeps it. Any other value (a typo such as `logonly`) logs only, with a
  warning in the daemon log, rather than enforce.
- **`login_bruteforce`: a Cloudflare WARP address gets the soft tier.** A
  WARP egress address is shared by many people, so a brute forcer on it now
  gets the 10 minute local ban, reported nowhere, instead of a 3 day fleet
  ban that would lock every WARP user out. The first day's dry run had 12
  WARP alerts. AS13335 is added to `[login_bruteforce.leniency] MATCH_ASN`.
  A `detectors.conf` with its own leniency block needs the same edit.

### Fixed
- **`GET /nginx/edgeban` no longer takes 100+ ms.** Each time the edge ban
  list was rebuilt, every ban was checked against every nft allow net in
  turn. With ~23 000 bans that took 55-150 ms per rebuild on mars, orion and
  virgo, ~800-1 700 "slow handler" lines a day. The allow nets are now
  merged into sorted ranges and searched, and the list is no longer sorted
  for nothing (190 ms → 3 ms with 1 000 allow nets). The rebuild also runs
  less often: a ban that expires no longer triggers one (the edge drops it at
  its expiry by itself), and neither does the 2 minute reconcile with nft
  when it changed nothing.
- **`login_bruteforce`: a forgotten password no longer adds up to a ban.**
  A lostpassword or register form shown again (an unknown user or address)
  counted as a full failed login, so a customer who failed twice and then
  tried four addresses for a reset reached the threshold (a Greek customer on
  gacbp.com, 2026-11-08, during the dry run: armed, the GR/CY leniency would
  have made it 10 minutes, and a customer abroad would have had 3 days). Such a form now counts as a third of a
  failure on the one-site rule: that customer is at 3.3 of the 4 needed. A
  brute forcer hiding its logins behind `?action=lostpassword` (the edge
  cannot tell the two apart) is still banned, at three times the tries (12).
  A site counts toward the many-sites rule with one failed login or three
  forms, and in an IPv6 /64 the address banned, and the ambiguity check, weigh
  forms the same way.
- **cPanel users see their site's traffic.** CFM opened from cPanel
  covered only the domain names in `/etc/userdatadomains` (`trimel.gr`), but
  a site's traffic is logged under the name it was asked for, nearly always
  `www.trimel.gr`. On qualityweb such a user saw 13 of 41 907 requests to
  their own site: empty stats, and no forensics for `www.`. The token now
  also holds every domain's `www.` name and its cPanel ServerAlias names. A
  name outside the account's own domains is never added. Users get it the
  next time they open CFM from cPanel.
- **cPanel users no longer land on admin pages.** A cPanel user who reached
  the Dashboard, Alerts, Web Bots or another admin-only page saw empty cards
  saying "admin token required". Those pages now send a cPanel user to Vhost
  controls. Admin access is unchanged on every route: hostname, port, edge
  proxy, WHM SSO and cfm-web SSO.
- **An admin who opened a customer's cPanel CFM stays admin.** Staff who
  logged in to a customer's cPanel (WHM "log in as user") and opened CFM there
  got that customer's cookie on the node's host, for every port. Its rolling
  renewal kept it alive, and the admin's own tab (`hostname/cfm-admin` or
  `hostname:<port>/cfm-admin`) then browsed as that customer until logout. The
  admin login now takes precedence over it. Calls from inside the cPanel
  frame keep the customer's identity.
- **Google Merchant Center feeds are no longer challenged.** Its feed fetcher
  (`google-xrawler`) got the challenge page instead of a shop's product feed
  whenever the vhost was under a challenge. Its addresses have no reverse DNS,
  so the Googlebot FCrDNS rules could never exempt it. The shipped
  `webdetector_challenge_exclude.txt` now skips it from Google's own network
  (AS15169) only. The same UA from anywhere else is still challenged.
  `/etc/cfm/webdetector_challenge_exclude.txt` is a config file: a node that
  edited its copy keeps it on upgrade. Add the line by hand there:
  `asn=as15169; ua=*google-xrawler*; action=skip`. Then save
  `/etc/cfm/detectors.conf` (`touch` is enough) or restart cfm: the exclude
  file is read only when the detectors config reloads, not on its own
  change.
- **Meta crawlers get a larger page budget than the SEO bots.** The edge's
  crawler throttle gave facebookexternalhit, facebookcatalog,
  meta-externalagent and meta-externalads the SEO bots' 5 pages/s per site.
  Meta checks a shop's product pages in waves: 2 563 pages in one minute on
  one shop (2026-11-09), from 737 Meta addresses. About 3 900 product pages
  got `429 Too Many Requests` that day. Meta's crawlers now have 10 pages/s
  per site, burst 100. The SEO bots keep 5/s. The 30-connection cap and the
  60/min per-IP limit are unchanged, and images keep their own 50/s budget.
  Expect fewer 429s, not none: a wave of 200 pages a second is still cut,
  and Meta retries the rest later. On a slow site the cost is higher: at
  1 s a page, 10 pages/s keeps about 10 PHP workers busy (the 30-connection
  cap is the bound). The edge error log names the page zones
  `meta_seo_host_rps` / `meta_fb_host_rps`; it used to be `meta_host_rps`.

## 2026.11.09

### Fixed
- **Facebook catalog imports no longer fail on product images.** The edge's
  crawler throttle gave a Meta crawler's image requests the same 5
  requests/s per site as pages. This covers facebookcatalog,
  facebookexternalhit, meta-externalagent and meta-externalads. A catalog
  crawl therefore got `429 Too Many Requests` on most of a shop's images:
  about 89 000 rejected image fetches in an hour on one shop (2026-11-09),
  and the import failed. A Meta crawler's images
  (`.jpg/.jpeg/.jfif/.png/.gif/.webp/.avif/.ico/.bmp/.tif/.tiff`) now have
  their own budget per site: 50 requests/s, burst 200, 30 connections. They
  have no per-IP limit. Everything else keeps the old limits:
  - pages;
  - `.svg` and `.php/…/x.jpg` paths;
  - the SEO crawlers' images (AhrefsBot, SemrushBot, …).

  Images keep a limit because the edge cannot tell a file on disk from one
  PHP renders, whether a resizer or the app's 404 handler. `throttle.log`
  lines now carry `img=1` when the image budget applied and `img=0` for the
  page budget. They also carry `limit_conn_status`, so a connection-cap
  reject reads `REJECTED` there. An origin's own 429 reads `REJECTED` in
  neither status field. The
  change is in both `openresty.conf` and `angie.conf`, and a node gets it
  with the new edge conf.

## 2026.11.06

### Added
- **WordPress brute force can be banned (`login_bruteforce`), in a dry run
  first.** It ships `DRY_RUN = 1`: every would-be ban is logged
  (`cfm.detectors.log`, the alert log with `mode=dryrun`, with the site, the
  rule and whether GR/CY leniency applied), once per client per hour, and
  nothing is banned or reported until `DRY_RUN = 0` in `[login_bruteforce]`. Until now nothing
  stopped it: of the 314 addresses the shadow `login_spray` signal flagged in
  one day on seven nodes, 11 were blocked by anything else. A client address is
  banned for 3 days, and reported to cfm-web, after either of these within an
  hour:
  - 5 failed logins on one site;
  - failed logins on 5 different sites, one each is enough: a proxy pool
    tries once or twice per site per address.

  Greek and Cypriot addresses, and the Greek / Cypriot ISPs' networks
  (OTE, Vodafone, Wind, Nova, Cyta, GRNET) wherever the geo database places
  them, get a 10 minute ban, reported nowhere (customers know
  unblock.myip.gr). Never banned:
  - a site's own tool, for its failures there (it already succeeded on the
    site at least as often as it failed);
  - a 2FA login: the password step (the origin sets the login cookie and
    clears it in the same answer) no longer reads as a failure (Two Factor
    0.8+, which sends no cookie on that step, is covered by the success that
    follows, below). A login hidden behind
    `?action=lostpassword`, and one with `?reauth=1`, still counts when it
    fails;
  - a password reset that went through, or a protected post's password;
  - an answer WordPress did not write (no `wordpress_test_cookie`): a
    server-level captcha or bot page answered nearly every login on
    speedhost, real users' too;
  - a failure the next success takes back: a success takes back up to 3 of
    the same address's failures on that site within 15 minutes, and a
    failure counts only once it is 2 minutes old, so 2FA users (a mistyped
    code, five client sites opened at once) are not banned;
  - an ambiguous shared IPv6 /64 (several addresses, one failure each): dry
    run;
  - a reverse proxy or WAF CDN address (`ALLOW_ASNS`: Sucuri, Imperva,
    Fastly, Akamai, StackPath, Bunny; and Cloudflare's own proxy ranges),
    which stands for every visitor of the sites behind it;
  - private, loopback and CGNAT addresses.

  An address with no geo record only logs "would block", since the GR/CY
  leniency needs its country. IPv6 counts per /64 and bans the /64's address
  with the most failures. The ban is also recorded
  for the edge, for a client behind Cloudflare (enforced there with
  `EDGE_BAN_MODE = enforce`). Every node runs it
  with the upgrade, without a `detectors.conf` change: the section and its
  leniency are built in until the operator writes their own
  `[login_bruteforce]`. Only WordPress logins
  are read today. Each ban is a notifier event: route
  `[detector "login_bruteforce"]` in `notify.conf` if mail is too much.

## 2026.11.05

### Fixed
- **Shadow `login_dirty_success` rows no longer flag a site's own tool.** In
  the first fleet day most rows came from one site's own tool that logs in
  all day and fails now and then (mygreecetours.org: 655 successes, 155
  failures). A success is no longer reported when the client had failed on
  that site and already succeeded there at least as often. Successes alone
  excuse nothing: a credential-stuffing hit before the spray flags the
  client is still reported when the account is used again. The first success
  on a site, and the first after a run of failures, are still reported. A
  password-reset request excuses nothing: anyone can send one before a
  spray. Sites with only successes no longer count as failed sites in
  `login_spray`, and never keep a failure from being counted: a client that
  logged in on many sites still has a later slow spray seen.

### Fixed
- **The login field now sees the site's redirect over HTTP/2 and HTTP/3.**
  On an HTTP/2 or HTTP/3 answer, nginx consumes the `Location` header before
  the log phase. Most real browsers log in over h2/h3 (813 of 895 login
  redirects on orion), so for them a hide-login plugin's failure redirect and
  a canonical redirect to another host were invisible: the failure read as
  unknown. The edge now reads the origin's own `Location`
  (`$upstream_http_location`, the access log's `uloc=`). A redirect counts
  as "to another scheme" against the scheme the site itself was told
  (`X-Forwarded-Proto`): behind Cloudflare Flexible every https redirect
  used to read as one. One more case is now a failure, not unknown: a
  plain-http login that the site answers with an https redirect on the same
  host whose query differs from the request's. A hide-login plugin on an
  https site sends exactly that; a canonical redirect keeps the query.

### Fixed
- **A canonical redirect of a WordPress login is no longer counted as a
  failed login.** The login outcome took any redirect to a login page as a
  failure. A site's own 301/308 (http to https, www) moves the login POST
  before WordPress reads it, and the first day's corpus showed one counted
  as a failure. Only a 302/303 back to a login page on the same scheme and
  host (what WordPress and hide-login plugins send) is a failure now. The
  edge tells the daemon whether a redirect leaves the request's scheme or
  host (never the host itself), because Apache's `[R]` redirect is a 302.

### Added
- **The edge now reports how each login POST ended.** Status alone cannot
  tell: a hide-login plugin answers a failed `wp-login.php` post with a 302 to
  `?login=failed`, exactly like a success. A login POST (the WAF's list of
  login endpoints: WordPress, Joomla, Drupal, Magento, OpenCart, `/login`, …)
  now sends the web detector one more field: whether WordPress set its
  logged-in cookie, plus the response's cookie NAMES and redirect path (never
  a cookie value, a host or a query string). The daemon turns that into an
  outcome (`ok`, `fail`, `na` for another wp-login action such as a password
  reset, or unknown), only for answers that came from the site itself. Nothing counts or blocks on it yet: the new MCP tool
  `auth_corpus` (`/api/v1/webdet/auth-corpus`, admin-only) groups what was
  seen by shape, so each CMS's success and failure answer can be read from
  real traffic before the login brute-force signals are built on it
  (`docs/webdetector-signals-v2.md`). Every other request's log line is
  unchanged.
- **Shadow login brute-force signals.** The web detector counts the failed
  WordPress logins that field reports and writes three new detection history
  rows, without blocking or alerting anything:
  - `login_spray`: one IP (an IPv6 /64) failing on 3+ sites (10+ tries in
    24 h), or 20+ tries in an hour, or 50+ in a day. This is the slow,
    cross-site sprayer that rule 501 (8 tries in 20 s) never sees.
  - `login_spray_net`: a /24 (IPv6 /48) with 5+ such IPs, or 30+ failures
    from 5+ of its IPs, i.e. a proxy pool sending one or two tries per address.
  - `login_dirty_success`: a successful login from such an IP or network,
    or after 10+ failures of its own on that site.

  A site is a registrable domain (an owner's `www.` and `staging.` are one).
  Crawlers and CDNs on the bypass list are not counted, and rows are
  budgeted (30 a minute per type), so a botnet cannot flood the history.
  Spray rows name no site, only counts. Query them with
  `detection_history type=login_spray node="all"`. The thresholds and the
  action (a ban or an edge deny) are decided after a fleet read. Kill
  switch: `[webdetector] LOGIN_SIGNALS = 0` (`docs/webdetector-signals-v2.md` §3).

### Fixed
- **A challenge exclude keyed on the User-Agent now sees the real UA for web
  detector alerts.** The UA was taken from the last column of the sample log
  line, which on the edge's lines is the bypass flag (`0`), not the
  User-Agent, so a UA-keyed exclude never matched those challenges.

## 2026.11.04

### Security
- **New WAF rule 440 blocks a fake plugin's command call.** After logging in
  with a stolen password and uploading a plugin with a random name, the
  attacker on vol2.gr (titan) called the plugin's own PHP file with
  `?task=download&url=http://…` and then `?task=run` to fetch and start the
  payload. A PHP file under `wp-content/plugins/` or `mu-plugins/` called with
  that `task` field is now refused at the edge (`WAF_BACKDOOR`). A month of
  seven nodes' traffic held no such request outside these attacks. The ban is
  held for a burn-in (`RULE_440 = 0` by default; set `RULE_440 = 1` in
  `[waf_security]` to ban and alert), because a page can make a visitor's
  browser send `task=run`.
- **A cleared visitor can no longer post logins without limit.** Rule 501
  (8 login posts per IP in 20 s, across sites) challenges the client, but one that
  had already solved a challenge only got a log line, so it could keep
  guessing passwords from its IP. Those posts past the limit now get a 403
  until the 20 s window closes, whichever rule takes the headline. They earn no
  ban: in the last three weeks the only cleared clients over the limit were
  legitimate users.

## 2026.11.03

### Added
- **Solver-farm alerts now show who is behind the flagged fingerprint.** A
  `challenge_solver_farm` finding carries the ChallengeV2 humanity
  distribution of the solves of the cluster it flagged that PASSED the
  challenge: how many scored `hs` 0, 1–59, 60–99 and 100+, how many sent no
  humanity report (`none`) or were not scored at all (`unscored`), the five
  most common `tells` combinations and the five top countries, with the
  number of solves covered and a note when the evidence cap made it a
  sample. Solves the humanity check rejected never reach the detector, so
  under a `challenge_v2` arm this shows who got through; the rejected side
  is `detection_history type=challenge_v2_reject`. A fingerprint is shared
  by everyone on the same TLS stack, so this tells a farm from a real
  audience on the same fingerprint (on one site, half of a convicted
  fingerprint's 12 323 solves were Greek visitors at `hs` 0). It appears in
  the alert mail/log, and on the `detection_history` `solver_farm` row as
  `payload.humanity` for admin and MCP readers; cPanel (scoped) users do not
  get it. Evidence only: no threshold or decision changed.
  `challenge_cookie_discard` alerts do not carry it yet.
- **Alert log: every detector event, mailed or not, in one searchable place.**
  Each event the detectors hand the notifier (the `[CFM] host — KIND ip …`
  mails: WAF/WEB/MODSEC blocks, autoblock bans, portscans, SSH/Dovecot auth
  failures, MySQL governor, ClamAV, outbound abuse, LSM) is now also stored in
  `/var/lib/cfm/alerts.db` (SQLite, 30 days / 500k rows), whether or not a
  mail or Slack channel is configured, and whatever dedupe or a detector
  override then decides. Each row records what the notifier did with it
  (`notified`, `send_failed`, `deduped`, `notifier_off`, `no_channels`,
  `muted`, `below_severity`, `queue_full`), so "why didn't I get a mail?" has
  an answer.
  The store adds the ISO country code, the ASN number and the vhost (from the
  detector's fields or the sample line) so events can be grouped. Writes are
  batched on their own goroutine and never block a detector, and reads use
  their own pool so they never block the writer. The files are 0600. New
  admin-only `GET /api/v1/alerts` (filters, cursor paging),
  `/api/v1/alerts/summary` (`group_by=` up to three of kind/category/country/
  asn/ip/vhost/reason/severity/delivery/mode/hour/day), `/api/v1/alerts/overview`
  and `/api/v1/alerts/stats`; a cfm-admin
  **Alerts** page (category chips, filters, group-by with click-to-drill,
  sample lines); and node MCP tools `alerts` and `alerts_summary`. The
  notifier's `notify.log.jsonl` stays the per-channel delivery journal. See
  `docs/alerts.md`.

### Changed
- **Rule 328 (Log4Shell lookup forms) now challenges instead of only
  logging** (`challenge_v2`). In 30 days every 328 hit on the fleet (29) was a
  scanner sending `${jndi:` in an `X-Api-Version`, `Referer` or
  `Authentication` header from cloud IPs; none came from a customer. Only the
  Log4Shell-specific tags are enforced: `${jndi:` (in a header; rule 320
  already blocks it in the query and body), `${::-`, `${lower:` and
  `${upper:`. The tags template engines also produce (`${${`, `${env:`,
  `${sys:`, `${main:`, `${date:`, `${base64:`) stay logonly at any mode:
  `WAF_CVE` is high-risk and armed for autoblock, so a challenge for a
  logged-in customer becomes a block and a ban. The rule now resolves the
  lookups the way Log4j would (`${…:-X}`, `${date:'X'}`, `${lower:X}` give
  X) and enforces any that resolve to a `${jndi:` lookup (new tag
  `RESOLVED`): `${${env:X:-j}ndi…` with any variable-name length and
  `${${date:'j'}${date:'n'}…` were `NESTED` / `ENV` and only logged. A
  template or shell default (`${env:HOME:-/root}`, `${PREFIX:-/}usr`)
  resolves to plain text and is not a hit. Lookups nested past 8 levels are
  enforced as `DEEP` (no template nests that deep, and unwrapping further
  would be unbounded work). The classic `${${::-j}${::-n}…` reports as
  `DEFAULT_VAL` (it was `NESTED`). The rule also reports the strongest tag in
  the whole request, so a `${date:}` in the query no longer masks a `${jndi:`
  header as logonly.
_Nothing yet._

## 2026.11.01

### Fixed
- **Rule 412 (polyglot upload) no longer blocks and bans customers for
  ordinary photos.** It flagged an image whose first 64 bytes held the ASP
  opener `<%`. Those two bytes turn up by chance in about 1 in 1 000 real
  images: 307 of 301 123 on rigel, in a JPEG's quantization table or a WebP's
  size field. In 14 days every 412 hit on the fleet was a customer uploading
  product photos to WordPress. On a logged-in customer the challenge turns
  into a block, so two were banned (test-toplevel.gr on rigel, e-geoponiki.gr
  on mars). Nothing on the fleet runs ASP or JSP, so the rule now checks the
  PHP and `<script` openers only; those matched none of the 301 123 images.
  A short echo `<?=` now counts only with a PHP expression after it, the
  guard rules 402 and 432 already use, because those three bytes can also
  occur in an image by chance.

## 2026.10.30

### Added
- **`cfm realip`: the origin sees visitors' real IPs behind the edge, on every
  panel.** The edge proxies to the origin from 127.0.0.1; an origin that does not
  trust that loopback logs 127.0.0.1 for every visitor and hands PHP
  `REMOTE_ADDR=127.0.0.1`. That was qualityweb (cPanel without Imunify360, whose
  `i360.remoteip.conf` carried the trust on the rest of the fleet), reported by a
  customer. `cfm realip` shows the verdict, reading the config along the server's
  own Include chain (a `<VirtualHost>`'s or `server{}`'s setting does not stand for
  the server) and taking the origin from the :80 listener. `cfm realip fix
  [--dry-run]` writes the trust where it is missing — cPanel, DirectAdmin, Debian
  and EL Apache, DirectAdmin and plain nginx — through a config test and a graceful
  reload, rolled back on failure, trusting only the loopback and reading
  `X-Real-IP` (through the edge a local process cannot forge it). LiteSpeed and NGM get the manual step
  printed instead (CFM does not edit their config). The edge installers run it
  after deploying the edge (`CFM_SKIP_REALIP=1` skips). `edge_health` gains Check G
  (`origin-real-ip`), so `whats_wrong` warns about it. See `docs/origin-real-ip.md`.

### Fixed
- **`cfm health`'s "Origin real-IP" line no longer warns wrongly.** It missed
  Apache's `conf.d/*.conf` (Imunify360's `i360.remoteip.conf` and the new drop-in),
  warned on hosts with no edge in front at all (a DirectAdmin nginx facing the
  internet), took a LiteSpeed `useIpInProxyHeader 2` as trusted without
  `127.0.0.1T` in the allow list, and called Apache trusted with no
  `RemoteIPHeader` set (mod_remoteip then reads nothing).

### Changed
- **The edge access log records each request's size (`req_len=`).** The
  `log_format cfm` line (OpenResty and Angie) ends with
  `req_len=$request_length`, the request line, headers and body as received.
  It is there to measure which routes legitimately take bodies larger than
  the 32 KB the WAF reads, before any size-based rule. The log readers parse
  fields by name, so nothing else changes; the line is a few bytes longer.

### Security
- **New WAF rules 10027 / 10028 block the Magento "PolyShell" file upload
  (CVE-2026-48356).** An anonymous request to a cart's items API can make
  Magento write any file, a PHP shell included, to
  `pub/media/custom_options/quote/`: the file travels base64-encoded inside the
  JSON body, where no upload rule looked. On 2026-10-29 it wrote eight GIF+PHP
  shells to a Magento 2.3.7 shop on orion through the edge (they did not run:
  the directory's `.htaccess` denies them). Rule 10027 blocks a cart-save
  request (REST cart routes, SOAP cart services) that carries the
  `custom_options` → `file_info` → `base64_encoded_data` names, in any
  spelling Magento accepts (`fileInfo`, `FILE_INFO`, `\u`-escaped), in its
  JSON, XML, query or form fields: 6 h ban and a `WAF/CVE-2026-48356` alert,
  like every CVE rule. Rule 10028 refuses, with a 403 but no ban, a cart
  request the WAF could not read: a cart or SOAP body larger than it reads or
  not read, an XML entity declaration, or an encoding it cannot read; the
  same names on any other Magento API route (no file is written there) are
  only logged. The edge now reads Magento's
  SOAP bodies whatever their Content-Type, as Magento does.

## 2026.10.28

### Fixed
- **Facebook / Instagram ad clicks no longer get a blank `bad ua` page on a
  challenged site.** The challenge server refused any User-Agent longer than
  256 bytes or carrying 16+ of `;()[]{}"'<>|\`, and the in-app browsers of
  Facebook, Instagram, WeChat and TikTok carry both: a visitor clicking an ad
  while the site was under a challenge (an automatic `suspicious_vhost` one, for
  example) got `403 bad ua` instead of the challenge page (vol2.gr, 2026-10-28;
  ~4 400 such refusals of ~1 400 client IPs fleet-wide in eight days, almost
  all Facebook / Instagram in-app browsers, most on titan, rigel, mars and
  orion). The cap is now 1024 bytes, and `;()[]` no longer count as junk
  punctuation (16+ of `"'<>{}|\` still do). These clients
  now see the challenge page and solve it like any other browser.

## 2026.10.27

### Fixed
- **No more detector reload loop after a restart on an exim host that has docker
  installed.** With the docker CLI present and no postfix container, the postfix
  and dovecot sections assumed a mailcow container was still booting and forced
  a full detector rebuild once a minute for five minutes after every restart
  (qualityweb, 2026-10-27). Each rebuild started a new web-detector engine: the
  edge lost the bridge socket for a moment (decisions failed open, log lines
  dropped) and the vhost uniqIP windows emptied. A host whose own exim service
  is running no longer waits for a mail container; a mailcow host (exim stopped)
  keeps the retry.

### Added
- **Vhost lockdown: an emergency brake for a crawler storm.** A vhost
  challenge lets crawlers on the bypass list, verified good bots and
  exclude-file matches through, and nothing else at the edge reached a
  bypass-listed crawler. So a crawl from 1 300 Applebot IPs on one shop could
  not be stopped short of an nft block. A manual vhost challenge can now be
  put in LOCKDOWN: no client exemption at all on that vhost. Crawlers cannot
  solve the challenge, so they are kept out; people solve it as usual. CDN
  fetchers (QUIC.cloud), `/.well-known/` (SSL), webhook endpoints, the server
  itself and visitors already cleared still pass. It lasts 30 minutes by
  default, at most 6 hours (hours of locked-out crawlers cost search
  ranking), and never past the challenge. Controls:
  - CLI: `cfm webtop challenge add <vhost> --lockdown`,
    `cfm webtop challenge lockdown <vhost> on|off`, shown in `cfm --help` and
    `cfm webtop help`.
  - TUI: the `L` key in `cfm webtop live` (pressed twice to turn it on).
  - cfm-admin: the Emergency challenge card, with a LOCKDOWN badge in the
    controls table.
  - API: `vhost/add lockdown=1` and the new `vhost/lockdown`.

  cPanel tenants may lock down their own vhosts. The bypass list now tells
  CDN prefixes (`2`) from crawler prefixes (`1`). See `docs/vhost-lockdown.md`.

### Fixed
- **`install-openresty.sh` works on AlmaLinux / Rocky / RHEL 10.** OpenResty
  publishes no EL10 repository, so the installer's repo file (`$releasever`
  = 10) failed with a 404 on `centos/10/.../repomd.xml` and nothing was
  installed. On EL10 the installer now pins the repo to the EL9 tree, whose
  packages bring their own OpenSSL / PCRE2 / zlib and run on EL10 (checked on
  AlmaLinux 10.2). A repo file left behind by the failed run is rewritten
  automatically, so re-running the installer is enough.

### Security
- **A shell command that writes a PHP file is now logged in any field
  (rule 331, `WAF_RCE:SHELL_*`, logonly).** The tophair.gr webshell
  terminal posted `wget … -O wp-admin/…/colors.php`, `curl -o x.php`,
  `echo <b64> | base64 -d > upgrade.php` and `touch -d '2025-07-10' g.php`
  in a form field, and the command rules (310-317) read only the query
  string. The new rule reads the decoded args and body: query, form, JSON
  and multipart. It logs `wget`/`curl` output to an executable name, a `>`/`>>`
  redirect or a `tee` to one (`.php*`, `.phtml`, `.phar`, `.inc`,
  `.htaccess`, `.user.ini`), and `touch -d/-t/-r` backdating, also behind
  `sudo`/`nohup`/`HOME=…`, an absolute path, `sh -c '…'` or inside a JSON
  value. The `wget -q -O - …/wp-cron.php` cron line (stdout) does not count.
  Its cost is linear in the body: under 1 µs on ordinary requests, about
  0.1-0.15 ms on a 19 KB body naming `.php` and a verb on every line, at most
  about 1.5 ms on a crafted 32 KB body. Logonly: it never bans, and
  goes to block after a clean hit-rate review. See `docs/waf.md` "Rule 331".
- **A WordPress admin action a stored XSS sends is now logged (rule 503,
  `WAF_ADMIN_XSCREEN`, logonly).** On tophair.gr staff opened an order
  carrying the PixelYourSite payload, and within five seconds their own
  browser created an administrator and uploaded a backdoor plugin: logged-in
  admin requests no other rule could judge. The rule logs creating a user,
  changing a role, a user's email or password, uploading, installing or
  activating a plugin, uploading or installing a theme, saving the file
  editor, opening registration as administrator in General settings, and the
  REST API's user, application-password and plugin writes, when the request
  did not come from that form:
  sent by a script (fetch / XHR, a hidden iframe), from another admin screen
  or a front-end page (the order screen, on tophair), cross-site, or as a
  navigation no click started; and a script fetching the screens that hold
  those forms' nonces. Two months of titan's logs show these forms posted
  only from their own screen, apart from the attack. Log-only: a hit means
  the site already holds a stored payload somewhere an administrator just
  opened. The IP in the hit is the administrator's, not the attacker's.
- **New WAF CVE rules 10025 (block, autoblock armed) and 10026 (block, ban
  held): PixelYourSite stored XSS (CVE-2026-1844 / CVE-2026-1841 /
  CVE-2026-109987).** Older PixelYourSite and PixelYourSite PRO releases
  store the traffic source, landing page and UTM values of a Store API
  checkout in the WooCommerce order and print them unescaped in the order
  screen. A bot places a cheap order with a `<script src=…>` cookie, and the
  script runs in the browser of the staff member who opens the order. On
  tophair.gr it uploaded a fake plugin and created two administrators within
  15 seconds (2026-10-06). The fleet holds about 100 such planted orders on
  16 shops, from 2026-02-13 (the day CVE-2026-1844 was published) to
  2026-10-10; no WAF rule read cookie values. Rule 10025 refuses executable
  markup (a script, iframe, object, embed, meta or base element, or any
  element with an event handler, `srcdoc` or `javascript:`) in the
  PixelYourSite traffic-source, landing-page and UTM cookies, plus a
  landing-page value that breaks out of its `href` or carries a
  `javascript:`, `vbscript:` or `data:` URL, and bans the source for 6 h
  with a `WAF/CVE-2026-1844` alert. Rule 10026 refuses the same markup in
  the request path, the Referer's host and `utm_*` query fields, which the
  plugin copies into the session; any site sees those, so it only blocks,
  without a ban or alert. A campaign named "Retargeting > 30 days", a
  `<b>` or an unfilled `<campaign_name>` placeholder does not count; a
  7-day replay of every server's edge log found 10026 hits only from an XSS
  scanner. They stop new orders only: payloads already stored need a
  database clean-up, and the plugin still needs updating (free 11.4.3, PRO
  12.6.8).

### Changed
- **A vhost's unique-IP count no longer includes clients the vhost challenge
  lets through.** The suspicious-vhost challenge arms once a vhost sees more
  than `CHALLENGE_SUSPICIOUS_VHOST_UNIQIP_ON` distinct IPs (150 by default).
  That count included the crawlers the edge then waves through the challenge
  anyway. On a cPanel node, Applebot alone (on the bypass list) brought about
  1 300 IPs to one shop in 10 minutes: the shop went into challenge, Applebot
  kept crawling, and only its human visitors saw the challenge. The count now
  leaves out what passes a vhost challenge: the bypass list
  (`challenge_waf_bypass.conf`, now reported by the edge per request), an
  FCrDNS-verified good bot under `CHALLENGE_GOODBOT_EXEMPT`, and a match in
  `webdetector_challenge_exclude.txt`. The thresholds stay as tight as they
  were and now count only the traffic a challenge can stop. A crawler removed
  from those lists is challenged and counted again. Across five busy nodes
  Google and Bing were 2–20 IPs per vhost, so most vhosts see no change.
  The same number is the `uniqIP=` in the auto_on/auto_off lines and history,
  and feeds the vhost score; the top-IP lists still show every client. Where
  the daemon cannot check an exemption cheaply it counts the client (a crawler
  is exempt once the edge has verified it). The edge's `log-cfm.lua` sends the
  bypass flag as a new last column; an older daemon ignores it safely.
  `CHALLENGE_SUSPICIOUS_VHOST_UNIQIP_EXEMPT = 0` restores the old count.
- **The challenge solver-farm detector's shipped thresholds now match what
  the fleet measured: a 180s window, 30 subnets, 15 solves** (were 60s / 40 /
  40). The longer window catches slow farms the 60s one missed, and the
  fingerprint track counts over it too. 30 subnets sits above the Greek shop
  audiences that a 15-subnet setting flagged as farms (paid-ad traffic peaks
  at 15–25 networks in three minutes) and below the farms seen without a
  fingerprint (33–77); the margins are thin, so watch the alerts. It is
  still alert-only. **An existing install keeps its own lines:** the stock
  `detectors.conf` has always written these three keys, so an edited
  conffile still says 60s / 40 / 40 (or whatever was set) after the upgrade.
  Change the `[challenge_solver_farm]` lines by hand; a node that set
  `MIN_SUBNETS = 15` should raise it to 30 to stop those alerts.

## 2026.10.24

### Changed
- **Rule 330 (`WAF_XSS_BODY`, logonly) no longer logs `javascript:` URLs,
  and skips cPanel session paths.** In its first 48 hours on seven nodes the
  `javascript:` tag was 2 826 of 2 831 hits and caught no attack:
  TranslatePress (`trp-ajax.php`) and PixelYourSite (`/wp-json/pys-facebook/v1/event`)
  post the page's own `href="javascript:void(0)"` links. The other tags
  (attribute breakout, a tag with an event handler, `<script`) fired 5 times:
  a CS-Cart scanner on two sites, a CS-Cart admin and a cPanel File Manager
  save through `cpanel.<domain>/cpsess<N>/`, which is now skipped (on the
  `cpanel.` / `whm.` / `webmail.` hosts only: elsewhere such a path still
  reaches the site's app).

## 2026.10.22

### Security
- **XSS in a POST body is now logged (rule 330, `WAF_XSS_BODY`, logonly).**
  Rule 302 reads only the path and query string, so a stored-XSS payload
  posted in a form field passed with no WAF line at all: on 2026-10-22 Live
  Helper Chat's chat-start email field took `x" onmouseover="alert(…)"` and
  it ran in the operator's browser. The new rule logs explicit markup in the
  body: a quote breaking out of an attribute into an event handler, a tag
  carrying an event handler (`<img onerror=`), a `<script` tag, a
  `javascript:` URL followed by code. It skips logged-in WordPress users,
  requests with an `Authorization` header (API clients, forms behind HTTP
  basic auth) and the `/wp-admin/` (except admin-ajax and admin-post),
  `/administrator/` and Live Helper Chat `/site_admin/` paths, where editors
  and operators post markup by design. Other apps' admin areas (OpenCart,
  PrestaShop, Drupal, WHMCS tickets with code) will show up in its log. Log-only: it blocks nothing, and
  its fleet hits decide whether it is ever promoted.
- **phpMyAdmin logins count toward the login-burst rule (501).** Eight
  `pma_password` submissions in 20 seconds from one IP to a `phpmyadmin` path
  now get the same `challenge_v2` as a WordPress or Joomla login burst. Its
  queries, saves and imports carry no password field and never count.
- **The malpath challenge now runs at the ChallengeV2 tier.** An IP
  challenged for asking for a malpath (`/.env`, `/.git/config`, a wp-config
  backup, a webshell name; `CHALLENGE_PATHS`) can no longer clear that
  challenge with an automated browser. For at least 15 minutes (or
  `CHALLENGE_PATHS_TTL` if longer), on every web host, a solve showing
  `navigator.webdriver` or a HeadlessChrome UA earns no clearance (`v2=mark`, `result=v2_reject` on the solve line). On 2026-10-22 a
  HeadlessChrome scanner solved the old v1 challenge on a hosted chat app
  and went on to list and download its files. A person who mistypes such a
  path pays nothing unless their browser fails the Rung-1 check (moving the
  mouse rescues a borderline score). `[webdetector] CHALLENGE_V2_PATHS =
  0` restores v1. Rejecting webdriver / headless browsers on every
  challenge was considered and not done: unarmed, they are mostly the site
  owner's own tools (HubSpot, iubenda's cookie radar, the Plesk screenshot
  bot).
- **The malpath challenge revokes the client's clearance cookie.** A client
  that had solved a challenge before (even at v1) kept fetching `/.env`,
  backups and webshell names with its cookie, never meeting the malpath
  challenge, and the daemon's solved-ok state answered "allow" over it on
  the decision path too. Now the edge stops honouring that IP's cookie
  within ~5 s of the challenge and serves it (the challenge page no longer
  waves the cookie through either); solving it gives a working cookie
  again. `[webdetector] CHALLENGE_PATHS_REVOKE = 0` turns it off.
- **A malpath-challenged IP that keeps failing the v2 check is held, then
  banned.** Before, such a scanner waited out the 10-minute challenge and
  walked back in, not challenged again for the 45-minute cooldown. Now each
  failed solve holds the malpath challenge for an hour (a later, shorter
  challenge no longer cuts it short), and a second failed visit in that
  hour (rejects 10+ minutes apart, or 30 minutes into one that never
  pauses; the page's retries and a reload are one visit) raises `WEB/CHALLENGE_V2_MALPATH_REJECT`, which the webdetector
  section blocks per its BLOCK policy (edge ban and notification included;
  DRY_RUN applies). The hold survives a `detectors.conf` reload (not a
  daemon restart). A person sharing
  the address passes by solving, which ends the hold and starts the count
  over. Only IPs the malpath challenge marked
  count. `[webdetector]
  CHALLENGE_V2_PATHS_REJECT_BAN` sets the visits (default 2); 0 turns it
  off.
- **More leaked-file probes are malpaths.** WordPress `debug.log`, SQL dump
  names (`/database.sql`, `/dump.sql`, `/db.sql`, ...; matched as a path
  substring, so `/db.sqlite` too), schema files (`.dbml`) and Live Helper
  Chat's `/cache/default.log` and `/doc/update_db/` now trigger the malpath
  challenge (and count toward the malpath flood block). The same pentest
  read two of them. `*.sql.gz` is left out (cPanel's own MySQL backup
  download ends in it), and so are config templates (`*.php.example`): a
  WebDAV sync of a code tree would request them. In 15 hours of the fleet's
  edge logs about 700 IPs asked for these on hundreds of sites, and not one
  was a real file. The
  list is a conffile: a node whose `/etc/cfm/webdetector_malpaths.txt` was
  edited gets the new entries as `.dpkg-dist` / `.rpmnew`. cPanel's own
  session URLs (`/cpsess<N>/…`) are no longer matched against the malpath
  list at all: File Manager's viewer puts the file name in the path, so a
  site owner viewing their own `backup.sql` would have been challenged.

### Fixed
- **An unblock clears the client's ChallengeV2 marks.** After `cfm unblock`
  (or an unblock from cfm-web) the client's next challenge within the mark's
  lifetime still ran at the v2 tier it had failed. The WAF, malpath and
  traffic-rule marks on the IP now go with the unblock, which lists them as
  `challenge_v2_mark`.
- **A detector's challenge keeps its reason.** The bridge sends each
  challenge to its own `/nginx/ip` handler without a reason, and that echo
  erased the detector rule from the entry, so solve lines read `src=ip`
  instead of `src=ip:CHALLENGE_PATHS` (and the solved hook got no reason).

### Changed
- **ChallengeV2: the always-on vhost challenge list now runs at v2 too.** A
  vhost on `CHALLENGE_VHOST` — by default every tenant's `webmail.`, `whm.`
  and `cpanel.` subdomain, and the panel ports' login challenge for a listed
  host — is challenged at the v2 tier by default, like the automatic
  challenges (`CHALLENGE_V2_AUTO_VHOST` gains `vhost_config`). A solve that
  fails the passive humanity score earns no clearance there; the page retries
  a few times, then asks the visitor to contact the site. Measured first, over
  14 days on 7 nodes: none of ~650 solves from Greek and Cypriot home ISPs on
  those hosts would have failed; the failures were bot farms, a cloud scanner
  and automated browsers. Unlike an automatic challenge this one never
  expires, so to keep one vhost at the old tier, pin it
  (`cfm webtop challenge tier <vhost> v1`), or drop it node-wide with
  `CHALLENGE_V2_AUTO_VHOST = suspicious_vhost,uniqpaths_short,under_attack`. A
  node with its own list of sources keeps it; `on`, `default`, `1` or a blank
  value follow the new default. Watch it with `v2_via=auto:vhost_config` or
  `src=vhost:vhost_config` on `challenge_v2_reject`. An upgraded node's own
  `detectors.conf` still describes `vhost_config` as opt-in and carries the
  old default as a commented line; the daemon now logs the sources it arms
  when it reads the config (`CHALLENGE_V2_AUTO_VHOST: automatic vhost
  challenges at v2: …`).

### Fixed
- **A challenge opened in a minimized window should no longer fail on its
  own.** The challenge page measured the window when it loaded: a minimized
  window most likely reads as 0x0, which counts as a headless-browser sign,
  and on an old PC with software graphics that was enough to reject the
  solve. The page then retried while still hidden, was rejected the same way
  each time, and gave up, so a visitor who came back to it found
  "Verification could not complete". The page now measures the window when
  it sends the solve, and a page nobody can see sends no window size (and a
  log-only `hid:1` in `sig=`), so that sign cannot fire on it. Background
  tabs still finish on their own, as before. Seen on shop pages, from Greek
  home ISPs.

## 2026.10.21

### Security
- **New WAF rules 10023 / 10024 block PHP2Shell (CVE-2026-109619) as it is
  exploited in the wild.** The public tool drives PHP's session upload
  progress, and its requests carry none of the shapes rule 10021 looks for:
  on 2026-10-21 they passed the edge to the origin on orion and mars, where
  Imunify360 stopped them (one site answered 200). Rule **10023** blocks the
  tool by its request head (User-Agent `php2shell-…`, or one of its multipart
  boundaries). Rule **10024** blocks a multipart field named
  `PHP_SESSION_UPLOAD_PROGRESS` unless the request carries a same-site Referer
  or Origin *and* a same-site `Sec-Fetch-Site`: the scanner forged a same-site
  Referer here, and every modern browser sends Fetch Metadata. A browser's own
  upload-progress form is only logged, including one posted from the `www.`
  or a sibling host and one under `Referrer-Policy: no-referrer` (`Origin:
  null`, no Referer). The field name is read as PHP joins it, so splitting it
  across header lines does not get past the rule. Both are armed (a 6 h ban), and 10024
  is enforced in the body burn-in too, which is where the tool's `POST /`
  passed. Built from Imunify360 ruleset 8.85 and the fleet's own logs. Not a
  fix: set `session.upload_progress.enabled = 0` and update PHP (8.2.35 /
  8.3.36 / 8.4.27 / 8.5.12).

### Fixed
- **A package upgrade, restart or reboot no longer frees every TTL-banned
  address.** TTL bans (autoblock, WAF autoblock, `cfm block --ttl`, fleet
  blocklist deltas) live only as timed elements of `block_v4` / `block_v6`,
  and the rpm upgrade script ran `cfm disable`, which deletes the whole
  firewall table: on the 2026.10.21 upgrade, 49 of 50 bans on one node
  disappeared while the notifier had already reported "Blocked: Yes". This
  had been in the rpm package since 2025-10. The upgrade now restarts the
  daemon without deleting the table, as the deb always did. The daemon also
  saves its TTL bans to `/var/lib/cfm/ttlbans.json` (every ~2 minutes and on
  stop) and restores them at start for the time they have left, which covers
  a reboot or `cfm reset`. Expired bans are dropped, and so are bans an allow
  entry, `cfm.ignore` or `IGNORE_IPS` now covers. Unblocks remove the entry at
  once, so a restart never brings an unblocked address back; `cfm flush`
  clears the saved bans too. Permanent bans
  still come from `cfm.deny`. As on deb nodes, a change of the input chain
  priority now needs `cfm reset` on rpm nodes too. See `docs/DETECTORS.md`
  "TTL bans across a restart".

### Security
- **Rule 401 (and the upload CVE rules) no longer miss an upload placed where
  PHP looks for the next field.** PHP does not read a file field that is left
  empty, has a malformed name, or comes past `max_file_uploads`; and a
  `MAX_FILE_SIZE` form field (which the sender chooses) makes it stop reading
  a bigger file partway. In each case PHP looks for the next field from that
  point, and the WAF did not: a `shell.php` upload placed there passed rule
  401 and the Elementor rule 10016, and a field placed there was hidden from
  the field-keyed CVE rules (checked against PHP 8.3.6). The WAF now follows
  PHP after a skipped field, and reads a body where a `MAX_FILE_SIZE` cut can
  happen once more from every field boundary in it; rule 10021 reads every
  body that way. A body with more than 20 files is read twice (for hosts that
  raised `max_file_uploads`). Still not modelled: `file_uploads = Off`; and
  after a `MAX_FILE_SIZE` cut, a part hiding its file name below 16 header
  lines is left to rule 10021, so it passes where 10021 is excluded.

- **WAF rules 10021 / 10022 block the PHP core RCE request shapes
  (CVE-2026-109618 / CVE-2026-109619, "PHP2Shell").** PHP before 8.2.35 /
  8.3.36 / 8.4.27 / 8.5.12 can be taken over by a request that runs PHP out of
  memory while it parses a multipart upload, before any site code runs. The
  edge now refuses the shapes the PHP advisories name. Rule 10021: a part with
  more than 16 header lines, 128 or more empty file fields, or a field name
  nested too deep (more than 16 levels on a file field, 32 on a plain one) —
  real forms don't send these, so a hit is a 403 plus a 6 h ban and a
  `WAF/CVE-2026-109618` alert (the exploit needs many attempts, so the first
  one is enough). It also applies to a large or chunked `POST /`, which the
  body burn-in would otherwise only log, and to a client holding a solved
  challenge. A false positive is cleared fastest with a WAF exclude for rule
  10021 on that host or path. Rule 10022: a multipart POST with no
  Content-Length that the edge passes on unread (an HTTP/3 upload it cannot
  read) — a 403 without a ban (`RULE_10022 = 1` in `[waf_security]` arms it);
  it needs the edge conf shipped with this release. A stopgap with limits: it
  sees the first 32 KB of a body only (an attacker who pads past it is not
  stopped), not the panel ports, not unread streaming paths, not nodes without
  the edge. Update PHP and set `session.upload_progress.enabled = 0`.

### Changed
- **ChallengeV2: the real-input rescue no longer clears a score above 100.**
  A failing solve with real pointer input is still rescued at 100, the score
  of the old Windows Chrome/109 PCs the rescue exists for. Above it (a
  software renderer plus a device claim the report contradicts, 110-150) it is
  rejected as before the rescue. In three weeks the rescue fired 0 times at
  any score, and that family is farm-only in every measurement; without the
  cap a farm that learned to post fake mouse movement would pass. The cap is
  fixed at 100 whatever `CHALLENGE_V2_FAIL_SCORE` says;
  `CHALLENGE_V2_INPUT_RESCUE = 0` still turns the rescue off.

### Fixed
- **edge_health no longer blames a CDN for a site that has none.** The
  "CDN caches the challenge" finding (whats_wrong, Check F) counted every
  visitor with a valid clearance who came back to the challenge page. On a site
  with no CDN in front, visitors opening a PDF on Android did exactly that: the
  download leaves the tab on the challenge address, and each re-tap counted.
  The edge now tells the challenge page whether a trusted proxy (Cloudflare)
  relayed the request, and only a relayed bounce for a page raises the
  warning. Bounces that reached the server directly, and relayed ones for a
  download (PDF, zip, office documents …), are listed in the finding's
  evidence (`direct_hosts`, `download_hosts`) instead, so a CDN CFM does not
  know about, or one that caches only files, stays visible. Needs the new edge
  conf; with the old one every page bounce still counts.
- **A WordPress API client or logged-in admin is no longer banned for the
  403s WordPress itself returns.** The web detector's 403 flood ban counted
  the 403 a site's WordPress gives to a REST API call (`/wp-json/…`,
  `?rest_route=…`) like a scanner probing forbidden paths. A WooCommerce
  stock sync whose API key lacked write access, and an admin whose Site Kit
  dashboard polls a route the site answers with 403, were banned (and the
  sync reported to the fleet blocklist). Those 403s no longer count toward
  the ban. Still counted: the 403s CFM's WAF gives scanners on REST paths, a
  REST login/token endpoint (a password guess there gets a 403), a
  `wp-login.php` brute force and forbidden-file scans.
- **A signed link no longer fails after the CDN cache-busting retry.** When a
  CDN (e.g. Cloudflare) bounces a visitor who already passed the challenge,
  CFM sends them to the page once more with an extra `cfm_nc` parameter the
  CDN has not cached. That parameter now stops at the edge: the site receives
  the URL the visitor asked for. Before, an app that signs its links (Laravel
  email verification, password reset and unsubscribe links, payment
  callbacks) saw the extra parameter and answered "invalid signature". A URL
  whose path is percent-encoded (non-Latin letters, `%2F`) or carries `//` or
  `/./` keeps the parameter as before: removing it there would hand the site a
  decoded path.

## 2026.10.19

### Added
- **Traffic rules export / import, to move a site's rules between servers.**
  cfm-admin → Traffic Rules → **Export / Import** downloads the rules of the
  vhost picked in the filter (or every rule) as a JSON file, and imports such a
  file on another server. The import always shows a preview first: which rules
  will be added, which already exist there (same vhosts, conditions and action;
  skipped, so importing the same file twice adds nothing) and any priority shared
  with an existing rule on the same vhost. "Import as disabled" brings every rule
  in disabled, to test with the simulator first. One invalid rule rejects the
  whole file and nothing is written. Imported rules get new ids, and their note
  says where they came from ("imported from orion 2026-10-14"). The same from
  the CLI: `cfm webtop rules export --vhost <host> --out f.json` and
  `cfm webtop rules import --file f.json [--dry-run] [--disabled]`. A rule
  that already exists but is disabled there, or has another priority, is
  flagged in the preview (the import does not change it). A rule with a field
  this cfm does not understand (from a newer cfm, or a typo in a hand-edited
  file) is refused rather than imported without it, since that would widen
  it. A cPanel user's export carries only their own vhosts, and the import
  accepts only their own vhosts. A rule shared with other sites comes along
  in an operator's export with all its vhosts, and the preview names them. Until now a site moving
  servers had its rules retyped by hand.

### Changed
- **A WordPress pingback no longer bans the server that sent it.** Every
  `pingback.ping` to `/xmlrpc.php` still gets a 403 (rule 511), but its
  `waf_security` ban is held in code (`RULE_511 = 0`). WordPress itself sends
  one when a post links to a site here, and the ban (the section `BLOCK`, 7 days
  on several nodes, reported to the fleet list) landed on the sender's shared
  hosting server, every port included, mail too: a fleet review of 2026-10-15
  found 35 such pingbacks among ~680 rule-511 hits, three of the senders still
  on the fleet list. Multicall (510) and the XML-RPC POST burst (512) keep the
  ban. Since a held block rule would take the headline, and with it the ban,
  from an armed rule on the same body, the 511 block is now recorded after
  the armed rules. A real pingback that 511 stops (block or challenge; the
  call WordPress runs is `pingback.ping`) never counts toward 512, and the
  edge's IP decision after it lasts 10 seconds instead of 30 minutes, which
  used to 403 every request from the sender's server to every site on the
  node. The words carried inside another XML-RPC call (a password guess), a
  decoy padded past the edge's body window, and a pingback 511 lets through
  (`logonly`, excluded) still count toward 512's ban, as before.
  `RULE_511 = 1` in `[waf_security]` arms it again.

### Fixed
- **A site behind Cloudflare no longer traps cleared visitors in a challenge
  loop.** When a vhost's Cloudflare Cache Rule ignores the origin's
  `Cache-Control`, Cloudflare cached CFM's challenge page and its redirects
  despite `no-store` (anastasiadi.gr on mars). Every visitor of a cached URL got
  the challenge, often a copy carrying another visitor's token. Visitors who
  solved were sent back to the cached challenge, solved again (~30 times in two
  minutes) and were finally banned by the challenge rate limit. Now:
  - the challenge page is served only at `/__cfm_challenge`, so a challenged
    homepage is a redirect there, never a cacheable copy of the page (a
    challenged `/` now answers 302 instead of 200, like every other URL; an
    uptime monitor that does not follow redirects sees the change). A tenant
    homepage's own `?next=` parameter is no longer read as the challenge
    target (`/?next=/account` stays the homepage's query);
  - every challenge response also carries `CDN-Cache-Control` and
    `Cloudflare-CDN-Cache-Control: no-store`;
  - a visitor who already holds a valid clearance and is bounced back is sent
    to the page they wanted once more, with a `cfm_nc` parameter the CDN has
    not cached, instead of being asked to solve again (once per page per
    10 s; web ports only; not for a target that would grow past the length
    limit or carries a `#` fragment, where the parameter could not work);
  - `edge_health` (and so `whats_wrong`) reports the vhosts where 3 or more
    distinct visitors (an IPv6 /64 counts as one) were bounced like this in
    24 h (`cdn-cached-challenge`), naming the fix: set the vhost's Cloudflare
    Cache Rule to respect the origin's Cache-Control, then purge.

  CFM cannot override a CDN that ignores `no-store`. Until its rule is fixed,
  every visitor of a cached URL is still challenged once.

## 2026.10.13

### Changed
- **"Done before" and "volume only" spikes: a follow-up review of the
  2026-10-13 change.** The sender's peak is now measured over three hourly
  buckets, the same span as the recent window, so an order or payroll run
  spread over three hours is no longer paged every day. A mailbox read from
  three countries that sends its usual run no longer confirms a hijack:
  logins from many countries are no longer a tell of the spike (the spike is
  what confirms the hijack), so the usual run is "done before" and no
  finding, and a spike confirms a hijack at warning or above (a tell of its
  own, or extreme) or at 1.5× its own record, not a volume-only run a little
  over it. A fixed-size run that equals its peak is "done before" too. Sending from 10+
  addresses counts as a tell only for addresses that SENT mail, not an
  office's phones reading the mailbox, and the message now says
  `· sent from N IPs`; with a mailbox's 256 tracked sources full, a sending
  one takes the place of the oldest reader. `whats_wrong`'s
  fallback lists warnings before the runs under their peak, and reads the
  node's `under_peak` instead of its own copy of the rule; `mail_traffic`'s
  anomalies list those runs last, so its capped list never drops a real
  spike for them.
- **A mailbox sending its usual big run, or volume with nothing abusive
  about it, no longer pages as a "compromised mailbox".** Titan's channel saw
  15 `mail_outbound_spike` alerts in 5 days, nearly all order confirmations,
  a claims system and a payroll run. A spike (mailbox or script) with no tell
  of abuse and no larger than the sender's own largest two-hour burst of the
  last 28 days is a run it has sent before and is no longer a finding
  (itadmin@ sent 177 one morning and 176 the next, paged both days). A
  mailbox spike with no tell of abuse (a sender outside this host's domains,
  sending as another domain, the contact-form pattern, bounces of its own,
  logins from many countries, sending from 10+ addresses at once) is
  published one step down and marked `· volume only`: info instead of a
  warning (logged, below every warning route), a warning instead of
  critical. A new sender with no history is not stepped down, and a sender
  alerted on in the last 28 days is never "done before" (its peak may be the
  thief's first wave). A mailbox sending as another address of its OWN
  domain (`mail@` sending its `claim@` notices) is no longer flagged
  "(not itself)".
  `mail_traffic`'s anomalies carry the sender's `peak`. See docs/mail-abuse.md
  "Done before" and "Volume alone".
- **A mailbox read from three countries is no longer a critical hijack
  page.** In a week the fleet raised 33 critical `mail_hijack` alerts on 10
  mailboxes, each reminded every 6 h, and every one was a mailbox only READ
  from abroad: owners travelling, behind a VPN or a company proxy. A hijack is
  now critical only when the mailbox is also used within the hour: mail sent
  (SMTP AUTH) from a country it was not read from, or from two countries, an
  outbound or bounce spike of its own, or its forwarder or mail filter
  changed in the last 24 h (cPanel). The message says which. Without that it is a warning that asks to
  check with the owner, and it is raised to critical the moment one appears.
  A warning hijack that comes back from no new country is not published
  again while it keeps coming back at least weekly
  (`/var/lib/cfm/mail_abuse_published_hijacks.json`); a critical one, or any
  hijack after a critical one, always is.
  Netskope, Zscaler and Cisco Umbrella exits now count as one source with no
  country, like Gmail fetching: on orion one company's staff were paged every
  few hours from Netskope exits in IN and UG. See docs/mail-abuse.md "Hijack
  severity".
- **A WordPress / Drupal / Joomla / OpenCart / Magento login brute force from
  a direct client is now challenged.** The login-burst rule (WAF 501) has
  counted clients that connect directly, not only those behind Cloudflare,
  since 2026-10-09, but only logged them for a burn-in. Over 86 hours on six
  servers it logged ~1 850 such hits, nearly all from hosting, VPN and Tor
  networks (on one server ~11 cloud addresses made ~1 460 of them), and no
  real visitor. They now get the same challenge as proxied clients; a
  challenge never leads to a firewall ban. To go back to logging only, set
  `auth_burst_direct_mode = "logonly"` in `cfm_waf_config.lua`.
### Added
- **Site Cache: micro TTLs of 90 s and 120 s.** Two more Tier B buckets
  (`cfm_micro_90s`, `cfm_micro_120s`), selectable on the cfm-admin Site cache
  page and with `cfm webtop site-cache set <host> --micro-ttl 90s|2m`. A TTL
  above 120 s now snaps to 120 s (was 60 s). The new cache dirs are created by
  the daemon and `cfm-cache-dirs.sh`; the edge conf needs the new reference
  `openresty.conf` / `angie.conf` (zones + locations), which the package update
  installs. A vhost whose stored micro TTL is above 60 s (e.g. `2m`) moves
  from the 60 s bucket to 90 s or 120 s on upgrade; set it again to keep 60 s.
- **Traffic rules recipe "Crawlers don't call AJAX / tracking endpoints".**
  Blocks social, AI and SEO crawlers, any method, on `admin-ajax.php`,
  `?wc-ajax=`, the WooCommerce Store API, PixelYourSite's `/wp-json/pys-*`
  events and LiteSpeed's `guest.vary.php`. A crawler that renders pages runs
  their JavaScript: on 2026-10-13 Meta's ads crawler fired ~7 000 such calls on
  one shop in an hour and took titan's load from ~25 to ~70. Pages, images and
  feeds stay open, so ad catalogs and previews keep working.

### Changed
- **Site Cache Tier B now stores pages that only set tracking cookies.** A
  response whose `Set-Cookie` headers are all tracking cookies (`_fbp`,
  `_fbc`, `_ga`, `_ga_<ID>`, `_gid`, `_gat`, `_gcl_au/aw/dc/gb/gf/ha/gs`) is
  micro-cached, and those cookies are removed from every micro response, so no
  visitor ever receives another visitor's id (the Facebook pixel and Google
  tags set them again in the browser). The cost, for a shop to know before
  arming micro: these cookies no longer come from the server, so Safari keeps
  them only 7 days, and a Facebook pixel event id printed into a cached page is
  shared by the visitors of one TTL (Conversions API deduplication). Facebook for
  WooCommerce sets `_fbp` from the server on every page, so until now no such
  shop could be micro-cached. Any other cookie (a session, cart, login,
  consent or currency choice) still means the page is never stored. The micro
  cache key changed with this, so every micro-armed vhost starts from an empty
  micro cache once after the upgrade.
- **Meta's ads crawler (`meta-externalads`) is part of the Meta crawler family
  in the traffic-rule recipes** (social group, "Throttle Meta crawlers",
  "Block Meta bot query-string loops", "Crawlers are read-only") and in the
  edge's Meta crawler throttle (5 req/s per site, 60/min per IP). It was
  missing, so "Crawlers are read-only" let its POSTs through. It is not added
  to the User-Agent-only allow some recipes put in front of verified crawlers
  for Meta's one-shot link previews: it is a repeat crawler.
- **SE Ranking's crawler (`SERankingBacklinksBot`) is in the recipes' SEO tools
  group.** On a WooCommerce shop it walked every category's `?type=…&orderby=…`
  combination, and each page ran a product-filter count over 14–31 M rows (up
  to 65 s per query). A rule copies the group's list when it is created: an
  existing SEO-tools rule gains it only when re-created from the recipe.
- **OpenAI's GPTBot and OAI-SearchBot are no longer on the crawler bypass list**
  (`challenge_waf_bypass.conf`, 51 prefixes). A bypassed client skips the
  traffic rules as well as the WAF and the challenge, so no "bots" recipe could
  reach them: on one shop GPTBot walked every `?filter_category=` combination at
  ~2 req/s, 2.4 s a page, and a block rule matching it never ran. They are now
  ordinary clients: rules can throttle or block them, and a vhost-wide challenge
  applies to them too (a page they can only skip, as any crawler without a
  bypass does). Google, Bing, DuckDuckGo, Applebot, Skroutz and QUIC.cloud stay
  bypassed — and so stay out of every traffic rule.

### Fixed
- **`cfm status` reports the firewall on nftlib nodes.** It printed "table
  present, but no rules found" and zero totals over a full firewall (one node:
  174 rules, 110 000+ entries). It read only `nft -j` output, and the nftlib
  backend answers in its own format; it now counts rules from the nft text dump
  and each set's entries through the backend. The same fallback covers a host
  whose `nft -j` output does not parse (a warning on stderr). A read that fails
  is reported as such ("UNKNOWN", "READ FAILED" per set, `read_error` in
  `--json`), never as zero or "table absent"; when only the rules cannot be
  read the set totals are still shown. Entries with a timeout are now counted
  on exec-engine nodes too, so their totals can go up.
- **The exec firewall backend lists interval-set entries as CIDRs / ranges.**
  It turned `{"prefix"}` / `{"range"}` elements into `<nil>` (and timeout-
  wrapped ones into `map[…]`) for every caller, and failed a read on a warning
  nft printed on stderr.
- **CLI commands no longer print the daemon's `[startup] backend type=…` line**
  (it also landed in `cfm status --json` output).

## 2026.10.11

### Fixed
- **The cfm daemon no longer needs four times the certificate list's size in
  memory to write it.** Each certificate change rebuilt the whole list (all
  hosts with their PEMs, ~110 MB on a 7 800-host node) in memory before
  writing it to disk or handing it to the web server, so an AutoSSL run made
  the daemon peak at 1.2 GB. The list is now written entry by entry straight
  to the file, and the web server is always served from a file: a synthetic
  60 MB list now costs +28 MB of heap instead of +235 MB, and a certificate
  change with six web-server workers fetching it +57 MB instead of +351 MB.

### Security
- **The certificate snapshot's temp file can no longer be redirected by the
  web server's user.** The daemon wrote the snapshot (every certificate's
  private key included) to a fixed `dump.json.tmp` in a directory the `cfm`
  group can write, and set its mode and group by name. A `cfm` process that
  planted that name as a symlink had root overwrite the link's target with
  the snapshot and make it readable by the `cfm` group. The temp file is now
  created new under a random name, and its mode and group are set on the
  open file.
- **The daemon no longer follows a name the web server's user can plant.**
  `/var/lib/cfm/scanner/pending`, `scanner/infected` and
  `sslcollector/dump.json` sat in directories the `cfm` group could write
  (the scanner dir is no longer group-writable, below).
  At every start the daemon chmod'ed and chown'ed them by name, so a `cfm`
  process that replaced one with a symlink had root make the target (`/etc`,
  say) group-writable by `cfm`, or hand a file such as Debian's
  `/etc/shadow` to the `cfm` group. They are now opened without following
  symlinks (a hard-linked `dump.json` is refused too) and set on the open
  handle; a refused name is left alone with a warning in the log. A FIFO
  planted as `dump.json` no longer hangs every `/dumpall` and snapshot
  write, and the snapshot's mtime is no longer stamped by name. Directories
  in root-only parents (`/var/log/cfm`, the Site Cache zones) still follow
  an operator's symlink, as before.
- **The web server's user can no longer make the daemon write, chmod or
  delete files elsewhere through the ClamAV scanner directories.** The
  scanner dir was `root:cfm 0770`, so a `cfm` process could rename `pending`
  or `infected` away and put a symlink (to `/etc`, say) in its place: every
  15 s root re-applied mode 0770 and group `cfm` to it by name, copied
  uploads (bytes of the attacker's choosing) and infected evidence into it,
  and removed spool files resolved through it. Even without the directory
  swap, root wrote the inline-scan fallback copy and the evidence copy to a
  fixed file name, following a symlink planted there. Now:
  - `scanner` is `root:cfm 0750` and `infected` `root:root 0700` (the edge
    only ever writes `pending`, which stays `root:cfm 0770`); their mode and
    owner are set on the opened directory, and a directory that is a
    symlink is refused and the feature that uses it disabled, with a
    warning. An operator who symlinked `pending` or `infected` to another
    disk must replace the symlink with a real directory or a bind mount
    (not change `CLAMD_PENDING_DIR`: the edge's spool path is fixed at
    `/var/lib/cfm/scanner/pending`);
  - every copy into those dirs is a new file with a random suffix, created
    exclusively, read from a source opened without following a symlink or
    blocking on a FIFO; evidence, inline and async, is now a copy named
    `<name>.<random>` (async evidence used to be the edge's own spool,
    renamed — its user could rewrite it, or overwrite it by re-posting the
    name);
  - a spool the edge hands over must be a regular file directly in
    `pending` with no control characters in its name, a queued file
    swapped for a symlink or FIFO is dropped, and the stale-spool sweep no
    longer follows a symlinked `pending`.

### Fixed
- **Edge workers no longer re-download the whole certificate list on every
  change during an AutoSSL run.** AutoSSL renews many certs within minutes,
  and each renewal was a new list version that every worker fetched in full:
  on a 7 800-host node each worker pulled the 110 MB list ~20 times in 3.5
  minutes and the cfm daemon peaked at 1.2 GB serving them. A worker now
  fetches at most once per 30 s for version changes (the first change still
  reaches every worker within ~30 s, as before; later ones are folded into
  one fetch that brings the newest), and the last worker no longer fetches
  every version twice.

## 2026.10.10

### Fixed
- **The web detector no longer bans verified search-engine crawlers.** A shop
  answering 403 to Googlebot's `?add_to_wishlist=` links made the 403-flood
  rule ban Googlebot for an hour and report it to the fleet blocklist — ten
  times on one node in a week. Every web-detector IP ban (`WEB/403`,
  `WEB/404`, `WEB/40X`, `WEB/403WAF`, `WEB/BOT`, `WEB/MALPATH`, `WEB/RPS`) now
  skips an address that is a forward-confirmed (FCrDNS) good bot: Googlebot,
  Bingbot, Applebot, Yandex, Meta and the rest of the built-in list, plus the
  challenge exclude file's `verify_fcrdns=1` PTR rules (not its `ua=`/`asn=`
  rules) — so a crawler listed there (the shipped file has Ahrefs and
  Semrush) is no longer banned for its request rate either. The skip is in
  the history as `outcome=exempt_goodbot`.
- **A new or renewed certificate reaches every edge worker within ~30 s
  (~10–25 s with six workers), not minutes.** Workers checked for a new
  certificate list every 60 s, and each
  fetch of the list took a lock shared by all workers, so they picked it up
  one per minute: on a six-worker node the last one served a new cert 4.5
  minutes after the daemon saw it (visitors hitting that worker got the
  fallback certificate). Workers now check every 10 s and fetch the list
  without the shared lock, a couple of seconds apart.
- **The certificate collector no longer rebuilds its whole list for every
  worker, or rewrites it when nothing changed.** On a node with 7 800 hosts
  the list is ~110 MB: each worker's fetch re-read every certificate and key
  into a fresh buffer (memory spikes of 50–280 MB in the daemon), and every
  hourly rescan rewrote the snapshot (~18 s) even when nothing had changed.
  The daemon now serves the snapshot file it already keeps (when it is
  current and complete) and otherwise builds the list once for the workers
  asking at the same time, rewrites the snapshot only when the list changed
  (or the file on disk is incomplete), and reads its counts off its front.
  A host moving to another certificate (one expiring) now also counts as a
  change.
- **`cfm debug` bundles now carry the CPU and heap profile tops again, and
  are ~160 MB smaller.** `pprof-cpu-top.txt` / `pprof-heap-top.txt` were
  missing from every bundle ("stat -: no such file or directory": the profile
  was piped to `go tool pprof`, which takes no profile on stdin), and each
  bundle carried its own `.gocache` with a fresh build of pprof. The profile
  now goes through a temp file, and the build cache is shared by every bundle
  in `/var/lib/cfm/debug/.gocache` (with `--output` elsewhere, only when that
  root is owned by the caller and not group/other-writable: the cache holds a
  binary `cfm debug` runs as root). The raw `.pb.gz` profiles were always
  complete.

### Security
- **A ban now also stops an attacker who comes through Cloudflare.** The
  firewall only sees the address a connection comes from, and for a site
  behind Cloudflare that is Cloudflare's, so a banned scanner kept reaching
  sites for half an hour after each ban (9 Oct). Bans from the WAF, the web
  detector, the challenge sections and other web detectors, and manual bans
  (API, cfm-admin's "Block selected", `cfm block`), are now also enforced by
  the edge for the same time, for a visitor that comes through Cloudflare:
  its request gets a 403. Unblocking or allowing lifts it at once, and a ban
  the firewall no longer holds stops within two minutes. An address any
  firewall allow list covers (including the fleet whitelist and the server's
  own addresses) or a Cloudflare address is never blocked this way, and
  direct visitors are left to the firewall as before. Mail, SSH and
  other non-web bans, fleet blocklists and `cfm.deny` are not copied.
  `[global] IGNORE_IPS` stay exempt; `[webdetector] EDGE_BAN = 0` turns it
  off. The edge also keeps its own copy, refreshed every few seconds with
  only what changed, and checks it before any other exemption: a visitor
  holding a challenge cookie, the cPanel/webmail proxy hostnames,
  `/.well-known/`, static files and recently allowed requests. That check
  starts in log mode (`[webdetector] EDGE_BAN_MODE = log`): it logs
  `would_block edge_ban` once a minute per address and counts it (`cfm debug`,
  `GET /api/v1/webdet/edge-ban`) until set to `enforce`. The edge config gains
  a `cfm_edgeban` shared dict; until the edge reloads it, the copy lives in
  the existing decision cache. Not covered yet: the cPanel/WHM/webmail ports
  (2083/2087/2096), the challenge page itself and `/cfm-admin`.
- **A challenged POST can no longer slip past the WAF through its resume
  link.** When a POST without a query string was challenged, the client got
  a resume link carrying a one-time token. Following that link raised an edge
  error, and under fail-open (the default) the stored POST went to the site
  without the WAF re-checking its body, traffic rules or the per-IP decision.
  The client did not even have to solve the challenge: it could follow the
  link itself, once, from the same IP and site. Only the body it had been
  challenged with could be sent this way; a request the WAF blocks is never
  stored. The replay now goes through every check, and one sent without
  solving is refused while the challenge stands.

### Fixed
- **The edge logs rotate every day again on EL9 / CloudLinux 9 (and Debian
  11+ / Ubuntu 22.04+).** There the
  system's `logrotate.service` runs with `/usr` read-only
  (`ProtectSystem=full`), so its nightly run failed on every OpenResty log
  under `/usr/local/openresty/nginx/logs` (`Read-only file system`) and the
  unit ended `failed`. Those logs were rotated only when one passed 2 GB, so
  some went months without rotating. The package now installs a small
  systemd drop-in that lets the unit write that directory.
- **A shorter automatic ban no longer cuts a longer one short.** When two
  detectors banned the same IP, the later ban replaced the earlier one, so a
  1-hour web-detector ban of a scanner turned its 7-day WAF ban into an hour
  (mars, 9 Oct: the scanner was back after the hour). Automatic bans (the
  detector sections, challenge self-protection) now only add or extend a ban;
  a longer or permanent ban stays, and the detector log line says "longer ban
  kept". Manual bans from the CLI and API still set exactly the time the
  operator asks for. On the default `nft` engine two bans of one IP arriving
  at the same moment in the daemon (automatic or manual) no longer race
  either: the shorter could still win.
  Mail and Slack alerts say "longer ban kept" too, in the built-in templates
  and the reference `notify.conf` (an existing `/etc/cfm/notify.conf` keeps its
  own subject). One effect to know: a lenient (GR/CY) ban of an IP that
  another section already banned for longer no longer shortens that ban.
- **A ban no longer fails when the firewall is slow to answer.** Automatic
  bans first read the block set; when that read failed (an `nft` timeout under
  load) the IP was not banned at all, and nothing said why. They now ban it
  anyway and log the reason: on the default `nft` engine only if no ban holds
  it yet (a longer ban stays), on `nftlib` the old way (which may cut a longer
  ban short). A ban that still fails shows `No (block failed: …)` on the
  detector log line.
- **A challenged WordPress save is replayed without an edge error.** When a
  challenged POST had no query string (`/wp-admin/post.php`), its replay
  after the solve raised a Lua error at the edge (`set_uri_args` got nil);
  under fail-open (the default) the save still reached the site, but the URL
  kept the `?cfm_rt=` token; under fail-closed it got a 500 and was lost.
  Seen on rigel and orion.
- **The WAF hit-rate counters' background push no longer fails about once
  a day per node.** It failed with `attempt to index upvalue 'SH' (a nil
  value)` (every node since September): it read state left over from the
  request that scheduled it. The next push usually restored the counts, but
  the last one of an hour could be lost. It now carries what it needs with
  it, and an error reaching the daemon no longer aborts it either.
- **`/dev/members.db` and similar paths no longer trip the `/dev/mem` rule
  (324).** It matched the text anywhere; `/dev/mem` and `/dev/kmem` now have
  to be the whole name.

## 2026.10.09

### Added
- **Shadow signal for bursts the origin's own WAF blocks.** An IP that sends
  30 or more POSTs a minute to one site, all answered 403 by the site's own
  WAF (Wordfence, ModSecurity), is now logged to `cfm.abuse_shadow.log` as
  `signal=origin_403_burst verdict=would_ban`. CFM had let such traffic through
  silently: the TranslatePress exploit on titan was 115 of them in a minute.
  WordPress's own "-1" nonce refusals are left out, because real visitors on a
  cached page send bursts of those, and verified good bots are logged as
  exempt. The `abuse_shadow` MCP tool lists the top offenders with how many
  ordinary requests each sent. Log-only: nothing is challenged or blocked. On
  by default wherever `ABUSE_SHADOW = 1`; the threshold is
  `ABUSE_SHADOW_ORIGIN403_PER_MIN`. The edge's log feed to the daemon gains a
  13th column naming the upstream, so CFM's own challenge server's 403s are not
  mistaken for the site's; until the edge reloads after the upgrade they can be.

### Security
- **A known scanner's attack now gets the scanner banned.** A request from a
  self-declared scanner (sqlmap, nikto, nuclei, zgrab, a fake legacy Internet
  Explorer UA) was blocked by the bad-User-Agent rule (201) before any other
  rule ran, and that rule does not ban. So sqlmap sending a SQL injection, or
  nuclei probing a CVE, got a 403 but never the 6-hour ban or the CVE alert
  the same payload earns from any other client. The SQL-injection, command
  injection, CVE and other banning rules now get the first word; a scanner
  request with no such payload still gets its 403, labelled as before.
  Such requests now also count toward the wp-login / xmlrpc burst rules, so
  a scanner hammering those can be banned by them too. An operator who armed
  the bad-UA ban (`BAD_UA = 1` in `[waf_security]`) now loses it on a
  request where an earlier non-banning block rule (the held TranslatePress
  rules, or a family set to 0) also matched. Commercial scanners carry the
  same scanner User-Agents (Nessus, Acunetix's `AWVS`, AppScan): an
  authorised scan, such as a customer's own or a PCI ASV scan, whose probes
  trip a banning rule now gets the 6-hour ban and the alert too. Exempt its
  source from the ban with `ALLOW_NETS` (or `ALLOW_UA_CONTAINS`) in
  `[waf_security]`; the request itself still gets its 403, as before.
- **Site Cache writes far less to disk under abuse.** The static-asset cache
  stored a full copy for every distinct query string, and a HEAD or an
  aborted download still stored the whole file: five HEAD requests with random
  query strings on a 20 MB image wrote about 96 MB, and only the 10 GB
  `max_size` stopped it, too late for a shared cPanel `/var`. Now every cache
  zone keeps 2 GB of the disk free (`min_free`, checked about every 10
  seconds), a static asset is stored only on its second request (so a one-off
  random query is never stored), and a response declaring 10 MB or more is
  never stored. A cached asset therefore takes one more trip to the site
  before it is served from the cache. The limits that remain are listed in
  docs/site-cache-design.md (the disk rails).
- **A flood of junk TLS fingerprints no longer switches off an armed
  fingerprint deny.** The edge asks the daemon about at most 50 new
  fingerprints a second per server; a client offering rotating cipher lists
  used that budget up, and every fingerprint whose 30-second cache had
  lapsed then went unchecked, an armed farm's included. A fingerprint that
  was armed when last asked is now still asked, from a small reserve the
  flood cannot spend, and keeps its last answer if even that runs out (then
  a disarm, an allow-listed fingerprint or an expiry can reach a flooded
  server up to 10 minutes late; the `FP_POLICY = 0` kill switch is
  immediate). A fingerprint not asked about in the last 10 minutes (new, idle,
  or since a restart) still passes while the flood lasts, as before.
- **The ClamAV inline-scan bypass for cPanel account transfers matches the
  path the server runs.** It (and the module's excluded paths) matched the
  request line as sent, so a `/acctxfer/../` prefix skipped the inline
  verdict for any upload. The WAF's traversal rule (103) already blocks that
  request by default; this closes it where the rule is off, held at
  log-only, excluded for the site, or the WAF has failed open.
- **The XML-RPC brute-force and pingback rules can no longer be skipped by
  claiming to be Jetpack.** Rules 510-512 let through any request carrying a
  Jetpack marker (`?for=jetpack`, a Jetpack or WordPress.com User-Agent, or
  the word "jetpack" in the body), all of which the client chooses; a marker
  now counts only from the networks Jetpack publishes (overridable as
  `xmlrpc_jetpack_nets` in `cfm_waf_config.lua`). The multicall and pingback
  rules also read the called method as WordPress does, in the first 32 KB of
  the body that the edge reads: padding the request past 2 KB, writing
  `system&#46;multicall`, or tricks with comments and inner tags hid it. A
  call padded past those 32 KB is now reported (log-only for now).
  And the XML-RPC and login burst counters count atomically across nginx
  workers.
- **Requests under `/.well-known/` are inspected unless they are a plain
  fetch.** The whole prefix skipped the WAF, the IP block and the challenge
  (for certificate validation). On a WordPress site, which routes any missing
  path to its `index.php`, that made the whole site reachable without them
  under `/.well-known/x?…` or a POST, and a shell dropped in `.well-known/`
  too. Only a GET or HEAD of a file, with no query string, no script
  extension and no escaped or dot-segment bytes in the request line, is
  exempted now (and CalDAV / CardDAV discovery): Let's Encrypt / AutoSSL and
  CA validation, `security.txt`, MTA-STS, app-association files and
  calendar/contacts setup keep working. A `/.well-known/webfinger?…` lookup
  is now challenged while its site is. The traffic-scoring side follows the
  same rule, so a scanner probing `/.well-known/x.php` is scored as well. And
  a request such as
  `/xmlrpc.php/x.css` (a PHP script with a static-looking tail) no longer
  reuses a visitor's cached allow for static assets, so the traffic rules and
  throttles that apply to `xmlrpc.php` run for it; nor does a POST or a
  request with a query string to a static-looking path (WordPress serves a
  missing `/x.svg?rest_route=…` from its `index.php`).
- **Four ways to slip a webshell past the upload rules are closed.** A
  filename split over two header lines (`filename="shell.p` + line break +
  `hp"`, or `file` + line break + `name="shell.php"`) is `shell.php` to PHP
  but was invisible to the filename rule (401); it now also checks every
  filename PHP itself registers. The PHP-in-zip check (414, and the SP Page
  Builder rule built on it) stopped after 512 zip headers, so 512 decoy
  headers in a form field before the real zip (the ANTONKILL vector) hid its
  webshell entry; it now reads them all, at a fixed cost per header. The
  upload-content rule (402, and the polyglot and SP Page Builder rules that
  share its matcher) missed short PHP tags written `<?=\func(…)`,
  `<?=/**/func(…)`, `<?=print`…``, `<?= new …`, `<?=0||func(…)`,
  `<?=1;func(…)` or `<?=true?func(…):1`; it now reads what comes after
  `<?=` much as PHP does, still without firing on stray bytes in images or on
  a ticket that quotes template code (`<?= __('Login') ?>`,
  `<a href="<?= BASE_URL ?>">`). And 402 only reads the
  first 2 KB of the request, so a webshell after 2 KB of image data went
  unseen: the new rule 415 reads each uploaded file, from its start to the
  16 KB multipart scan budget, for PHP / JSP tags, including the
  `<? echo …` / `<?system(…)` short open tag (in files only: a support
  ticket quoting it is not flagged). It ships log-only for burn-in; promote it in
  `cfm_waf_config.lua` once its hits look clean (docs/waf.md, rule 415).
- **Four ways to hide a payload from the WAF's scan are closed.** A JSON
  body's escapes were scanned as written, so `1\u0027 OR
  \u00271\u0027=\u00271` (a quote tautology once the app decodes it) passed
  the SQL-injection rule; printable `\u00XX` escapes and `\/` are now
  decoded for the scan (an escaped backslash stays one, so the WordPress
  editor's `\\u0027` attributes stay text, and newlines stay `\n`, so SQL
  examples in a post's code blocks do not read as injections). JSON and XML
  sent under a media type like `application/vnd.api+json` or
  `application/soap+xml` were scanned only to 2 KB instead of 32 / 16 KB. On
  a GET, 2 KB of padding in the query string pushed a `php://` wrapper or a
  serialized PHP object out of reach of the rules that block them; the query
  is now scanned to 8 KB, as the injection rules already did. And
  `;wget+http://…` or `|sh+…` in a query string (`+` is a space there)
  slipped past the command-injection block rule, which already blocked the
  `%20` spelling. Legitimate JSON with escaped quotes, accents, HTML, URLs
  or code, and office-document uploads, are unaffected.
- **A POST body sent without a Content-Length, or declared larger than 1 MB,
  was never inspected by the WAF on most routes.** A chunked upload
  (`Transfer-Encoding: chunked`), an HTTP/2 request without the header, or a
  body padded past 1 MB reached a clean-URL route (`/checkout`, a custom
  router, an API path outside the WAF's list of known endpoints) with its
  body unread, so a SQL injection or webshell in it went straight to the
  site. The edge now reads such a POST body (its first 32 KB, as for any
  body) where nginx buffers it anyway (the main `location /`; the PHP/admin
  and media locations keep streaming, and a PUT or PATCH keeps the old size
  rule). These bodies start in burn-in: the request is decided as before,
  and a hit only the body produces is recorded as log-only, with an
  error-log line `waf_body_burnin would=<action>`. Once that looks clean,
  `CFM_WAF_BODY_BUFFERED_ENFORCE=1` enforces them. This needs the edge
  config shipped with this release (`location /` sets `$cfm_body_buffered`;
  the server default and the streaming locations clear it); with an older
  one these bodies stay unread, as before. Separately, a body the edge
  cannot read at all (an HTTP/3 POST without Content-Length) no longer skips
  every check: reading it raised an error that, under the default
  `CFM_FAIL_OPEN`, sent the request straight to the site past IP blocks,
  challenges and traffic rules (even to `/wp-login.php`). It is now logged
  as `waf_body_unread` (once a minute per IP) and the request goes on
  through those checks; with `CFM_FAIL_OPEN=0` it still gets a 500 where it
  did before. Also, WooCommerce's `/?wc-ajax=` endpoint, which is on that
  list, never matched it; a wc-ajax body the old size rule would not have
  read starts in the same burn-in. See docs/waf.md, "Which request bodies
  the WAF reads".
- **A request that tripped a log-only WAF rule skipped every check after the
  WAF.** The edge sent it straight to the site, so an IP block, a site under
  challenge or Under-Attack Mode, a traffic rule, a throttle, a
  challenge-armed fingerprint and a forced-challenge location (e.g. a login
  page) all let it through. Anyone could trigger that on purpose: one header
  such as `X-A: ${date:}` trips the log-only Log4Shell rule. A log-only hit
  is now recorded as before and then goes through those checks like any
  other request; `X-CFM-Action` still reads `logonly` when it is allowed,
  and such a request is never served from the micro cache. Separately, an
  error inside a WAF rule no longer skips those checks either: with the
  default `CFM_FAIL_OPEN` the request goes on without the WAF (logged as
  `waf_error` with the rule's stack, reported as `X-CFM-Action: waf_error`
  when allowed, and never micro-cached); with `CFM_FAIL_OPEN=0` it still
  gets a 500.
- **One crafted request could hold an edge worker for up to a second.** Five
  WAF checks re-scanned the same bytes over and over on purpose-built input:
  the WordPress page-template check (rule 10017) on a 32 KB form upload took
  0.5-0.9 s, the Gravity Forms uploader check (10010) 0.2 s, and the
  debug-toggle, command-injection and CRLF checks 20-160 ms on a 2 KB query
  string. Any unauthenticated visitor to any site could send them in a loop.
  Each now reads its input once; the same requests take under 10 ms in
  total, what any request of that size costs. Four of the checks give
  exactly the answers they gave before. Rule 10017's fallback scan now reads
  each form field name only up to its first `;` or space, at most 96 bytes,
  and does not look inside a name it has read. The names it stops matching
  are: a `name=` inside another field's name, or after only a space, neither
  of which PHP reads as a field; a name padded past 96 bytes with %-encoded
  spaces, which PHP (it does not decode a form field name) never reads as
  `pagename`; and a `pagename[...]` array whose `]` is past that point,
  which WordPress never uses as a page path. PHP's own reading of the
  request, which the rule checks first, is unchanged.
- **A repeated request header no longer switches the WAF off for that
  request, or loses its ban.** Two `Content-Type` headers crashed the
  polyglot-upload check (rule 412); the edge fails open, so every later WAF
  rule (the PHP dropper scanners, TranslatePress 10018-10020, path traversal
  101/103) and the rest of the edge's checks (IP blocks, challenges, traffic
  rules) were skipped and the request reached the site. The check now reads
  the Content-Type and its boundary the way PHP does (a second header, a
  boundary cut at a comma, an empty boundary, a media type that is not
  multipart first), so it can no longer be pointed at a different boundary
  from the one the site's upload parser uses. Separately, a WAF hit whose
  request repeated `User-Agent`, `Referer` or `Content-Type` was reported to
  the daemon in a form it refused, so the hit was dropped whole: no ban, no
  `cfm.waf.log` line, no history row; that report now carries each header's
  first value. The xmlrpc / login burst counters keep counting per IP across
  all of a server's sites, as before; that is now explicit in the code, and
  a new test fails any module under `configs/lua/` that reads an undeclared
  global.
- **WAF rules 10018/10019/10020 block the TranslatePress account takeover
  (CVE-2026-19632, TranslatePress 3.3.1 and older; fixed in 3.3.2).** An
  attacker asks for the admin's password reset in translation preview, so the
  plugin stores the reset mail, key included, as a translatable string. They
  then read it back through an AJAX action that answers anyone. Seen on titan
  on 2026-10-08 (villadimitramykonos.com). Rule 10018 blocks the reset request
  (`trp-edit-translation` on a lost-password POST); the fleet's retained
  edge logs show the attack and nothing else. It is armed: a 6 h ban and a
  `WAF/CVE-2026-19632` alert. The plugin's editor preview adds that parameter
  to every form, so the same request from a logged-in user, most likely a
  translator, is filed as rule 10020: still a 403, but no ban. Rule 10019 blocks
  the read-back (`trp_get_translations_regular` with `string_ids` and no
  WordPress login). Its ban is held in code (`RULE_10019 = 1` arms it), because
  a translator whose login expired with the editor open sends the same request.
  The rules read the request the way PHP does and count any value of a
  repeated field. Updating the plugin is still the fix: an admin whose own
  language is a secondary site language has the mail stored without the preview
  trick, and a field placed where the WAF reads no body (past its 32 KB window,
  or a chunked POST outside its body allowlist) is not seen.
- **A crafted POST could freeze an edge worker for seconds (WAF rule 520,
  removed).** Rule 520 (SP Page Builder contact-form relay, released
  2026.10.06) scanned the posted recipient with a pattern that slows down
  quadratically on input it does not match. One ~30 KB POST carrying
  `addon=ajax_contact`, sent to any site on the edge (not only SP Page Builder
  ones), held an nginx worker for about 7 seconds; a few per second could tie
  up every worker. The rule is removed (see Removed). Until this release is
  installed, turn it off with `rule_form_relay_sppb_contact = "disabled"` in
  `/etc/cfm/cfm_waf_config.lua`.

### Fixed
- **The login brute-force rule (501) now covers direct visitors, and only
  counts real login attempts.** It skipped every visitor not behind
  Cloudflare, so most brute force against `wp-login.php`, Drupal, Joomla,
  OpenCart, Magento and custom login forms went unseen by it. It also counted
  every request to those pages, so an OpenCart or Joomla admin clicking
  through eight admin pages in 20 seconds got a challenge. It now counts only
  a POST that submits a password (8 in 20 s per IP, a JSON login too), not
  page loads, admin navigation or admin uploads; a login padded past the
  32 KB the WAF reads still counts. For direct visitors it only logs for now (burn-in); behind
  Cloudflare it challenges as before. cPanel / WHM / webmail are unchanged:
  cPanel's own login-failure detector bans there.
- **Two upload rules no longer ban people for innocent file names and text.**
  The upload file-name rule (401) matched its sensitive names anywhere in a
  name, so uploading `Q3.environmental-report.pdf` (`.env`) or
  `superuser.ini` (`user.ini`) blocked the uploader and banned their IP for
  6 hours; the names must now stand on their own (`.env`, `.env.local`,
  `.htaccess`, `user.ini`, `web.config` are still blocked). The
  upload-content rule (402) blocked a multipart form whose TEXT fields
  mentioned `$_POST` or `$_GET`, such as a support ticket about a form
  handler, or an attached `error.log` quoting one; it now looks for those
  only inside uploaded files, next to a PHP short open tag (`<?`) or
  `<script language="php">` in the same file (`<?php`, and `<?=` followed by
  code, still block on their own within the scanned window). An XML header PHP cannot run, such as an SVG's
  `<?xml version=…?>` or a photo's XMP `<?xpacket begin=…?>`, is not an
  open tag. A name hidden behind URL encoding is caught: `x%2f.env` as
  before, and now `%2ehtaccess` too.
- **Mail hijack false positive: the node's own address.** A site's form or
  mailer authenticating to the server it runs on connects to the server's
  public IP; that login counted as a remote one, with the node's country
  (orion, 9 Oct: info@nothak.gr paged as "DE, GR, US" — DE was orion
  itself). The node's own addresses are no longer hijack sources.
- **WAF rules that match a request parameter by name now read the name the way
  PHP does.** PHP ends a name at a NUL byte and turns `.`, a space or an
  unmatched `[` into `_`, so `pagename%00x=…` reached WordPress as `pagename`
  while rule 10017 (CVE-2026-87902) did not see it. Rule 10017 and the new
  TranslatePress rules now match those forms. Rule 10017 also reads the body
  the way PHP parses it: the parser is chosen by the Content-Type's media type,
  and multipart bodies follow PHP's own rules (header continuation lines, the
  5120-byte line cut, quoting). Before, a urlencoded body whose Content-Type
  merely mentioned `multipart/form-data`, or a multipart field name split over
  two header lines, hid a `pagename` traversal from it. The reader is checked
  against a real PHP (`scripts/tests/php_request_fields_oracle.py`).
- **A request padded past 100 header lines no longer hides headers from the
  WAF.** The edge read only the first 100 header lines, while nginx forwards
  them all: any header after line 100 was invisible to the WAF. That included
  a CVE rule's marker header (rule 10012), a second Content-Type carrying the
  multipart boundary, and the body headers the PHP field reader needs. The
  WAF now reads up to 1 000 header lines, on the web edge and the panel ports.
  A request with more is logged (`header_lines=over_max`, one line per IP a
  minute in the edge error log) and, for its burn-in, passed with its first
  1 000 lines inspected. Set `max_header_lines_mode = "block"` in
  `/etc/cfm/cfm_waf_config.lua` to refuse it (`431`; on the panel ports a
  block when the panel WAF enforces). `max_header_lines` sets the limit
  (never below 100); `0` turns the check off.

### Changed
- **The WAF's percent-decoding is faster.** The normalized scan surface every
  rule reads, and the `filename*=` upload check, now decode `%XX` through a
  lookup table instead of a Lua call per escape: a 30 KB percent-encoded body
  normalizes in ~0.6 ms instead of ~1.5 ms, with the same bytes out. The PHP
  field reader shares the same decoder (it already used a table).
- **A `RULE_<id>` line in `[waf_security]` now honours an inline comment.**
  `RULE_511 = 2 ; note` used to fail to parse and silently fall back to the
  family default; it now applies 2, like every other detectors.conf scalar
  since the earlier inline-comment fix. Check your `RULE_` lines if any carry
  a comment.
- **WAF hit pushes are de-duplicated per block rule, not per family.** A
  family can mix armed and held block rules (the TranslatePress rules 10018
  vs 10019/10020), and a held rule's hit used to suppress the armed rule's
  ban and alert for the same IP for a minute.

### Removed
- **WAF rule 520 (`rule_form_relay_sppb_contact`, family `WAF_FORM_RELAY`).**
  It never matched the abuse it was written for, and could not have:
  - The spam on titan (hotellito.gr, ~1 500 mails) came from the
    `form_builder` addon with the site's own `Cc: {{email}}` setting, so every
    submission was copied to the address the visitor typed. Those requests
    are identical to an honest visitor's; the fix is the form setting
    (removed on 20 sites on 2026-10-07).
  - The recipient list it watched for never delivers: Joomla hands PHPMailer
    one address, and PHPMailer rejects a list.
  - A rework that also covered injected `Cc:`/`Bcc:` headers had to mirror
    PHP's request parsing on every request; review kept finding CPU-DoS and
    bypass cases in it, which is too much risk for the few sites it could
    protect.

  What protects a site instead: update SP Page Builder to 3.8.8 or later
  (3.8.0 to 3.8.3 still post these settings as plain base64 a bot can edit;
  3.8.4 to 3.8.7 were not checked; correction to the 2026.10.06 entry, which
  said 3.8), and don't put `{{...}}` placeholders in a form's Cc/Bcc. A
  leftover `rule_form_relay_sppb_contact` line in `cfm_waf_config.lua` or
  `FORM_RELAY` line in `detectors.conf` is ignored; delete it at leisure. Id
  520 stays reserved.

## 2026.10.08

### Added
- **Spamhaus through DQS.** The fleet resolves through public resolvers, and
  Spamhaus refuses `zen.spamhaus.org` queries from them, so the RBL check never
  saw Spamhaus. `MAIL_RBL_SPAMHAUS_DQS_KEY` in cfm.conf makes it ask
  `<key>.zen.dq.spamhaus.net` instead. The key is never logged or shown, and
  `cfm debug` redacts it; editing it (or `MAIL_ABUSE_ALERT`) in cfm.conf
  applies without a restart.

### Changed
- **Bounces are not a queue hog.** Frozen bounce messages (null sender: exim
  `<>`, Postfix `MAILER-DAEMON`)
  piling up are the normal state of a cPanel queue; `mail_queue_hog` no longer
  counts them, and an open one closes saying so.

### Fixed
- **Mail hijack false positive:** a mailbox read by mail services for its
  owner (Mail.ru / VK's collector behind the myMail app, a mail app or CRM on
  Google Cloud) counted as logins from Russia and the US. Those networks now
  count as one source with no country, like Gmail / Outlook / Yahoo / iCloud
  (orion, 8 Oct: info@socialpower.gr, GR + RU + US, one owner).
- **Fewer mail spike pages:** a MILD volume spike (under 50 messages in 2 h
  and under 10× its usual, nothing abusive in its context) no longer alerts;
  21 and 37 messages at 4–5× a small sender's usual paged the channel for
  nothing. A small spike far above its usual (a quiet site hacked) or one
  sending as a foreign domain / in the contact-form pattern still alerts.

### Added
- **Mail abuse reaches the team channel.** Every 5 min the Mail Monitor now
  raises `mail_script_spike` (a site's scripts — a hacked site or an abused
  contact form — sending far above that user's own history, with the script
  directory, the envelope sender and the number of different recipients),
  `mail_outbound_spike` (a mailbox doing the same) and `mail_hijack` (a
  mailbox logging in from ≥ 3 countries, or ≥ 10 IPs in 2+ countries, within an hour), and
  resolves each with `mail_recovered`. They go to `detection_history` for
  cfm-web to alert on. On titan a contact form sent ~1 000 messages a day for
  days without tripping `exim_relays`' fixed 110-per-15-min threshold; the
  per-user baseline sees it in the first hour. Alert only. `MAIL_ABUSE_ALERT
  = 0` in cfm.conf turns it off. Each finding shows the decoded subject, the
  top recipient domains, the contact-form pattern (the owner copied on every
  message plus a new outside address each time) and a sender spoofing a
  foreign domain or another mailbox, so a newsletter can be told from spam.
  The `mail_traffic` MCP tool lists them under `abuse` (admin) and
  `whats_wrong` reports them. See `docs/mail-abuse.md`.
- **More mail-abuse findings.** `mail_bounce_spike`: a sender whose mail
  bounces in bulk (≥ 20 bounces and ≥ 25 % in 2 h), with the main reason —
  a form or hacked account writing to harvested addresses. `mail_queue_hog`:
  one sender holding half of a queue of 100+ messages. `mail_rbl_listed`: a
  server IP on Spamhaus ZEN, SpamCop, Barracuda or PSBL (checked every
  30 min; a list that refuses the resolver is logged once, never read as
  "delisted"). `mail_hijack` now also counts IMAP/POP3 logins from dovecot,
  and no longer counts Gmail / Outlook / Yahoo / iCloud fetching a mailbox as
  many places (their network is one source), a phone's rotating IPv6 (one
  /64), or a home plus a VPN (many addresses need 5+ outside the main
  country).


### Fixed
- **Backup alerts: no more duplicates or false "OK again"** (review of the
  backup check). One job is one alert: only the worst of stuck / failed /
  stale / partial is published, so a failing job no longer also pages
  `backup_stale` a day later. A change of state (partial → failed, failed →
  stuck) resolves the old alert as "now failed: …", not "backup OK again". A
  disabled or removed job says so. A restart no longer resolves and re-opens
  an open `backup_check_error`, and a hung-check alert resolves after a
  restart. An adapter gone for 24 h (uninstalled) resolves its alerts. One
  JetBackup job with no logged run no longer freezes every other job behind a
  `backup_check_error` (an empty or truncated log history still is one: it
  must never read as healthy). A shared Proxmox storage running low is
  reported by one node, not all; offline is still reported by each node whose
  mount failed. A Proxmox stuck run folds with the node's failed / stale. New:
  `backup_no_job` for a Proxmox node hosting guests (not just templates) with
  no enabled vzdump job, when they are not already `backup_uncovered`.
- **Node faults are marked sent only once stored.** With no history store or
  a failed write a finding or recovery was marked delivered and lost; it is
  now retried. Same for the mail-abuse findings.
- **Mail-abuse alerts (review of #1556).** A new sender pages critical only
  from 200 messages in 2 h. A new MAILBOX that opened as a warning and stays
  under 200 settles after a day at a steady volume ("now its usual volume");
  a script spike or a critical one never settles — a hacked quiet site opens
  exactly like a new sender. The script directory is the sending user's own (a
  busy node pointed at another tenant's site). The contact-form pattern no
  longer matches a site mailing only its owner. Greek and Cyrillic subjects
  in legacy charsets decode. `whats_wrong` shows alerts still open in
  cfm-web and ignores a check that stopped running.
- **Security: scoped history.** `history/events` never returns `mail_*` or
  `backup_*` rows to a scoped (cPanel) caller, even with the server hostname
  in scope.
- `frontend_working` is `unknown`, not `none`, when no edge is found and the
  DNAT state cannot be read.

### Added
- **Backup check: a fixed backup now says so (`backup_recovered`).** When a
  backup finding goes away (the next run succeeds, the CLI reads again, a
  hung check finishes) the node records `backup_recovered` under the same
  key. cfm-web uses it to close the open alert: it posts RESOLVED and stops
  the reminders, instead of reminding about a backup that already works
  until someone presses Ack. Nodes without a cfm-web that knows the type
  just keep it in their history.
- **`GET /api/v1/health/backup` and the MCP tool `backup_status`:** the node's
  latest backup check — every job with its last result and last successful
  run, the open findings, and how old the check is. cfm-web polls it for its
  fleet Backups table and to notice a node that stops reporting backups.

### Fixed
- **A node with no web frontend is no longer "frontend down".** On a host
  with no angie/openresty/nginx at all — mailcow in docker (mymail), a
  nameserver, a backup box — `system_health` reported `frontend_working:
  down` ("frontend unknown") and `whats_wrong` raised a critical "frontend not
  serving" every time, so the daily digest flagged mymail as broken while it
  served mail fine. Such a host now reads `frontend_working: none` and is not
  a finding. A stopped edge is still detected and still `down`, and so is a
  host with DNAT on and no edge.
- **Backup check: a JetBackup "Partially Completed" run is no longer reported
  as failed.** JetBackup's log status is 1 Completed, 2 Failed, 3 Aborted,
  4 Partially Completed, 5 Never Finished; the check read 2 as partial and 4
  as failed. A partial run (on orion and virgo most nights: one account over
  its own disk quota) now raises `backup_partial` and counts as a backup for
  freshness, so the false `backup_failed` + `backup_stale` alerts on those
  nodes resolve on the next check after the upgrade.
- **`backup_partial` is `info` (was `warning`)** for JetBackup, Virtualmin and
  Proxmox: it shows on the cfm-web dashboard but reaches no warning/critical
  alert route. A partial run is the normal state of a hosting node (one
  customer over quota); vzdump still escalates to `backup_failed` after 3 in a
  row, and a job that stops backing up goes `backup_stale`.

## 2026.10.07

### Added
- **Backup check: the health detector now notices backups that stopped.**
  On orion the daily JetBackup job failed on 19 and 20 Sep and then sat on
  one account for 16 days; nobody knew until a customer asked. Every 15 min
  the health detector now reads JetBackup 5 (cPanel and DirectAdmin),
  Virtualmin scheduled backups and Proxmox vzdump, whichever is installed,
  and records `backup_failed`, `backup_partial`, `backup_stale`,
  `backup_stuck`, `backup_uncovered` (Proxmox guests in no job, reported by
  the node that hosts them), `backup_dest` (backup storage offline or nearly
  full), `backup_no_job` (nothing enabled) and `backup_check_error` (a
  backup system unreadable twice in a row, or a hung check) in detection
  history, where cfm-web picks them up. Weekday-only, weekly and brand-new
  jobs are judged on their own schedule, so a weekend is not a missed backup.
  One alert per broken job (not one per failed run); what was published is
  remembered in `/var/lib/cfm/backup_published.json`, so an upgrade does not
  re-announce open findings. Proxmox `WARNINGS: n` runs are successes; a node
  whose vzdump ends in `job errors` every night goes stale. Virtualmin
  destinations are shown without their credentials. `BACKUP_DEST_FREE_PCT = 0`
  turns the destination free-space check off.
  "Stale" counts from the last SUCCESSFUL run: JetBackup advances a job's
  "last completed" even when the run failed. No local mail is sent. Knobs:
  `[health] BACKUP_ALERT`, `BACKUP_EVERY`, `BACKUP_STUCK_AFTER`,
  `BACKUP_PROXMOX_STALE`, `BACKUP_DEST_FREE_PCT`. See `docs/backup-check.md`.
- **WAF rules that only match behind a stronger rule are now measurable.**
  The WAF log and detection history recorded only the headline rule of each
  request. A logonly rule that runs after a stronger one never appeared at
  all: a 30-day fleet read found zero hits for the 13 dropper/backdoor
  scanners (421-425, 430-436, 439), which sit behind rules 402/404. That left
  no data to decide whether to promote or retire them. Each WAF event now also
  lists the other rules that matched the same request (`also_rule_ids`,
  record-only, nothing enforces on it). The WAF summary API counts them for a
  numeric rule filter when asked with `also=1` (`also_matches`; without it the
  filter stays headline-only), and the MCP `waf_rule_detail` shows them as
  `web_by_id`. The counts are sampled, not exact: the edge reports at most
  one event per IP, rule family and tier a minute, so read them as "does this
  rule fire at all", not as a rate. A rule after a blocking rule is still
  never evaluated on that request; this covers the challenge and logonly
  cases.

## 2026.10.06

### Changed
- **WAF rule 612 (missing fetch-metadata, logonly) measures more cleanly.**
  A 7-day read across seven nodes found real people and honest services in
  its "browser-claiming automation" pool. Now kept out of the pool, as
  self-declared bots: WP Rocket's SaaS fetcher (`WP-Rocket-SaaS`, which the
  old `wp rocket` token never matched) and SimilarTech's SMTBot. Google
  Mobile Ads WebViews (`afma-sdk`, a person tapping a paid ad) join TikTok
  under the `NO_FETCH_META_IN_APP` tag, which is never enforced even if 612 is
  promoted. Requests relayed by Google's front end (`,gzip(gfe)`) get their
  own `NO_FETCH_META_GFE` tag so they can be judged on their own counts; the
  string is spoofable, so they are not exempt. The rule stays logonly; nothing
  is blocked or challenged by this change.

### Security
- **New WAF rule 520 blocks spam relayed through Joomla SP Page Builder
  contact forms.** The page builder's `ajax_contact` addon mails whatever
  recipient the browser posts back, as a hidden base64 field. A bot adds a
  victim to that list and the site sends the spam. On titan, hotellito.gr sent
  ~990 such mails in 7 hours on 2026-10-06. Rule 520 blocks a submission whose
  decoded recipient list has two or more addresses and includes the email typed
  into the form, on a mail domain no other recipient uses. A real form never
  mails an outside visitor, so it ships at `block`.
  Its new `WAF_FORM_RELAY` family is held at 0 for autoblock during burn-in:
  the 403 already stops the mail, and `FORM_RELAY = 1` adds the 6 h ban once
  the fleet logs look clean. A recipient list without the visitor's address is only logged
  (`MULTI_RECIPIENT`), since an owner may save several addresses and a staff
  member may test the form. It does not block a bot that replaces the recipient
  outright, injects a victim on the owner's own mail domain or adds a decoy on
  the victim's, or pads the recipient past the WAF's 32 KB body window (logged
  as `BODY_PAST_WINDOW`). Updating SP Page Builder (3.8 or later) closes all of
  them.

### Fixed
- **The challenge page no longer serves the PoW to clients the decision
  exempts.** A challenged visitor's address bar shows the challenge page's own
  URL (`/__cfm_challenge?next=…`). Fetchers handed that URL fetched it
  directly: Google-Read-Aloud, Meta's link-preview and agent crawlers,
  Twitterbot, and Googlebot or Applebot from shared links. That location
  bypasses the edge decision, so none of the client exemptions ever ran for
  them: the challenge-exclude file, the verified good-bot exemption, and
  Challenge Access-Control. On rigel, Read-Aloud kept getting the challenge
  after its #1539 rule had loaded. On titan, meta-externalagent got it
  ~1 940 times in 14 hours (2026-10-05/06), and the link previews showed
  "Just a moment…".
  - The page now sends such a client straight to `next`. The cases are a
    verified good bot (`CHALLENGE_GOODBOT_EXEMPT`), a Challenge
    Access-Control match, or an exclude-file match.
  - The exclude match is skipped when a per-IP challenge or a country/ASN
    policy covers the client, because the file never lifts those.
  - A `next` that carries a `cfm_rt` still gets the page. That token is a
    challenged POST waiting for its owner, and no exemption cleared it.
  - The page's redirect loop breaker covers these redirects, and is now per
    HTTP method. If the edge still challenges the client at `next`, for a
    reason none of these exemptions lifts (a fingerprint policy, a WAF hit, a
    traffic rule), the client comes back once and then gets the page.
  - Each redirect is counted in bridge stats
    (`challenge_page_exempt_redirects`). The challenges log gets one
    `exempt_redirect` line per host per minute.
  - The breaker's loop line is now `next_redirect_loop` (it was
    `cleared_redirect_loop`), with a `why=` field.
- **A challenged POST is no longer lost to another client that opens its
  resume URL first.** When a POST is challenged, the edge stores it and
  replays it after the challenge, on the GET that carries its `cfm_rt`
  token. The edge deleted the stored entry before checking that the request
  came from the same IP and host, so the first GET with the token spent it,
  from any client. The token sits in the visitor's address bar while they
  solve, inside the challenge page's `next`. A fetcher handed that URL that
  solves the challenge and follows `next` (Google-Read-Aloud does both)
  could spend it before the visitor, and the visitor's save was lost. Only a
  request from the same IP and host now consumes the entry. Another
  client's GET leaves it in place, and an unclaimed one expires after
  `CFM_POST_RESUME_TTL_SEC` (90 s by default).

## 2026.10.04

### Fixed
- **nftlib engine: the cPanel DNAT redirect is replaced in one batch too.**
  `cfm dnat cpanel on`, every `cfm dnat cpanel bypass add/remove` and the
  panel failsafe's recovery deleted `cfm_panel_redirect` in one netlink batch
  and created the new one in a second: in between, panel traffic reached
  cpsrvd directly, and a second batch that failed left the panel DNAT off
  (seen live: `cfm dnat cpanel on --priority -250` on orion turned it off).
  Now it is one batch, as the web redirect already was, and a rebuild that
  fails keeps the old one. The 2026.10.04 entry said the nftlib engine
  "already did" this; that was true of the web redirect only.
- **`cfm dnat cpanel on` refuses a nat priority nft rejects** (-200 or below)
  before it reloads the panel listener or touches the firewall, as
  `cfm dnat on` does, instead of failing halfway with a long nft error.

### Fixed
- **nft engine: the web and cPanel DNAT redirects are replaced in one
  transaction.** `cfm dnat on`, every `cfm dnat bypass add/del`, the edge
  failsafe's recovery and a startup `NFT_DNAT_PRIORITY` change rebuild the
  redirect table (`cfm_redirect`; `cfm dnat cpanel on` the same for
  `cfm_panel_redirect`). The nft engine deleted the table and created the new
  one in a second `nft` run: in between, web (or panel) traffic reached the
  backend directly, without the edge, WAF or challenge, and a second run that
  failed left DNAT off. Now it is one batch the kernel applies all-or-nothing,
  as the nftlib engine already did: a replacement that fails keeps the
  working redirect, and a failed `cfm dnat bypass add/del` says the redirect
  with the previous list is still in force. One case does not keep it: when
  `cfm dnat on` to other listener ports fails, it reads the table after the
  failure and, if the redirect still points at the old ports, removes it
  (traffic goes straight to the backend, logged as an OFF transition; with
  intent ON the failsafe re-installs it once the edge answers on the daemon's
  ports). The edge may no longer listen on the old ports, and the failsafe,
  which probes the daemon's `HTTP_PORT`/`HTTPS_PORT`, would not notice. That
  was the nft engine's outcome before; on the nftlib engine it is new (it kept
  the stale redirect). Out-of-range ports are now refused before anything
  changes. Removing the old ports' accepts after the new redirect is in place
  is best effort on both engines: a failure there is a logged warning (the
  leftovers match nothing, the next reload prunes them), no longer a
  `dnat on failed` for a redirect that was installed.

### Fixed
- **The web DNAT accepts are no longer deleted and re-added on every reload.**
  After each ports apply (daemon start, any `cfm.conf` change) the daemon
  re-asserts the `ct status dnat` accepts for the edge listener (80 → 9080,
  443 → 9043). It used to delete them all and re-insert them one `nft` run at
  a time, so for that moment every new web connection DNAT'd to the edge hit
  the default drop (seen live: the three accepts got new handles on every
  `cfm.conf` touch, on both engines), and a failed insert left web traffic
  dropped until the next reload. They now follow the cPanel accepts' rule: an
  accept already above the drop is kept untouched (matched by its comment
  tag, so an older nft's print form doesn't count as a change), a missing one
  is inserted, and only then are extras (misplaced, duplicated, the other
  engine's tag) deleted, best effort. On `cfm dnat on` with new listener
  ports, the old ports' accepts now stay until the redirect has moved. The
  edge failsafe is unchanged (it turns DNAT off and on with `cfm dnat
  off/on`, not this re-assert).

### Fixed
- **The ports policy (TCP_IN/UDP_IN/TCP_OUT/UDP_OUT) is now written as one
  nft transaction, on both engines.** Every ports apply (daemon start, any
  `cfm.conf` change) used to delete the live `ct state new … @tcp_in_ports
  accept` and the catch-all NEW drops by substring and re-add them one `nft`
  process at a time, and to flush each port set before refilling it in a
  second run. For a moment on every apply the input chain had no default drop
  (all ports open) or no TCP_IN accept (new inbound connections dropped), and
  an error between a delete and its re-add left it that way until the next
  change. The sets, the input and output rules and the loopback exemption are
  now one `nft -f` batch the kernel applies all-or-nothing (a failed apply
  leaves the previous policy in place, and is re-planned and retried once).
  A re-apply that changes nothing writes no rule at all, only the set reload;
  DNAT accepts and every other feature's rules keep their place, and a rule
  the policy lacks is inserted where it belongs (portscan tracking above the
  DNAT accepts, so DNAT'd connections stay tracked). An existing output chain
  is no longer re-declared, so its policy is kept, and an existing port set is
  reloaded without being re-declared. Also fixed on the way:
  - a portscan TTL (`PS_INTERVAL`) of 60 s or more was looked for as `60s`
    while nft prints `1m`, so the four tracking rules were added again on
    every apply; such copies are now removed, and so are tracking and
    debug-port rules the config no longer has (an earlier TTL or mode, a
    removed debug port, or portscan turned off, which used to leave its
    tracking rules feeding `ps_pairs_*`);
  - a catch-all drop in another form (`tcp dport 0-65535 ct state new drop`,
    or with a counter or a comment) is removed instead of being left above
    the accepts; a narrower drop (a source, an interface) is never touched.
- **A strict `TCP_OUT` / `UDP_OUT` no longer cuts local traffic.** The egress
  allowlist in `inet cfm output` had no loopback exemption (input has always
  had `iif "lo" accept`), so narrowing `TCP_OUT` to e.g. `25,53,80,443`
  silently broke every local connection: PHP → MariaDB on `127.0.0.1:3306`,
  the edge → its origin or an app on a loopback port, an app → a local
  Valkey/Postgres. `oif "lo" accept` is now the first rule of the output chain
  on both firewall engines, exactly once, written on every ports apply (daemon
  start or a `cfm.conf` change) in the same transaction as the port sets, so a
  stricter `TCP_OUT` never lands without it.
  The shipped default (`0:65535`) was not affected; the allowlist now applies to
  traffic leaving for the network only. TCP_OUT was never an isolation layer
  between local accounts (it applied to root and the edge alike): a service
  listening on loopback TCP is reachable by every local user, so keep
  tenant-private services on unix sockets or behind uid-scoped rules.
- **Three more legitimate fetchers are no longer challenged: Meta's
  product-catalog fetcher, X's link-preview bot and Google Read Aloud.** A
  fleet scan of who the edge sent to the challenge page found each one
  challenged. The shipped `webdetector_challenge_exclude.txt` adds a rule for
  each, scoped to the operator's own network (ASN) so the same UA from anywhere
  else stays challenged:
  - `facebookcatalog` (Meta, AS32934) reads e-shop product pages for Facebook /
    Instagram shops. Its UA matched neither existing Meta rule. Rule:
    `asn=as32934; ua=*facebook*`.
  - `Twitterbot` (X, AS13414) builds X link previews. Rule:
    `asn=as13414; ua=*twitterbot*`. iMessage and Google Messages send a UA that
    also contains `Twitterbot/1.0`, from the user's own device; those requests
    are not on AS13414 and do not match.
  - `Google-Read-Aloud` (Google, AS15169) is the "listen to this page" fetcher a
    user triggers. Rule: `asn=as15169; ua=*google-read-aloud*`. AS15169 is
    Google's own network, not Google Cloud (AS396982), where a spoofing farm
    cycles fake bot UAs.
  - The file is a conffile: a node whose copy was edited locally gets the new
    rules in the `.rpmnew` / `.dpkg-dist` and needs them added by hand. The
    rules lift a vhost-wide challenge only on nodes running 2026.10.01 or later.

## 2026.10.01

### Changed
- **`cfm.conf` inline comments after a single space are cut, so the value
  before them applies.**
  - Before, a comment was cut only with two spaces or a tab in front of it.
    In `SYS_CT_MIN = "262144" # minimum entries` the whole string was the
    value; it did not parse, and the built-in default applied with no
    warning. A bool such as `KEY = 1 # on` read as off.
  - Now a `#` or `//` starts a comment when it follows a space, a tab or a
    closing quote (`"1"# on`). One that follows anything else stays part of
    the value (`http://…`, `a#b`, a value starting with `#` or `//`, as a
    raw or base64 key can), and so does one inside quotes (`"a # b"`, a JSON
    string, a quoted list such as `"a # b, c"`). Quote a value that really
    contains ` #` or ` //`.
  - A quote opens only at the start of the value or after whitespace or
    one of `,:[{(`, and closes only before the end, whitespace, a comment
    or one of `,:]})`, so a stray `"` or an apostrophe inside a word opens
    nothing. When a value leaves a quote open, the old rule applies, so it
    never keeps more comment text than before.
  - A credential (`AUTH_TOKEN`, `MCP_TOKEN`, `MAXMIND_LICENSE_KEY`, any key
    `cfm debug` redacts) that the new rule cuts shorter logs a warning once,
    without the value: quote it if the cut text was part of the secret. A
    changed `AUTH_TOKEN` also changes the keys derived from it, such as the
    MFA key when `AUTH_MFA_ENCRYPTION_KEY` is empty.
  - The stock `cfm.conf` has two lines with a one-space comment,
    `SYS_CT_MIN` and `SYS_CT_MAX`. Their values equal the defaults, so nothing changes unless you edited
    them; then your value now applies. On the nodes checked, those two are
    the only lines affected.
- **`SSLCOLLECTOR_SOCK_TOKEN` now lives in `/var/lib/cfm/secrets/`, not in
  `cfm.conf`,** the same way as the two `detectors.conf` tokens below. The
  daemon used to write a generated socket token back into `/etc/cfm/cfm.conf`,
  which left that conffile "modified" on every node (hence the
  `cfm.conf.rpmnew` / `.dpkg-dist` after every upgrade).
  - The token is in `/var/lib/cfm/secrets/sslcollector_sock_token` (root
    only), and that file is the one in use. It is created once: on the first
    start after the upgrade the daemon copies the token from `cfm.conf`, so
    the edge keeps working without a reload; otherwise it generates one. The
    daemon no longer writes `cfm.conf`.
  - After that the `cfm.conf` line is not used and can be set back to
    `placeholder`, the new stock value. Keep the line.
  - To rotate: set the line to `placeholder`, delete the file, restart.
  - `cfm ssl` / `cfm sslcollector` (and the cfm-admin "Rescan certs" button)
    send the token the edge has, `/var/lib/cfm/lua/cfm_token.lua`, which the
    daemon rewrites with the token it serves; the stored file is the
    fallback.
  - A `cfm.conf` token too long for a token file (4096 bytes or more) is not
    copied: a new one is generated.
  - If no token can be generated, the daemon keeps serving the one it
    already runs. With none running, the socket stays down instead of
    serving with the `cfm.conf` placeholder as its bearer.
- **`CHALLENGE_TOKEN` / `OPENRESTY_TOKEN` now live in
  `/var/lib/cfm/secrets/`, not in `detectors.conf`.** The daemon used to
  generate these per-host tokens into `/etc/cfm/detectors.conf`. That left the
  conffile "modified" on every node, so upgrades never updated it and left a
  `.rpmnew` / `.dpkg-dist` behind with the new stock settings in it.
  - Each token now lives in `/var/lib/cfm/secrets/` (`challenge_token`,
    `openresty_token`; root only), and that file is the one in use. It is
    created only when missing: copied from `detectors.conf` when that still
    carries a token, else generated. CFM never writes `detectors.conf`.
  - **Nothing changes on upgrade:** on its first start the new daemon copies
    the node's current token from `detectors.conf`, so no visitor is
    re-challenged. After that the `detectors.conf` value is no longer used
    (logged once if it differs) and can be set back to `placeholder`.
  - The stock file ships the two lines as `placeholder`. Keep them that way:
    never delete them or leave them empty. After a rollback, an older binary
    replaces a placeholder in place. It appends a missing line to whatever
    section is last, and an empty line makes it overwrite the line after it.
  - **When the token still rotates, by design:**
    - once on a Debian upgrade where you take the package's `detectors.conf`
      at the prompt: the old daemon, still running until `postinst` restarts
      it, may write a new token into the fresh file, which the new daemon then
      copies (set the line back to `placeholder` afterwards);
    - on a rollback to an older version, if its `detectors.conf` line is at
      `placeholder`: the older binary generates its own token there, and the
      next upgrade goes back to the stored one (two rotations). While the line
      still holds the token, a rollback changes nothing.

    A rotation re-challenges visitors who hold a clearance cookie
    (`CHALLENGE_COOKIE_LIFE`, 45 min stock) once.
  - To rotate a token: set its `detectors.conf` line to `placeholder` (a
    token still there would be copied back), delete its file, and restart.
  - To set a specific token (e.g. one shared by nodes behind a load balancer),
    write it into its file (root, `0600`) and restart; editing
    `detectors.conf` no longer changes a stored token. A file that holds no
    usable token (under 32 characters, quoted, a symlink) is never
    overwritten (nor a symlink followed): CFM logs it and runs another token,
    unstored, until you fix or delete it. An empty file is replaced.
  - `cfm health` reports the stored token (inside the daemon: the one it
    runs), and a token file that holds no usable token as missing.
  - The token step (and `cfm_bridge_config.lua`) now also runs when
    `[webdetector]` exists only in a `detectors.d/` overlay. A token set in an
    overlay is copied when the base file has no `[webdetector]` section, as the
    older binary ran it.

### Fixed
- **`cfm debug` bundles and the MCP detectors-config view now redact
  `MAXMIND_LICENSE_KEY` and `AUTH_MFA_ENCRYPTION_KEY`.** The secret-key
  matcher knew `token`, `secret`, `password`, `hmac`, `api_key` and
  `private_key`, but not `license_key` or `encryption_key`, so those two
  values went into a debug bundle in clear.
- **A `cfm.conf` value with two inline ` #` (or ` //`) no longer hangs the
  daemon and every `cfm` command.** For example `KEY = value #a #b`: the
  inline-comment scan kept finding the same ` #` and never returned, so the
  config never finished loading.
- **Meta's link-preview crawlers are no longer served the challenge page on a
  vhost-wide challenge.** Under a vhost-wide challenge (`suspicious_vhost`,
  `under_attack` or a manual one) the edge serves the challenge to every client
  without clearance. Rules in `webdetector_challenge_exclude.txt` were checked
  there only for IPs already seen on the vhost, and without the User-Agent, so
  a rule with a `ua=` condition (such as the shipped `asn=as32934; ua=*meta*`)
  never matched. Meta's crawlers (`meta-externalads`, `meta-webindexer`,
  `meta-externalagent`, `facebookexternalhit`) come from IPv6 addresses with no
  reverse DNS, so the verified-crawler exemption could never clear them either.
  Links shared on Facebook / Messenger / WhatsApp then previewed as "Just a
  moment…" instead of showing the page title, image and description.
  - The decision bridge now checks the file's ua / asn / host rules against each
    request's real User-Agent and ASN, and lifts only the vhost-wide challenge
    (with `skip` or `skip_vhost_only`).
  - A per-IP challenge (a WAF challenge-tier hit, the geo policy floor) and a
    block are never lifted, and the WAF and traffic rules still apply.
  - The check makes no inline DNS lookups, so a rule whose `ptr=` needs
    `verify_fcrdns=1` never applies there; verified crawlers are cleared by
    `CHALLENGE_GOODBOT_EXEMPT`.
  - Each lift is counted (`challenge_exclude_lifts` in the bridge stats) and
    logged to the challenges log as `action=exclude_lift`, at most once per
    host per minute.
  - Because the check runs per request, a ua-only rule lifts the vhost-wide
    challenge for anyone sending that UA, and an asn-only rule lifts it for
    every request from that network, Under-Attack Mode included. The shipped
    asn-only rules are Skroutz (`as202042`) and Apple (`as714`); review them if
    that is more than you want.
- **An exclude rule's `asn=` without a wildcard now matches that ASN exactly,
  and `host=` matches that host and its subdomains only.** Both used to be
  substring matches. The shipped `asn=as714` (Apple) rule therefore also
  exempted AS7140–AS7149, AS71400 and so on, and `host=shop.gr` also matched
  `myshop.gr`. `host=` also ignores a `:port` and a trailing dot. Use `*` / `?`
  for a deliberate pattern.
- **A `detectors.conf` whose tokens sat outside `[webdetector]` no longer
  reloads every 5 seconds.** The old generator appended a missing token to the
  end of the file, which could put it in another section. After that the
  daemon never found it in `[webdetector]`, wrote a new value on every reload,
  and the rewrite triggered the next reload. The token changed every 5s and
  the detector layer kept restarting. server.speedhost.gr was in this loop
  (2026-09-30). Tokens are no longer written into `detectors.conf` at all.
