# Vhost lockdown — "nothing gets past this vhost's challenge"

A vhost challenge lets some clients through by design:

- the crawler **bypass list** (`challenge_waf_bypass.conf`, `cfm.lua` Step 0: Google, Bing, Apple, DuckDuckGo, Skroutz…);
- **FCrDNS-verified good bots** (`CHALLENGE_GOODBOT_EXEMPT`);
- **Challenge Access-Control** entries;
- the operator **exclude file** (`webdetector_challenge_exclude.txt`).

That is right on an ordinary day. It is wrong when those very clients are the problem. On 2026-10-27 Applebot crawled one shop from about 1 300 IPs in 10 minutes. A vhost challenge could not stop it, and nothing else at the edge reached a bypass-listed client either: Step 0 returns before the challenge, the WAF, the traffic rules and `cfm bots`.

A **lockdown** is the emergency brake for that case. It is an attribute of a **manual** vhost challenge. While it holds, that vhost's challenge has **no client exemption at all**. Crawlers cannot solve a challenge, so they are shut out of the vhost; people solve it as on any challenged vhost.

## What still passes

A lockdown is about *clients*, not paths or the node. These are left alone:

- **CDN fetchers**: the bypass list's `2` prefixes (QUIC.cloud). Their requests are a site's visitors, so locking them out would lock out the site behind them.
- **`/.well-known/`**: ACME / AutoSSL / CA DCV keep working.
- the **challenge-exempt machine endpoints** (payment webhooks and the like);
- the **cPanel / webmail panel passthroughs**;
- the **server's own IPs**, `IGNORE_IPS` and `CHALLENGE_HOST_BYPASS`;
- a visitor that **already holds a clearance cookie** or has solved.

## Duration

The default is **30 minutes** and the maximum is **6 hours**; the daemon caps it and the response says `lockdown_capped`. It never outlives the challenge it belongs to. Crawlers kept out for hours start to cost a shop its search ranking, so a lockdown always ends on its own. Renew it deliberately if the storm goes on.

A re-arm of the challenge (a TTL extension, a button or command that sends no lockdown field) **keeps** the lockdown, clamped to the new expiry. Only an explicit `lockdown=0`, the lockdown endpoint, or removing the challenge lifts it (the TUI's `c` on a manual challenge removes it, lockdown included). A **new** `www.` arm under a locked-down apex inherits the apex's lockdown: arming `www.` from a surface that knows nothing of lockdowns must not quietly unlock it.

## Controls

| Surface | How |
|---|---|
| CLI | `cfm webtop challenge add <vhost> --lockdown [--lockdown-ttl 30m]` arms the challenge with the lockdown. `cfm webtop challenge lockdown <vhost> on\|off [--ttl 30m]` switches it on an armed vhost. `cfm webtop challenge status <vhost>` shows it. Also listed in `cfm --help` and `cfm webtop help`. |
| TUI (`cfm webtop live`) | `L` toggles it on the vhost in the drilldown, or on the selected row in the picker; lowercase `l` still drills into an IP. On a vhost without a manual challenge it arms one for 30 minutes with the lockdown. The header shows `⛔ LOCKDOWN left=…`. |
| cfm-admin | Controls page, **Emergency challenge** card: pick a duration, then **⛔ Lockdown (no exemptions)** or **Lift lockdown**. The controls table and the challenged-vhost pills show `LOCKDOWN`. |
| API | `POST /api/v1/challenge/vhost/add` with `lockdown=1` (JSON `"lockdown": true`) and optional `lockdown_ttl`; `lockdown=0` lifts; absent keeps. `POST /api/v1/challenge/vhost/lockdown` with `host`, `lockdown=1\|0` and optional `ttl` switches it in place and returns `409` without a manual challenge. `vhost/status`, `challenge/vhost(s)` and `webdet/vhosts` report it (`lockdown`, `lockdown_until`, `challenge_lockdown_until`). Recipes: [`webui-api-curl-recipes.md`](webui-api-curl-recipes.md). |
| MCP | The `challenge_vhosts` rows carry `lockdown` / `lockdown_until`. |

Scoped (cPanel tenant) tokens may lock down their own vhosts, like any manual challenge: a lockdown only adds challenges, on a vhost the tenant owns. For a `www.` host the arm changed is the apex's when that is the one covering it, and the scope check covers that host too. Wildcard hosts cannot be locked down: the edge matches the exact host.

Audit:

- `challenge_vhost_lockdown` history rows (`lockdown`, `until`, `actor`);
- `action=manual_lockdown` / `action=lockdown_restore` lines in `cfm.challenges.log`;
- `lockdown_until` on a `challenge_vhost_manual_on` row whose re-arm kept one.

## How it works

- **Daemon.** `manualChalEntry.LockdownUntil` is persisted with the manual challenge (`lockdown_until`; an older snapshot loads as none). `SetManualChallengeLockdownAs` is the one change point. `syncVhostLockdowns` publishes `host → expiry` to the bridge. An apex arm also covers its `www.` variant, unless that `www.` host has an arm of its own.
- **Edge Step 0.** `configs/lua/cfm_lockdown.lua` keeps each worker's copy of `GET /nginx/lockdown`, refreshed out of band every 5 s (`CFM_LOCKDOWN_REFRESH_SEC`). Each entry carries its expiry, so a lockdown ends on time even while the bridge is unreachable. For a `1` (crawler) bypass client on a locked host, Step 0 does not return; the request goes through every later step and meets the vhost challenge. A `2` (CDN) client keeps its bypass. Any failure of the module (load, fetch, a raise) leaves the bypass as it always was: fail-open to the old behaviour. The refresh is lazy: a worker that served no bypass request for a while serves its first one after a new lockdown with its old table, then refreshes (one request per worker, at most).
  A crawler held this way **skips the inline WAF**, as its bypass always did: a site could feed a crawler bait (a sitemap link carrying SQLi) and an armed rule would make `waf_security`, which has no good-bot exemption, nft-ban Googlebot for the whole node, long after the lockdown. The challenge is all it meets.
- **Decision.** `handleDecision` skips the good-bot downgrade, Access-Control and the exclude-file lift on a locked host. The challenge page grants no exemption (`challengePageExempt`). A v2 arm waives no good bot at verify (`v2_waiver_miss=lockdown`).
- **Vhost uniqIP count.** Unchanged by a lockdown, on purpose: the vhost is already under its manual challenge, and counting the crawlers it holds would arm an automatic challenge (v2 by default) that outlives the lockdown.
- **Resync.** The daemon republishes the lockdown set on every tick (`RunOnce`), so a `www.` arm that lapses on its own hands `www.` back to the apex's lockdown within seconds.

The bypass list's two kinds come from `scripts/build_bypass_list.py`: a source in `CDN_SOURCES` is written as `<cidr> 2;`, every other source as `<cidr> 1;`, and a prefix in both kinds as `2`. `bypass_list_test.py` pins the format and fails a committed list that lost the `2` lines. The edge's `log-cfm.lua` sends the value as column 13, and the daemon reads `1` and `2` as bypass and `2` as CDN.

## Version skew

The edge Lua and the daemon ship in one package. On a node whose conf predates the lockdown, nothing changes: the geo still answers `1` for every bypass prefix and the Lua treats them as crawlers. A list with `2` lines reaching an older Lua is impossible from the package, because the Lua updates first. If it ever happened, the older Step 0 (`== "1"`) would stop bypassing QUIC.cloud, so upgrade the Lua and the list together.
