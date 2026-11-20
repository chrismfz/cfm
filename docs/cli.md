# CFM CLI: the commands that have no doc of their own

Every command prints its own help (`cfm <command> help`, `cfm webtop help`).
This page covers the ones no topic doc owns; the others live with their
subsystem: `cfm clam` → `docs/clamav.md`, `cfm mysqltop` →
`docs/mysql-governor.md`, `cfm kernsec` → `docs/kernsec.md`, `cfm lsm` →
`docs/cfm-lsm.md`, `cfm dnat` (also `cfm edge`, below) → `docs/panel-dnat.md` / `docs/dnat-bypass.md`,
`cfm webtop site-cache` → `docs/site-cache-runbook.md`, `cfm webtop rules` →
`docs/traffic-rules.md`, `cfm webtop waf` → `docs/waf.md`.

## `cfm webtop`


```bash
cfm webtop                       # summary (short + suspicious)
cfm webtop top 20                # top 20 vhosts by RPS
cfm webtop top 20 5xx            # sort by 5xx error rate
cfm webtop --limit 15 --sort err # sort by error ratio
cfm webtop <vhost>               # drilldown into a vhost

cfm webtop long 30               # long-window top by score
cfm webtop ip 50                 # global IP view
cfm webtop ip 1.2.3.4            # drilldown a specific IP

cfm webtop analyze <ip|host> [--last 30m] # offline drilldown from TSV (debug/forensics)
cfm webtop analyze example.com --last 30m   # host-filtered forensic analysis
cfm webtop analyze 1.2.3.4 -last 1h        # IP-filtered forensic analysis

# Traffic rules (docs/traffic-rules.md)
cfm webtop rules list
cfm webtop rules get <rule-id>
cfm webtop rules add --file docs/examples/traffic-rule-throttle-meta.json
cfm webtop rules update <rule-id> --file docs/examples/traffic-rule-challenge-login.json
cfm webtop rules remove <rule-id>
cfm webtop rules simulate --host example.com --ua "facebookexternalhit/1.1" --path / --method GET --country US
# Move a site's rules to another server (also: cfm-admin → Traffic Rules → Export / Import)
cfm webtop rules export --vhost example.com --out example-rules.json   # on the old server
cfm webtop rules import --file example-rules.json --dry-run            # on the new one: preview
cfm webtop rules import --file example-rules.json [--disabled]         # all-or-nothing; duplicates skipped

# Site Cache (per-vhost edge caching — docs/site-cache-runbook.md)
cfm webtop site-cache list
cfm webtop site-cache get <vhost>
cfm webtop site-cache set <vhost> --static static_lean                  # Tier A
cfm webtop site-cache set <vhost> --micro micro_safe --micro-ttl 5s     # Tier B (a dry run where MICRO_CACHE_ENFORCE = 0)
cfm webtop site-cache off <vhost>        # opt-out (also under an armed *.suffix)
cfm webtop site-cache remove <vhost>     # delete the policy
cfm webtop site-cache purge <vhost>      # or: purge --all (admin)
cfm webtop site-cache stats [vhost]      # HIT / MISS / BYPASS + strict hit ratio
```

The `--last` / `-last` duration uses Go-style duration strings, such as `30m`, `1h`, or `2h30m`.

**Sort keys:** `rps`, `2xx`, `3xx`, `4xx`, `5xx`, `uniq`, `err`, `rt`, `bot`, `ua_div`, `score`

## `cfm bots`: box-wide User-Agent emergency rules

Box-wide UA emergency control surface. Where `cfm webtop` is keyed on
vhost/IP, `cfm bots` is keyed on the **normalized User-Agent across all
vhosts** — useful when one bot family (Facebook OG fetcher, SemrushBot,
AhrefsBot, …) hammers many vhosts at once and per-vhost throttles don't
catch the aggregate.

```bash
cfm bots                          # live two-pane TUI (top + active rules)
cfm bots top [N]                  # static top-N snapshot
cfm bots list                     # active emergency rules + countdown / hits
cfm bots drill <ua>               # drilldown: top IPs, vhosts, raw UA variants

# Install / undo rules (only "throttle" and "block" — no "allow" by design)
cfm bots throttle <ua> [--ttl 30m] [--reason ...]
cfm bots block    <ua> [--ttl 30m] [--reason ...]
cfm bots remove   <ua>
```

**Options for install commands**

- `--ttl <duration>` — Go-style duration (e.g. `5m`, `30m`, `1h`); default
  `30m`, hard-capped at 60m, floored at 1m
- `--reason <text>` — free-form, captured in
  `/var/log/cfm/ua_emergency.log` for post-mortem
- `--confirm` — required to act on verified Google crawlers
  (`googlebot`, `adsbot-google`, `mediapartners-google`, …); the API
  returns `409 google_verified_bot_requires_confirm` without it

**Action semantics**

- `throttle` — box-wide token bucket (rate 10 r/s, burst 20) keyed on
  the normalized UA. Bot continues but at a bounded aggregate rate.
- `block` — `ngx.exit(444)` (TCP close, no body) — cheapest possible
  emergency relief; bot sees the connection drop.
- No `allow` action: a UA-only allow rule would be a trivially spoofable
  WAF bypass (anyone sending `User-Agent: Googlebot/...` would inherit
  it). For verified-crawler exemptions use per-vhost rules with IP/ASN
  verification instead.

**Hybrid aggregation — counts always, IPs lazy**

Per-UA request counts (RPS / Reqs / Vhosts) are always aggregated so
`cfm bots top` works on a fresh box. The heavier work — tracking the
unique-IP set per UA, which dominates memory under crawler load — only
activates while at least one emergency rule is installed (a single
atomic load per event keeps the gate cheap). The Lua per-request check
also early-exits when no rules exist, avoiding the UA-normalize cost on
idle workers.

In the bot-top output, the `IPS` column shows 0 until a rule is in
place. Install any short observation rule to enable IP detail:

```bash
cfm bots throttle observer --ttl 5m --reason "observing"
cfm bots top
cfm bots remove observer
```

**Where rules go**

- In-memory store on the cfm daemon
- JSON snapshot at `/var/lib/cfm/ua_emergency.json` (consumed by nginx
  workers via 3s lazy refresh)
- Audit log at `/var/log/cfm/ua_emergency.log` — one line per
  create / undo / TTL-expire event

**Web UI:** the same surface is exposed at
`/cfm-admin/webdetector/bots/` (admin-only — box-wide rules cross
tenant boundaries).

## `cfm firewall status`

Use this command to validate core firewall resources and generate a health report that works across firewall backends.

```bash
cfm firewall status
# human-readable report (engine, capabilities, features, set sizes, counters, findings)

cfm firewall status --json
# machine-readable JSON report

cfm firewall status --verbose
# enables optional extra backend probes when available

cfm firewall status --strict=false
# do not return non-zero even if FAIL findings are present
```

Report fields include:
- engine + config source
- capability flags
- feature enablement (`ports`, `connlimit`, `portflood`, `smtp`, `autoblock`, `feeds`, `dnat`)
- set sizes for key sets (`block_v4/v6`, `allow_v4/v6`, `ignore_v4/v6`, feed sets, plus `*_cardinality` roll-ups)
- key counters (when backend exposes them)
- health findings with level `ok` / `warn` / `fail`

Exit behavior:
- With default `--strict=true`, command exits non-zero if report status is `fail`.
- Warnings (`warn`) do not cause non-zero exit by themselves.

## `cfm firewall path`

Use this read-only diagnostic when CFM DNAT/redirect rules interact with
Imunify/WebShield, iptables-nft, or another nftables owner:

```bash
cfm firewall path
cfm firewall path --hook prerouting --proto tcp --dport 443
cfm firewall path --json
```

It lists base chains by actual numeric hook priority, then statically reachable
DNAT/SNAT/redirect/masquerade/TProxy rules under each base-chain context.
Findings flag same-priority ambiguity and configured-versus-runtime CFM
priority drift;
ordered CFM/Imunify overlap is reported as informational context. Collection
uses `nft -j -t list ruleset`: terse mode omits set contents, so large IP
blocklists are never copied into CLI/API/UI/MCP output. The same report is
available at admin-only `GET /api/v1/firewall/path`, on the cfm-admin Firewall
page, and through MCP `netfilter_path`.
`--strict` exits non-zero only for warning/critical findings; informational
ordered overlaps remain successful.

## `cfm health`

Health of the local node, from the API snapshot (`/api/v1/health/snapshot`).
Fleet-wide health is cfm-web's job.

```bash
cfm health
# human summary sections (Host, Disk, Network, CFM)

cfm health json
# pretty-printed JSON payload from /api/v1/health/snapshot

cfm health watch --interval=2s
# periodic one-line samples; prints selected interval first

cfm health live
# interactive TTY dashboard when stdout is a terminal
# fallback: if no TTY is available, auto-runs watch mode
```

Expected output semantics:
- `cfm health` is optimized for operators (readable summary).
- `cfm health json` is stable machine-readable output for scripts/integration.
- `cfm health watch` emits a banner with effective interval, then one line per sample.
- `cfm health live` requires a TTY; otherwise it safely degrades to watch output.

## `cfm edge`

One command for the in-path edge proxy (OpenResty, Angie or cfm-edge). It
adds no logic: each subcommand is an existing one under a name that says what
it is about, and `cfm dnat` / `cfm realip` keep working as before.

```bash
cfm edge [status]                # the edge at a glance (read-only)
cfm edge on | off                # = cfm dnat on | off: 80/443 through the edge, or straight to the origin
cfm edge web                     # = cfm dnat: the full web DNAT report
cfm edge bypass list|add|remove  # = cfm dnat bypass …
cfm edge panel [status|on|off|bypass …]   # = cfm dnat cpanel … (alias: cfm edge cpanel)
cfm edge realip [status|fix]     # = cfm realip …
cfm edge ipv6 [status]           # the IPv6 listen decision of every installed engine
```

`on` and `off` move traffic; they never start or stop the edge service.

The bare `cfm edge` prints the engine (`running`, or `enabled, NOT running`
for an enabled one that stopped; a warning when more than one is active), web
DNAT (priority, target ports, bypass count, last health
probe), panel DNAT (priority), the running engine's IPv6 listen decision and
the origin real-IP verdict, then what needs a look:

- web or panel DNAT on with no edge engine running (that traffic goes to
  nothing);
- DNAT off while its saved intent is on (the daemon's failsafe puts it back
  once the edge answers; `cfm edge off` / `cfm edge panel off` clear it).

A state it cannot read prints `UNKNOWN (…)` (an unreadable bypass list: "bypass
list unreadable") and exits 1, never `OFF`; the panel priority is the live
chain's, the saved one only when the rules do not parse (and it says so). The
routes that need no firewall (`realip`, `ipv6`, `help`) also work where the
nft backend cannot start. Flags go after the subcommand (`cfm edge panel on
--priority -99`); one before it is refused.

## `cfm realip`

Does the origin see visitors or `127.0.0.1`, and the fix: `docs/origin-real-ip.md`.

