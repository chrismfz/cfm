# Alert log (`internal/alerts`)

As-built reference for the node's alert store: what it records, where, and how
to read it. cfm-web's fleet alert view (step 2 of the plan below) builds on
the API described here.

## Why

Every detector reports through the notifier (`notify.Enqueue` /
`notify.Emit`), and until now the only durable trace was the mail it sent:
operators read a `logs@` mailbox sorted into folders (WAF, Greece, MySQL,
Portscans, …). On a node with no working SMTP/sendmail nothing was kept, and
the events dedupe or a detector override did not send were never visible
anywhere. The notifier's `notify.log.jsonl` is a **delivery** journal (one row
per channel attempt, written only when something was sent) and is scanned
linearly, so it can't answer "group by country/network/site".

## What is recorded

`notify.Emit` records every event it is handed, before any of its gates, and
`notify.Enqueue` records the ones it can't queue. Each row carries what the
notifier did with it:

| `delivery` | meaning |
|---|---|
| `notified` | handed to at least one channel (`event_id` = the delivery journal's `correlation_id`) |
| `deduped` | same dedupe key inside its cooldown |
| `muted` | the detector's override has `notify = false` |
| `below_severity` | below the detector override's `min_severity` |
| `no_channels` | notifier enabled, but no enabled channel matched |
| `notifier_off` | notifier disabled, its config failed to load, or it never started |
| `queue_full` | the notifier's 100-slot queue was full; the event never reached `Emit` |

A detector that asks for no mail at all (`core.ExtraNotify = no`) never calls
the notifier and is not recorded.

Columns: `ts_unix`, `host` (the node), `category` (the kind's family: the part
before `/`, or before `_` for the old unslashed kinds — `WAF/SQLI` → `WAF`,
`outbound_abuse` → `OUTBOUND`), `kind`, `severity` (normalised to
info/warning/critical), `ip`, `country` (display, e.g. "Athens, Greece"),
`country_iso` (from mmdb, no DNS), `asn` (text) and `asn_num`, `ptr`, `vhost`
(the detector's `vhost`/`host` extra when it names a domain, else the first
sample line's `host=` or ModSecurity `[hostname "…"]`), `reason`, `mode`
(ttl/permanent), `ttl_sec`, `count`, `section`, `delivery`, `event_id`, up to 5
sample lines (2 KB each) and the detector's extra fields (JSON).

## Storage

- `/var/lib/cfm/alerts.db` (SQLite, WAL, mode 0600), `alerts.DefaultPath`.
- Retention: 30 days and 500,000 rows, whichever comes first; pruned every 10
  minutes. Not configurable yet.
- Writes go through a buffered queue (8192) to one writer goroutine that
  inserts in batches of up to 256 every 500 ms. A detector never waits on it: a
  full queue drops the row and counts it (`dropped_since_start` in stats).
- Opened by `alerts.Init()` in `cmd/cfm/main.go`, before `notify.Init`. If it
  fails to open, `cfm.log` says `[alerts] init error` and recording is off; the
  notifier is unaffected.
- Tests: `alerts.SetPathForTest`; nothing opens the default store unless
  `Init` runs, and `notify` records nothing without one.

## Reading it

All admin-only (`adminOnlyHandler`; the store holds every tenant's events).

- `GET /api/v1/alerts` — rows, newest first by event time. Filters:
  `hours` (default 24, max 2160) or `from`/`to` (RFC3339 or unix seconds),
  `category`, `kind`, `delivery` (comma lists or repeated), `min_severity`,
  `ip`, `country` (ISO-2 or part of the name), `asn` (number or part of the
  name), `vhost`, `mode`, `q` (substring of reason/kind/ptr/asn/vhost/samples).
  `limit` (1–500, default 100), `cursor` = the previous page's `next_cursor`.
- `GET /api/v1/alerts/summary` — the same filters plus `group_by` (up to three
  of `category`, `kind`, `severity`, `ip`, `country`, `asn`, `vhost`, `reason`,
  `mode`, `delivery`, `section`, `hour`, `day`) and `top` (1–500, default 50).
  Per group: `key`, `count`, `distinct_ips`, `first_unix`, `last_unix`, and a
  `label` (the ASN or country name). Sorted by count; hour/day buckets in time
  order.
- `GET /api/v1/alerts/stats` — rows, size, oldest/newest, limits, writer
  counters.
- cfm-admin → **Alerts** (`/cfm-admin/alerts/`): category chips with counts,
  filters (kept in the URL hash, so a view can be linked), headline tiles,
  group-by with click-to-drill, and per-row detail with the sample lines.
- MCP: `alerts` and `alerts_summary` (MCP.md §4).

Example — "did we block many legit Greek users this week, and why?":

```
GET /api/v1/alerts/summary?hours=168&country=GR&group_by=kind,asn
```

then the top rows' `kind` + `asn` → `GET /api/v1/alerts?hours=168&country=GR&kind=…&asn=…`
for the sample lines, and `detectors_config` for the threshold behind that kind.

## Plan

1. **Node store + API + cfm-admin page + MCP tools** — this document. Done.
2. **cfm-web fleet view** — an ingestor pulls each node's `/api/v1/alerts`
   (cursor-based, like the solver-farm and hard-fault ingestors) into a central
   table, with a fleet Alerts page, a tab on Agent → Health, and an MCP tool
   that groups across nodes.
3. **Central routing** — cfm-web's alert router (Mattermost/mail, storm guard,
   digests) sends the notifications, so a node no longer needs its own SMTP to
   be heard; node mail becomes optional.
