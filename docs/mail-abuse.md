# Mail abuse findings (as built)

> Node side of `cfm-web:docs/fleet-alerting.md` (mail abuse). Code:
> `internal/mailtraffic/abuse.go` (on top of the Mail Monitor's counters,
> `internal/mailtraffic` + `internal/mailmeter`). Visibility only: nothing is
> blocked, held or changed.

## Why

On titan (Oct 2026) a Joomla contact form on the `hotellito` account sent
~1 000 messages a day for days, each to the site owner plus one new outside
address, "from" a gmail address. That is ~43 an hour: never enough for
`exim_relays`' fixed LOCALRELAY threshold (110 per 15 min), and the Mail
Monitor's own baseline anomaly existed only inside the `whats_wrong` /
`mail_traffic` MCP tools, which nobody asks unprompted.

## What it does

Every 5 minutes the Mail Monitor collector (which already tails the exim
mainlog / maillog every minute into hourly per-user counters) checks:

| Type | Severity | Meaning |
|---|---|---|
| `mail_script_spike` | warning / critical | a unix user's LOCAL submissions (`U=user P=local`: PHP `mail()`, sendmail from a script or cron) far above that user's own history — a hacked site or an abused contact form. The message names the script directory (`cwd=`), the envelope sender (flagged when it is not a domain on this host), and how many different recipients. `root`, `mailnull`, `cpanel*`, `exim` are skipped |
| `mail_outbound_spike` | warning / critical | an authenticated mailbox (SMTP AUTH) sending far above its own history |
| `mail_hijack` | critical | one mailbox SUCCESSFULLY authenticating from ≥ 3 countries, or ≥ 10 IPs in at least 2 countries, within an hour — a stolen password in use (IPs alone are not enough: a mailbox used as "send mail as" in Gmail logs in from dozens of Google addresses in one country; without GeoIP data there is no hijack finding) (exim `A=…` + `H=[ip]`, Postfix `sasl_username` + `client=[ip]`) |
| `mail_recovered` | info | the finding with the same key is over (for a hijack: the logins stopped — the password still needs changing) |

"Far above its history" is the Mail Monitor's anomaly rule: the last 2 h
against the user's average per active hour over the previous 7 days, at least
3× and at least 20 messages; a sender with almost no history sending ≥ 50 is
flagged outright. **Critical** when it is ≥ 50 messages and ≥ 10× (or a sender
with no history).

Keys are per user / mailbox (`mail:script:<user>`, `mail:out:<addr>`,
`mail:hijack:<addr>`), published once, again when the severity rises, and
resolved with `mail_recovered`. A spike closes only when the recent volume is
back under 1.5× what was expected **when it opened** (or under 20): the
baseline is the sender's own trailing week, so a long incident slowly becomes
its own baseline and would otherwise "recover" while still sending. The edge
state is kept in `/var/lib/cfm/mail_abuse_published.json` (next to the
counters), so restarts do not re-announce. Delivery is the same
`detection_history` node-fault path as the backup check; cfm-web ingests it.

## Knob

`cfm.conf`: `MAIL_ABUSE_ALERT = 1` (default). `0` turns the findings off; the
counters and the MCP views stay.

## Not covered yet

- Bounce/defer ratio spikes per sender, the node's own IP on an RBL, one
  sender dominating the queue.
- Dovecot (IMAP/POP) logins for the hijack check — SMTP AUTH only.
- Recipient novelty (a contact form writes to a NEW outside address every
  time): reported as a count, not yet a trigger of its own.
