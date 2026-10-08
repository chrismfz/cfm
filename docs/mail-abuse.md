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
| `mail_hijack` | critical | one mailbox SUCCESSFULLY logging in from ≥ 3 countries, or from ≥ 10 sources of which ≥ 5 are outside its main country, within an hour — a stolen password in use. SMTP AUTH (exim `A=…` + `H=[ip]`, Postfix `sasl_username` + `client=[ip]`) and IMAP/POP3 (dovecot `Login:` / `Logged in:` + `rip=`; a failed login never counts). See "Hijack sources" below; without GeoIP data there is no hijack finding |
| `mail_bounce_spike` | warning / critical | a sender (local user or authenticated mailbox) whose remote deliveries bounce in bulk: ≥ 20 bounces and ≥ 25 % of its delivered + bounced in the last 2 h (critical from 100 and 50 %; counted per recipient). A failure through a local transport (a full or deleted mailbox on this host) is not a bounce, as local deliveries are not counted either — a form or hacked account writing to harvested or made-up addresses. Names the main bounce reason (`no-such-user`, `blocked-reputation`, …) and the sender context. Stays open down to half of each threshold |
| `mail_queue_hog` | warning / critical | one envelope sender holding ≥ 50 % of a queue of ≥ 100 messages, with ≥ 100 of them of which ≥ 50 are frozen or stuck over 1 h — a campaign going out fine is not a clogged queue (critical from 1 000); `<>` is shown as bounce messages (backscatter). Read from the exim/postfix queue detector's latest listing (`exim_queues` / `postfix_queues` must be on). A listing that failed (count fine, nothing listed — a big queue is slow to list) or is 10 min – 1 h old leaves an open finding as it is; older than that (the detector switched off) it no longer holds it. Stays open down to 30 % / 50 messages |
| `mail_rbl_listed` | warning / critical | one of the node's public IPv4 addresses on Spamhaus ZEN (SBL / XBL / PBL), SpamCop, Barracuda or PSBL, checked every 30 min. Critical for a Spamhaus SBL/XBL listing or two lists at once. Each list is judged on its own: one that does not answer cleanly (a timeout, or Spamhaus's `127.255.255.x` "your resolver is refused" — logged once) keeps its own last verdict, never read as "delisted" and never holding the other lists' verdicts. An address that leaves the node is resolved |
| `mail_recovered` | info | the finding with the same key is over (for a hijack: the logins stopped — the password still needs changing; for an RBL listing: delisted) |

"Far above its history" is the Mail Monitor's anomaly rule: the last 2 h
against the user's average per active hour over the previous 7 days, at least
3× and at least 20 messages; a sender with almost no history sending ≥ 50 is
flagged outright. **Critical** when it is ≥ 50 messages and ≥ 10× (or a sender
with no history).

Keys are per user / mailbox / IP (`mail:script:<user>`, `mail:out:<addr>`,
`mail:hijack:<addr>`, `mail:bounce:local:<user>` / `mail:bounce:auth:<addr>`
(a cPanel user can be both), `mail:queue:<sender>`,
`mail:rbl:<ip>`), published once, again when the severity rises, and
resolved with `mail_recovered`. A spike closes only when the recent volume is
back under 1.5× what was expected **when it opened** (or under 20): the
baseline is the sender's own trailing week, so a long incident slowly becomes
its own baseline and would otherwise "recover" while still sending. The edge
state is kept in `/var/lib/cfm/mail_abuse_published.json` (next to the
counters), so restarts do not re-announce. The per-line context (bounce
outcomes, logins) lives in memory, so after a restart an open bounce finding
is held for 2 h and an open hijack for 1 h, until the window has filled again:
neither "back to normal" nor re-paged. Delivery is the same
`detection_history` node-fault path as the backup check; cfm-web ingests it.

## Hijack sources

A login's address is first normalised, because several sources are one
person, or a service acting for them:

- loopback and private addresses (webmail, a local relay) are not counted;
- an IPv6 address counts as its /64 (a phone rotates privacy addresses);
- Google, Microsoft, Yahoo and Apple's networks (AS15169, 8075, 36647, 26101,
  34010, 714, 6185) count as ONE source with no country: Gmail fetching a
  mailbox over POP3 logs in from a dozen Google addresses an hour (seen on
  titan, Oct 2026). A hijacker on a VM in those networks is missed — that
  includes Azure, which shares AS8075 with Outlook.com; they mostly use
  residential proxies and VPS networks.
- `::ffff:1.2.3.4` is `1.2.3.4`.

So "many IPs" needs ≥ 5 of them outside the mailbox's main country: a home,
a phone and a VPN are many addresses in two places, not a hijack.

## Telling a newsletter from spam

Each finding carries a **context** gathered from the log lines of the last
2 h (up to 2 000 per user / mailbox):

- the decoded **subjects** (`T="…"`, RFC 2047 words decoded, ≤ 80 chars, the 3
  most common) — the alert shows the top one as `· «subject»`;
- the **recipients**: how many different addresses, the top recipient domains
  (`gmail.com×812`), and the **contact-form pattern** — one address (the site
  owner) in ≥ 80 % of ≥ 5 messages while the others are ≥ 80 % distinct;
- the **sender**: a local script sending "as" an address whose domain is not on
  this host (`· as x@gmail.com (not a domain here)`), or a mailbox sending as an
  address other than itself (`(not itself)`) — the spoofing tell;
- the script directory (`cwd=`) for local submissions.

A newsletter reads as one sender, one subject, many mixed recipient domains
from its own address; a hacked form reads as a foreign "from", a constant
copied-to owner and a new outside address each time. The node does not decide
which — it shows it.

The same findings, with the full context, are in the `mail_traffic` MCP tool
(`abuse`, admin callers only) and in `whats_wrong` (category `mail`), so a
general "what's wrong" on a node or `node="all"` names them too.

## Knob

`cfm.conf`: `MAIL_ABUSE_ALERT = 1` (default). `0` turns the findings off; the
counters and the MCP views stay.

## Not covered yet

- Bounces on a Postfix host with a content filter (amavis / rspamd
  re-injecting): the re-injected message has a new queue id with no
  authenticated sender, so its bounces are not attributed. Exim and plain
  Postfix are.
- IPv6 addresses on blocklists (few lists carry them).
- Recipient novelty and the contact-form pattern are shown as context, not a
  trigger of their own.
