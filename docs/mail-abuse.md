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
| `mail_outbound_spike` | info / warning / critical | an authenticated mailbox (SMTP AUTH) sending far above its own history, and above its own largest burst of the last 28 days. **Info** (listed, never paged) when nothing about it looks like abuse — see "Volume alone" below |
| `mail_hijack` | warning / critical | one mailbox SUCCESSFULLY logging in from ≥ 3 countries, or from ≥ 10 sources of which ≥ 5 are outside its main country, within an hour. SMTP AUTH (exim `A=…` + `H=[ip]`, Postfix `sasl_username` + `client=[ip]`) and IMAP/POP3 (dovecot `Login:` / `Logged in:` + `rip=`; a failed login never counts). **Critical** only when the mailbox is also being USED — see "Hijack severity" below; logins alone are a warning. See "Hijack sources" below; without GeoIP data there is no hijack finding |
| `mail_bounce_spike` | warning / critical | a sender (local user or authenticated mailbox) whose remote deliveries bounce in bulk: ≥ 20 bounces and ≥ 25 % of its delivered + bounced in the last 2 h (critical from 100 and 50 %; counted per recipient). A failure through a local transport (a full or deleted mailbox on this host) is not a bounce, as local deliveries are not counted either — a form or hacked account writing to harvested or made-up addresses. Names the main bounce reason (`no-such-user`, `blocked-reputation`, …) and the sender context. Stays open down to half of each threshold |
| `mail_queue_hog` | warning / critical | one envelope sender holding ≥ 50 % of a queue of ≥ 100 messages, with ≥ 100 of them of which ≥ 50 are frozen or stuck over 1 h — a campaign going out fine is not a clogged queue (critical from 1 000); bounces (null sender: exim `<>`, Postfix `MAILER-DAEMON`) are not counted — frozen undeliverable bounces piling up are the normal state of a cPanel queue, not one sender's doing. Read from the exim/postfix queue detector's latest listing (`exim_queues` / `postfix_queues` must be on). A listing that failed (count fine, nothing listed — a big queue is slow to list) or is 10 min – 1 h old leaves an open finding as it is; older than that (the detector switched off) it no longer holds it. Stays open down to 30 % / 50 messages |
| `mail_rbl_listed` | warning / critical | one of the node's public IPv4 addresses on Spamhaus ZEN (SBL / XBL / PBL), SpamCop, Barracuda or PSBL, checked every 30 min. Spamhaus refuses `zen.spamhaus.org` through public resolvers (the fleet's 1.1.1.1 / 8.8.8.8): set `MAIL_RBL_SPAMHAUS_DQS_KEY` and it is asked through Data Query Service (`<key>.zen.dq.spamhaus.net`) instead; the key is never logged or shown. Critical for a Spamhaus SBL/XBL listing or two lists at once. Each list is judged on its own: one that does not answer cleanly (a timeout, or Spamhaus's `127.255.255.x` "your resolver is refused" — logged once) keeps its own last verdict, never read as "delisted" and never holding the other lists' verdicts. An address that leaves the node is resolved |
| `mail_recovered` | info | the finding with the same key is over (for a critical hijack: the logins stopped — the password still needs changing; for an RBL listing: delisted) |

"Far above its history" is the Mail Monitor's anomaly rule: the last 2 h
against the user's average per active hour over the previous 7 days, at least
3× and at least 20 messages; a sender with almost no history sending ≥ 50 is
flagged outright. A MILD spike — under 50 messages in the 2 h AND under 10×
its usual, with nothing abusive in its context — is not an alert: 20–40
messages at 4–5× a small sender's usual is a newsletter or a busy day, and
paged the channel for nothing (`mail_traffic`'s `anomalies` still list it). A
small spike far above its usual (a quiet site hacked: 45 at 45×), or one
sending as a foreign domain / another domain or in the contact-form pattern,
still alerts; an open one keeps being judged, so it does not flap.
**Critical** when it is ≥ 50 messages and ≥ 10×, or a sender with no history
from 200.

**Done before.** The ratio is against the sender's AVERAGE active hour, so a
sender with one big run a day reads "3×" every day: titan's itadmin@ sent its
"Order production start" run of 177 one morning and 176 the next, paged both
days. So a spike (script or mailbox) is also compared with the sender's
**peak**: the most it sent in any two consecutive whole hours over the 28 days
before the recent window (`mail_traffic`'s `anomalies` carry it as `peak`).
The recent window is the hours of now−2 h and now−1 h plus the current one, so
a sender at a steady rate is always over its peak: an incident not caught at
its onset (no sink yet, a restart) never becomes its own "done before". At or
under its peak, **with no tell of abuse** (below), it is a burst this sender
has sent before: still listed in `anomalies`, never a finding. The tells are
judged first because the peak can be the same thief's earlier run. An open
finding keeps being judged as before (its own incident is in the peak by
then). A monthly run older than the counters' 30 days, or a sender's first
run, is not "done before".

### Volume alone

Most mailbox spikes the channel saw were a shop's order confirmations, a
claims system, a payroll run: volume and nothing else. A mailbox spike with no
**tell of abuse** is published one step down: a would-be warning as **info**
(in the event log and `whats_wrong`, below every route set to warning; a route
an operator sets to `info` receives them) and a would-be critical as a warning
(still seen: 422 read receipts in 2 h is a loop worth knowing about). The
message says `· volume only`. A **new sender** (no history at all) is not
stepped down: a dormant mailbox suddenly sending is the strongest signal. The
tells:

- the envelope sender is not a domain on this host (`(not a domain here)`);
- the mailbox sends as an address of ANOTHER domain (`(another domain)`); as
  another address of its own domain (`mail@` sending its `claim@` notices) it
  is the same owner, shown as `· as claim@…` and no tell;
- the contact-form pattern;
- a `mail_bounce_spike` finding of the same mailbox this check;
- the mailbox is logged in from many countries this hour (a hijack candidate,
  which the spike in turn confirms: "Hijack severity" below).

Local script spikes (`mail_script_spike`) keep their severity: a hacked site
sending as its own domain to many addresses shows none of these tells. "Done
before" still applies to them, unless they send as a foreign domain, in the
contact-form pattern, or bounce.

One gap is left on purpose: a mailbox sending as another address of its OWN
domain used to count as spoofing, and kept even a 20-message spike an alert.
That was titan's `mail@pantelos.gr` → `claim@`, paged twice a day. A thief
sending a few internal-looking messages (`info@` as `ceo@`, business email
compromise) never reached the spike floor anyway; the hijack check is what
sees that mailbox's logins.

Keys are per user / mailbox / IP (`mail:script:<user>`, `mail:out:<addr>`,
`mail:hijack:<addr>`, `mail:bounce:local:<user>` / `mail:bounce:auth:<addr>`
(a cPanel user can be both), `mail:queue:<sender>`,
`mail:rbl:<ip>`), published once, again when the severity rises, and
resolved with `mail_recovered`. A spike closes only when the recent volume is
back under 1.5× what was expected **when it opened** (or under 20): the
baseline is the sender's own trailing week, so a long incident slowly becomes
its own baseline and would otherwise "recover" while still sending. A sender
with no baseline before the spike has nothing to go back to: a new MAILBOX
(`mail_outbound_spike`) that opened as a warning and stays under 200 in 2 h is
resolved after a day at that volume ("now its usual volume"); a script spike
or a critical one is never settled that way — a hacked quiet site opens
exactly like a new sender, and stays open until the volume falls or someone
acknowledges it. A new sender is a warning up to 200 in 2 h. The edge
state is kept in `/var/lib/cfm/mail_abuse_published.json` (next to the
counters), so restarts do not re-announce. The per-line context (bounce
outcomes, logins) lives in memory, so after a restart an open bounce finding
is held for 2 h and an open hijack for 1 h, until the window has filled again:
neither "back to normal" nor re-paged. Delivery is the same
`detection_history` node-fault path as the backup check; cfm-web ingests it.

## Hijack sources

A login's address is first normalised, because several sources are one
person, or a service acting for them:

- loopback and private addresses (webmail, a local relay) are not counted,
  nor the node's own public addresses (a site's form or mailer
  authenticating to the server it runs on connects to its public IP — on
  orion, nothak.gr's form read as a login from "DE");
- an IPv6 address counts as its /64 (a phone rotates privacy addresses);
- the networks of services that read a mailbox for its owner count as ONE
  source with no country: Google (AS15169) and Google Cloud (AS396982, where
  third-party mail apps and CRMs sync), Microsoft (8075), Yahoo (36647,
  26101, 34010), Apple (714, 6185) and Mail.ru / VK (47764, its collector
  `rimap*.m.smailru.net` behind the myMail app). Gmail fetching a mailbox over
  POP3 logs in from a dozen Google addresses an hour (titan); orion's
  info@socialpower.gr was read from the office (GR), the VK collector (RU)
  and an app on Google Cloud (US) in one hour — one owner, paged as a
  hijack before this. A hijacker on a VM in those networks is missed —
  Google Cloud and Azure (which shares AS8075 with Outlook.com) included, and
  likely VK Cloud's VMs if they sit in AS47764;
  they mostly use residential proxies and VPS networks.
- corporate security gateways count the same way, as ONE source with no
  country: Netskope (AS55256), Zscaler (AS53813, 62044, 22616) and Cisco
  Umbrella (AS36692). A company sends its staff's traffic out through the
  vendor's nearest point of presence, which geolocates anywhere: on orion,
  larrynail@aspirephysiciansolutions.com was read from a US phone, the French
  office and Netskope exits in IN and UG, and paged as a hijack every few
  hours. They are paid enterprise tenants, not a VPN anyone can buy (Cloudflare
  WARP or a consumer VPN still count by country);
- `::ffff:1.2.3.4` is `1.2.3.4`.

So "many IPs" needs ≥ 5 of them outside the mailbox's main country: a home,
a phone and a VPN are many addresses in two places, not a hijack.

## Hijack severity

Logins from many places are a candidate. In the week before this rule (Oct
2026) the fleet raised 33 critical hijacks on 10 mailboxes, and every one of
them was a mailbox READ from abroad (IMAP/POP3) with no mail sent from there:
owners travelling, behind a VPN or a corporate proxy. They paged the channel
and were reminded every 6 h until acknowledged, so the team stopped reading
them. A thief who has the password uses it, so a hijack is **critical** only
when, as well, within the hour:

- the mailbox **sent mail (SMTP AUTH) from a country it was not read from**
  (IMAP/POP3) within the hour: the owner's mail app sends from where it
  reads, a thief submitting spam sends from where nobody reads;
- or it **sent mail from two countries or more** within the hour: the owner
  and a thief with a full mail client both sending.

  No "home country" is guessed: within an hour the majority is whoever has
  more addresses, and a thief behind a proxy pool has more than the owner.
  Sources with no country (the fetchers and gateways above) are not judged.
  Each source keeps the time of its last login per protocol, so an address
  that sent two hours ago and only reads now has not sent within the hour.
  One gap is left: a thief who reads AND sends from one country while the
  owner only reads elsewhere looks like the owner sending from where they
  read. That warning names the country (`sent mail only from VN, where it is
  also read`), so check it is the owner's;
- the same mailbox has a `mail_outbound_spike` or `mail_bounce_spike` FINDING
  this check (one only held open on its volume is no news about this hour);
- its **forwarder or mail filter changed in the last 24 h** (cPanel: a line for
  the address in `/etc/valiases/<domain>` with that file changed, or
  `~<owner>/etc/<domain>/<local>/filter`, what webmail's Email Filters writes;
  the owner comes from `/etc/userdatadomains` / `/etc/userdomains` through
  `internal/panelmap`). A thief keeps a copy of the mail
  coming. `valiases` is the whole domain's file: a change to ANY forwarder of
  the domain counts for an address that has one, so check the forwarder the
  message names. Not read on DirectAdmin or Postfix hosts, only asked when
  nothing above already confirmed the hijack, and the answer is reused for
  10 minutes.

The message names which (`… and sent mail from VN — likely a stolen
password`). Otherwise the finding is a **warning** that says `reading only`
(or `sent mail only from GR, where it is also read`) and asks to check with
the owner. An alert published critical stays critical in `whats_wrong` /
`mail_traffic` while open, even if a later check judges the hour a warning
(the SMTP login left the window): publishing never downgrades. Reading alone can still be a thief (business email
compromise: the mail is read now and the fraud sent from elsewhere later), so
it is still published, shown in `whats_wrong` and `mail_traffic`, and rises to
critical, published again, the moment one of the above appears.

**No re-page for the same trip.** A resolved WARNING hijack is remembered for
7 days (`/var/lib/cfm/mail_abuse_published_hijacks.json`, next to the open
findings) with every country it was seen from while open. The same mailbox
back as a warning from no new country is not published again (it is still
listed in `whats_wrong` / `mail_traffic`), and each such sighting renews the
7 days, so an owner behind the same VPN every day is not paged every week. A
new country, a critical one, or 7 days without a sighting makes it news.
Nothing is quiet after a critical hijack: that password was in use and may
not have been changed. Only a critical hijack's `mail_recovered` says the
password still needs changing.

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
  address of another domain (`(another domain)`) — the spoofing tell (another
  address of its own domain is shown as `· as claim@…`, no tell);
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

`cfm.conf`: `MAIL_RBL_SPAMHAUS_DQS_KEY = <key>` (optional): a Spamhaus DQS
key, so the Spamhaus lookup works behind a public resolver. A credential:
keep it out of the repo; it is never logged, and `cfm debug` redacts it
(`internal/secretkeys`). A cfm.conf edit applies without a restart (so does
`MAIL_ABUSE_ALERT`).

## Not covered yet

- Bounces on a Postfix host with a content filter (amavis / rspamd
  re-injecting): the re-injected message has a new queue id with no
  authenticated sender, so its bounces are not attributed. Exim and plain
  Postfix are.
- IPv6 addresses on blocklists (few lists carry them).
- Recipient novelty and the contact-form pattern are shown as context, not a
  trigger of their own.
