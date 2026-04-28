# Ad-hoc DNS Forensics Runbook (Temporary NFLOG Capture)

Use this runbook only when an **outbound abuse alert** needs deeper DNS visibility for one suspect account. The goal is short, scoped capture without creating permanent detector noise.

> Scope: temporary DNS egress packets for a specific Linux UID/GID.

## When to use this

- You already have an outbound alert for a user/process and need DNS corroboration.
- Existing logs are insufficient to attribute suspicious destination churn.
- You can run a **short** capture window (recommended 60–180 seconds).

Do **not** leave any of these rules running continuously.

---

## Guardrails (required)

1. **Short duration:** default to `120s`; do not exceed `300s` without incident lead approval.
2. **Sample cap:** stop after a bounded packet count (`-c` in `tcpdump`) to avoid disk blowups.
3. **Scoped identity:** match only the target `skuid`/`skgid` and DNS ports (`53`, optionally `853`).
4. **Dedicated path + retention:** write under `/var/log/cfm/forensics/` and remove artifacts within 24h unless attached to a ticket.

Recommended staging:

```bash
sudo install -d -m 0700 /var/log/cfm/forensics
sudo find /var/log/cfm/forensics -type f -mtime +1 -delete
```

---

## 1) Temporary nftables + NFLOG capture

Set variables first (replace with case-specific values):

```bash
TS="$(date -u +%Y%m%dT%H%M%SZ)"
UID_TO_WATCH=1007
GID_TO_WATCH=1007
NFLOG_GROUP=191
CAP_SECONDS=120
PCAP_OUT="/var/log/cfm/forensics/dns-${UID_TO_WATCH}-${TS}.pcap"
TXT_OUT="/var/log/cfm/forensics/dns-${UID_TO_WATCH}-${TS}.txt"
```

Create an ephemeral chain and hook it to `output` for DNS only:

```bash
sudo nft add table inet cfm_forensics
sudo nft 'add chain inet cfm_forensics dns_probe { type filter hook output priority 11; policy accept; }'
sudo nft add rule inet cfm_forensics dns_probe meta skuid "$UID_TO_WATCH" udp dport 53 nflog group "$NFLOG_GROUP" prefix "dns_uid "
sudo nft add rule inet cfm_forensics dns_probe meta skuid "$UID_TO_WATCH" tcp dport 53 nflog group "$NFLOG_GROUP" prefix "dns_uid "
sudo nft add rule inet cfm_forensics dns_probe meta skgid "$GID_TO_WATCH" udp dport 53 nflog group "$NFLOG_GROUP" prefix "dns_gid "
sudo nft add rule inet cfm_forensics dns_probe meta skgid "$GID_TO_WATCH" tcp dport 53 nflog group "$NFLOG_GROUP" prefix "dns_gid "
```

Optional DoT visibility (only if needed):

```bash
sudo nft add rule inet cfm_forensics dns_probe meta skuid "$UID_TO_WATCH" tcp dport 853 nflog group "$NFLOG_GROUP" prefix "dot_uid "
```

Start capture with both timeout and packet cap:

```bash
sudo timeout --signal=INT "${CAP_SECONDS}s" \
  tcpdump -i nflog:"$NFLOG_GROUP" -nn -s0 -c 3000 -w "$PCAP_OUT"
```

---

## 2) Example parsing commands

Decode to readable text:

```bash
tcpdump -nn -tttt -r "$PCAP_OUT" > "$TXT_OUT"
```

Quick DNS summary (qname + rrtype where present):

```bash
tcpdump -nn -vvv -r "$PCAP_OUT" 'udp port 53 or tcp port 53' \
  | sed -n 's/.*\? \([^ ]*\)\. (\([0-9]*\)).*/\1 type=\2/p' \
  | head -n 200
```

Top destination resolvers contacted:

```bash
tcpdump -nn -r "$PCAP_OUT" \
  | awk '/ > / {print $5}' | sed 's/:.*//' | sort | uniq -c | sort -nr | head
```

If using `ulogd2` JSON output instead of direct `tcpdump` on NFLOG:

```bash
jq -r 'select(.oob.prefix?|test("dns_(uid|gid)|dot_uid")) | [.oob.time_sec,.ip.daddr,.l4.dport] | @tsv' /var/log/ulog/dns-forensics.json \
  | head
```

---

## 3) Safe cleanup (always run)

Remove temporary nft table/chain/rules in one command:

```bash
sudo nft delete table inet cfm_forensics 2>/dev/null || true
```

Verify nothing remains:

```bash
sudo nft list tables | grep -q 'cfm_forensics' && echo 'still present' || echo 'clean'
```

Retention cleanup for local artifacts:

```bash
find /var/log/cfm/forensics -type f -name 'dns-*.pcap' -mtime +1 -delete
find /var/log/cfm/forensics -type f -name 'dns-*.txt' -mtime +1 -delete
```

---

## 4) Operator notes

- Prefer one UID at a time. Parallel captures increase ambiguity and noise.
- If packet volume hits cap before timeout, treat as high-signal and escalate.
- Save only minimal artifacts needed for incident evidence; scrub or rotate quickly.
- After cleanup, continue normal response using outbound sentinel alerts and process/context logs.
