# DNAT Source-IP Bypass

Source-IP bypass lets trusted peers reach the underlying service
(`cpsrvd`, Apache, DirectAdmin) **directly**, skipping CFM's DNAT
redirect to openresty / angie. CFM otherwise sits in the prerouting
chain rewriting destination ports so all incoming traffic flows through
the challenge / WAF layer first. The bypass lifts that interception for
a curated source-IP allowlist.

This is the same effect as running `cfm dnat off` or
`cfm dnat cpanel off`, but **per-source-IP** instead of globally.

## When to use it

- **cPanel-to-cPanel WHM Transfer Tool source hosts.** The Transfer
  Tool's `whm_xfer_download-ssl` rsync stream on port 2087 uses a
  custom non-standard HTTP variant (`GET /acctxferrsync/<acct>?...`
  with the rsync protocol streamed bidirectionally over the same
  request) that breaks when wrapped by any HTTP-aware proxy. Listing
  the source server's IP in the cPanel bypass file makes the WHM
  transfer source connection hit `cpsrvd` natively — exactly as it
  does with cpanel DNAT off — while panel filtering stays in place
  for everyone else.

- **Cluster peers.** Two or more nodes that talk to each other on
  panel / web ports without needing the challenge layer.

- **Migration sources from partner companies.** Trusted external
  providers handing customer data over and using protocols (rsync
  over HTTPS, dovecot dsync, raw socket pass-through) that don't
  survive HTTP-aware intermediation.

- **Anything where you control the source IP and prefer raw upstream
  access over the CFM-mediated path.**

Don't use it for "I want to skip the WAF for my customer" scenarios —
listed IPs lose ALL of CFM's L4–L7 protection on the matching ports.

## Two scopes, two files

| Scope | File | nft table | Affects |
|---|---|---|---|
| **Web** | `/etc/cfm/cfm.dnat_bypass` | `inet cfm_redirect` | `cfm dnat on`: 80 / 443 → openresty/angie |
| **cPanel** | `/etc/cfm/cfm.dnat_cpanel_bypass` | `inet cfm_panel_redirect` | `cfm dnat cpanel on`: 2082 / 2083 / 2086 / 2087 / 2095 / 2096 / 2222 → 12082-12222 |

The two scopes are independent. An IP listed in the cPanel file does
*not* bypass the web DNAT, and vice versa. Add to both if you want
both — common for a peer node that serves both web and panel traffic.

## File format

Same as `cfm.allow` / `cfm.deny`:

- one IP or CIDR per line
- IPv4 and IPv6 both supported (single addresses and CIDR networks)
- blank lines ignored
- lines starting with `#` ignored
- trailing `# comment` on a data line also ignored
- entries are mask-normalised on add (`84.54.49.5/24` becomes
  `84.54.49.0/24`) so `add` is idempotent against existing entries

Example:

```text
# /etc/cfm/cfm.dnat_cpanel_bypass

84.54.49.205            # peer-cpanel-01 (transfer source)
84.54.49.206            # peer-cpanel-02
192.0.2.0/24            # internal management subnet
2001:db8:cafe::/56      # ipv6 management range
```

## CLI

```bash
# web scope
cfm dnat bypass list
cfm dnat bypass add    <IP|CIDR>
cfm dnat bypass remove <IP|CIDR>
cfm dnat bypass help

# cPanel scope
cfm dnat cpanel bypass list
cfm dnat cpanel bypass add    <IP|CIDR>
cfm dnat cpanel bypass remove <IP|CIDR>
cfm dnat cpanel bypass help
```

`add` is dedup-safe: a duplicate add is a no-op (exit 0). `remove` of
a non-present entry is also a no-op (exit 0) so the commands are safe
to script.

When DNAT is **on**, add / remove triggers an immediate re-render of
the matching nftables table and the bypass takes effect for the next
packet. When DNAT is **off**, the file is still persisted and the
bypass applies on the next `cfm dnat on` / `cfm dnat cpanel on`.

The help text is also reachable via `cfm dnat help`, `cfm dnat cpanel
help`, `cfm dnat bypass help`, and `cfm dnat cpanel bypass help`.

## How it renders in nftables

Each bypass entry becomes one `accept` rule in the prerouting chain,
inserted **between** the existing `iif "lo" accept` and the dport DNAT
rules. nftables evaluates the chain top-to-bottom and the first
matching rule wins — so a bypass match short-circuits before any NAT
translation runs.

Example chain after `cfm dnat cpanel on` with two bypass entries:

```nft
table inet cfm_panel_redirect {
    chain prerouting {
        type nat hook prerouting priority -101; policy accept;

        iif "lo" accept                                                    # always-first loopback exemption
        ip  saddr 84.54.49.205    accept comment "cfm_dnat_bypass"         # bypass
        ip6 saddr 2001:db8::1     accept comment "cfm_dnat_bypass"         # bypass (ipv6)
        tcp dport 2082 dnat to :12082
        tcp dport 2083 dnat to :12083
        tcp dport 2086 dnat to :12086
        tcp dport 2087 dnat to :12087
        tcp dport 2095 dnat to :12095
        tcp dport 2096 dnat to :12096
        tcp dport 2222 dnat to :12222
    }
}
```

A packet from `84.54.49.205` to `earth:2087` hits the second rule and
is accepted as-is. The dport 2087 rule never fires, so the packet
reaches the kernel socket on port 2087, i.e. `cpsrvd`. A packet from
any other source to `earth:2087` falls through to the dport rule and
gets DNAT'd to port 12087, i.e. the CFM panel listener.

The web DNAT chain (`inet cfm_redirect`) follows the same pattern with
`tcp dport 80 dnat to :HTTP_PORT` / `tcp dport 443 dnat to
:HTTPS_PORT` rules instead of the panel ports.

## Backend implementations

CFM ships two firewall backends. Both implement bypass identically at
the rule level; the difference is *how* the rules get into nftables:

- **`nft` (shell-out, default).** The backend renders a complete `nft`
  script as text and pipes it to the `nft` CLI. Bypass entries are
  injected as `add rule ...` lines in the script between the loopback
  accept and the dport DNAT lines. See
  `internal/firewall/nft/dnat.go::dnatScript` and
  `internal/firewall/nft/panel_dnat.go::panelDNATScript`.

- **`nftlib` (netlink-direct, opt-in via `CFM_FIREWALL_ENGINE=nftlib`).**
  The backend talks directly to the kernel via netlink using
  `github.com/google/nftables`. Bypass entries are built as
  `[]expr.Any` lists by
  `internal/firewall/nftlib/dnat_bypass.go::dnatBypassRuleExprs`. The
  emitted expressions are:
  1. `meta load nfproto => reg1`
  2. `cmp eq reg1 == ipv4|ipv6`
  3. `payload @network base, offset 12/8, len 4/16 => reg1`
  4. *(CIDR only)* `bitwise reg1 = reg1 & mask ^ 0`
  5. `cmp eq reg1 == <network bytes>`
  6. `verdict accept`

  The leading `nfproto` check is required for inet-family chains: the
  same chain sees both IPv4 and IPv6 packets, and reading source-IP
  bytes from an IPv6 packet at an IPv4 payload offset would yield
  garbage. The nfproto guard short-circuits to "rule doesn't match"
  for packets of the wrong family.

Both backends store bypass rules with a distinct `comment`
("cfm_dnat_bypass") / UserData prefix (`cfm_dnat_bypass:v1:`) so they
are easy to identify in `nft list table inet cfm_panel_redirect` and
the nftlib reconciler doesn't accidentally treat them as DNAT rules to
delete.

## Failure modes and diagnostics

### Verifying the rules landed

```bash
# Full table inspection — bypass rules will show up between iif lo and
# the dport DNAT rules with the cfm_dnat_bypass comment.
nft list table inet cfm_panel_redirect
nft list table inet cfm_redirect
```

If you see your bypass entry in `cfm dnat cpanel bypass list` but NOT
in the nftables output, either DNAT is off (the rule is queued for the
next `on`) or you forgot to reload after manually editing the file
instead of using the CLI. Re-run `cfm dnat cpanel on` to force a
re-render.

### Verifying a packet is actually being bypassed

The simplest end-to-end check is to look at the upstream service's
access log. For cPanel, `tail /usr/local/cpanel/logs/access_log` on
the **source** server during a transfer from a bypassed peer: requests
should arrive with the actual client IP (not 127.0.0.1) and without
the `X-Forwarded-For` header that the CFM panel listener would
otherwise inject.

For finer-grained tracing, drop in a counter rule (manually, won't
survive a reload):

```bash
nft 'insert rule inet cfm_panel_redirect prerouting ip saddr 84.54.49.205 counter accept'
nft list table inet cfm_panel_redirect    # watch packets/bytes increment
```

### cPanel transfer still stuck at ~20% even with tunnel changes

If `/acctxferrsync` still hangs after long-running tunnel fixes, the
most common miss is not request buffering but **close propagation** on
the return path:

1. `cpsrvd` finishes streaming and sends FIN.
2. proxy path does not propagate FIN/RST promptly to the WHM transfer
   client.
3. `whm_xfer_download-ssl` keeps polling an ESTAB socket waiting for
   the terminal close marker, and WHM UI sits at "20% Homedir".

Quick checks:

- Confirm the source IP really hits the intended path (bypassed direct
  `:2087` *or* tunneled `:12087`) with packet counters/logs.
- Capture both ends during reproduction:

```bash
tcpdump -ni any host <peer_ip> and tcp port 2087
tcpdump -ni any host <peer_ip> and tcp port 12087
```

You should see upstream FIN mirrored to the client side quickly. If
not, the data pump can be correct while the session still appears hung.

- Check for lingering-close behavior on the tunnel location. For these
  transfer endpoints use `lingering_close off` so nginx/OpenResty
  doesn't hold the connection open waiting for additional client bytes
  after response completion.
- If your environment has intermediate L4 devices (cloud LB, NAT GW,
  IDS middleboxes), verify they are not normalizing away half-close
  behavior on long-lived flows.

When time-to-recovery matters, a source-IP DNAT bypass is a safe
operational fallback for trusted transfer peers because it restores the
exact direct-to-cpsrvd behavior while keeping mediation for all other
sources.

### Skipped (unparseable) entries

If the CLI's `add` won't accept an entry it's not in the file. If you
hand-edited the file with a malformed line, you'll see:

- in `cfm dnat bypass list`, a stderr block listing the skipped lines
- in the rendered nftables (when the `nft` backend is in use), a
  `# WARNING: cfm.dnat_*_bypass skipped entry: …` comment in the
  generated script

Fix the malformed line and re-run `cfm dnat [cpanel] on` to reload.

## Interaction with the rest of CFM

- **Allow / deny lists (`cfm.allow`, `cfm.deny`).** Bypass operates on
  the prerouting chain; allow / deny operate on the input chain.
  They're orthogonal. A bypassed IP that's also in `cfm.deny` will
  still be blocked at the input chain.
- **Challenge engine.** A bypassed IP never reaches the openresty /
  angie listener for the matching ports, so challenge pages and WAF
  inspection don't apply to it. The challenge engine continues to
  protect every other source.
- **Imunify360 / WebShield.** Bypass rules run before any Imunify
  chain CFM may delegate to. If you bypass an IP, Imunify also won't
  see its panel traffic on those ports.
- **`EnsureDNATAccepts` / `PanelDNATAcceptState`.** These maintain
  scoped `ct status dnat` accepts in the input chain so DNAT'd
  traffic from the prerouting chain can actually reach the local
  listener. Bypass rules accept BEFORE the dnat redirect runs, so
  `ct status dnat` never gets set for them — and these accept rules
  don't apply to bypassed traffic. That's fine because bypassed
  packets land directly on the original port (cpsrvd, Apache) whose
  listening socket accepts them without needing the DNAT-tagged
  accept.

## Do the DNAT listener ports need to be in `TCP_IN`?

**No.** `cfm dnat on` DNATs `tcp/80 → :9080` and `tcp+udp/443 → :9043`
in prerouting, then installs scoped `ct status dnat` accepts in
`inet cfm/input` so the translated traffic reaches the edge listener.
These accepts match on the *original* destination port
(`ct original proto-dst 80/443`), so they open `9080/9043` **only** for
packets CFM itself redirected — you do not (and should not) add
`9080/9043` to `TCP_IN`. `cfm dnat cpanel on` does the same for the
panel listener ports (`12082..`, `12222`).

Because the install happens inside `DNATOn`, it used to be invisible.
`cfm dnat on` now prints one `Firewall: opened scoped 80->9080
(nft cfm/input)` line per mapping (mirroring `cfm dnat cpanel on`), and
`cfm dnat` status prints a **Scoped DNAT accepts** block reporting each
mapping as:

- `open` — accept present and effective;
- `BLOCKED` — accept present but sitting *after* the default drop (run
  `cfm dnat off` then `cfm dnat on` to reinstall it before the drop);
- `ABSENT` — no accept found.

If every mapping reads `open` but a non-allowlisted client still can't
reach the site, the drop is **upstream of CFM**, not a missing CFM
rule — check for an external firewall filtering the listener ports
(CSF/Imunify `INPUT` at priority `filter`/`0` runs *after* CFM's input
chain and does not know about `9080/9043`), or an edge proxy that only
listens on `127.0.0.1` instead of the public address DNAT preserves.

## Security considerations

- A bypassed IP completely opts out of CFM's panel / web mediation on
  the matching ports. The challenge layer, the WAF, the open-redirect
  guard, the panel-token transport, and any per-vhost policy do not
  apply to it. Treat the bypass file as a security-critical asset.
- File permissions are `0600 root:root` (both CLI-created files and the
  packaged templates). Don't loosen them.
- Each entry should be a specific IP or a small CIDR. Avoid catch-all
  ranges like `0.0.0.0/0` or `::/0`; those would defeat the entire
  DNAT.
- Audit periodically. `cfm dnat bypass list` and
  `cfm dnat cpanel bypass list` show every entry; pipe through
  configuration management to track drift.

## Implementation map

| File | Role |
|---|---|
| `configs/cfm.dnat_bypass` | Sample / packaged config for the web scope |
| `configs/cfm.dnat_cpanel_bypass` | Sample / packaged config for the cPanel scope |
| `internal/firewall/dnat_bypass.go` | Shared: file parsing, validation, scope types |
| `internal/firewall/nft/dnat.go` | `nft` backend: web DNAT script with bypass injection |
| `internal/firewall/nft/panel_dnat.go` | `nft` backend: cPanel DNAT script with bypass injection |
| `internal/firewall/nftlib/dnat_bypass.go` | `nftlib` backend: bypass `expr.Any` builders |
| `internal/firewall/nftlib/challenge.go` (`installDNATRules`) | `nftlib` backend: web DNAT bypass reconciler |
| `internal/firewall/nftlib/panel_dnat.go` (`PanelDNATOn`) | `nftlib` backend: cPanel DNAT bypass placement |
| `internal/dnat/bypass.go` | CLI handler: add / remove / list, reload trigger |
| `internal/dnat/cli.go` | Dispatch: `cfm dnat bypass`, `cfm dnat cpanel bypass` |
