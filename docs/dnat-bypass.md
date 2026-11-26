# DNAT Source-IP Bypass

CFM's DNAT redirects (`cfm dnat on` for the web ports, `cfm dnat cpanel on`
for the panel ports, `docs/panel-dnat.md`) send incoming connections to the
edge listeners, so they pass the challenge and WAF layer first. The bypass
lists exempt chosen source addresses from that redirect: their connections
reach the service on the original port (Apache/LiteSpeed, `cpsrvd`,
DirectAdmin) directly. It is the effect of `cfm dnat off` /
`cfm dnat cpanel off`, for those sources only.

A listed source loses everything the edge does on those ports: challenge,
WAF, edge bans, panel guard, per-vhost policy. Use it only for peers you
control; never for "skip the WAF for this customer".

## When to use it

- **cPanel WHM Transfer Tool.** `whm_xfer_download-ssl` on the destination
  server opens one HTTPS connection to the source server's `:2087` and runs
  rsync over it (`GET /acctxferrsync/…`), which no HTTP proxy handles. The
  panel listeners hand `/acctxfer(rsync|dsync)` to a raw byte tunnel
  (`configs/lua/cfm_panel_tunnel.lua`), so transfers normally work through
  CFM. When one still hangs, list the **destination** server's IP in the
  cPanel bypass on the **source** server: its connection then reaches
  `cpsrvd` directly, as with panel DNAT off. The bypass matches the
  connecting address, so always list the peer that opens the connection to
  this node.
- **Cluster peers** that talk to each other on web or panel ports.
- **Migration sources** whose transport does not survive an HTTP-aware
  intermediary.

## Two scopes, two files

| Scope | File | nft table | Exempts from |
|---|---|---|---|
| Web | `/etc/cfm/cfm.dnat_bypass` | `inet cfm_redirect` | `cfm dnat on`: tcp/80 → `:9080`, tcp+udp/443 → `:9043` (default listener ports) |
| Panel | `/etc/cfm/cfm.dnat_cpanel_bypass` | `inet cfm_panel_redirect` | `cfm dnat cpanel on`: 2082/2083/2086/2087/2095/2096/2222 → 12082-12222 |

The scopes are independent: an address in one file is still redirected by
the other chain. List a peer in both when it uses both.

## File format

- one IP or CIDR per line, IPv4 or IPv6
- blank lines, `#` lines and anything after the first token (a trailing
  `# comment`) are ignored
- a CIDR is normalised to its network (`84.54.49.5/24` reads as
  `84.54.49.0/24`)
- an unparseable line is skipped (no rule)
- packaged and CLI-created files are `0600 root:root`; keep them so

```text
# /etc/cfm/cfm.dnat_cpanel_bypass
84.54.49.205            # peer-cpanel-01 (transfer destination)
192.0.2.0/24            # internal management subnet
2001:db8:cafe::/56      # ipv6 management range
```

## CLI

```bash
cfm dnat bypass list | add <IP|CIDR> | remove <IP|CIDR>          # web scope
cfm dnat cpanel bypass list | add <IP|CIDR> | remove <IP|CIDR>   # panel scope
```

- `add` stores the normalised value; a duplicate is a no-op (exit 0).
  `remove` (aliases `rm`, `del`, `delete`) of an absent entry is a no-op
  (exit 0). `list` prints skipped lines on stderr and exits 1 when there
  are any.
- When the scope's DNAT is on, `add`/`remove` re-render its table at once
  (web: at the live listener ports and priority; panel: at the saved panel
  priority, `docs/panel-dnat.md`). If that fails, the old
  rules stay in force, the file already has the change, and the command
  exits 1. When the DNAT is off, the file is updated and applies on the next
  `cfm dnat on` / `cfm dnat cpanel on`.
- A hand edit of the file is not picked up by itself (a daemon restart
  leaves a live table as it is): re-run `cfm dnat on` /
  `cfm dnat cpanel on` with the options in use.

## How it renders in nftables

Each entry becomes one `accept` rule placed after `iif "lo" accept` and
before the port redirects, so a match leaves CFM's chain before any DNAT
rule runs. Panel chain on the `nft` engine, with two entries:

```nft
table inet cfm_panel_redirect {
    chain prerouting {
        type nat hook prerouting priority -101; policy accept;
        iif "lo" accept
        ip saddr 84.54.49.205 accept comment "cfm_dnat_bypass"
        ip6 saddr 2001:db8::1 accept comment "cfm_dnat_bypass"
        tcp dport 2082 dnat to :12082
        ...
        tcp dport 2222 dnat to :12222
    }
}
```

The web chain has the same shape with `tcp dport 80`, `tcp dport 443` and
`udp dport 443` redirects.

Both engines rewrite CFM's rules in the chain in one transaction (one
`nft -f` / one netlink batch) on every `on` and every bypass change, so the
order above always holds:

- `nft` engine: the entries go into the generated script
  (`internal/firewall/nft/dnat.go` `dnatScript`, `panel_dnat.go`
  `panelDNATScript`) with `comment "cfm_dnat_bypass"`. A skipped line is
  only a `# WARNING` comment in that script.
- `nftlib` engine: `internal/firewall/nftlib/dnat_bypass.go`
  `dnatBypassRuleExprs` builds `meta nfproto ipv4|ipv6` + source-address
  match (masked for a CIDR) + `accept`; the nfproto guard is needed because
  the inet chain sees both families. The rules are tagged with the userdata
  `cfm_dnat_bypass:v1:<value>` rather than an nft comment. A skipped line
  is logged as a `bypass entry:` warning.

## What still applies to a bypassed source

- **The input chain.** The bypass only skips the redirect. The connection
  then reaches `inet cfm input` for the ORIGINAL port, where `cfm.deny`,
  the block sets and the default drop still apply: the port must be open in
  `TCP_IN`/`UDP_IN` (or the source allowed). The scoped `ct status dnat`
  accepts that open the listener ports match only redirected connections,
  so they do nothing for it.
- **Other NAT chains.** A connection is NAT'd by the first nat chain that
  rewrites it; CFM's `accept` rewrites nothing, so a later nat chain on the
  same hook still runs. On an Imunify360 node whose WebShield redirect
  covers these ports (Imunify's chain at -100, CFM's ahead of it), a
  bypassed source goes to WebShield, not to the service directly.

## Verifying

```bash
cfm dnat cpanel bypass list
nft list table inet cfm_panel_redirect     # or inet cfm_redirect for the web scope
```

`cfm dnat` and `cfm dnat cpanel status` list the bypass rules on both
engines: the exec engine prints the raw table, the `nftlib` engine a
rendering of the live chain (`ip saddr … accept` / `ip6 saddr … accept`,
before the DNAT rules, as in the chain). If an entry is in the file but
not in the table, the DNAT is off or the file was hand-edited (see CLI
above).

End to end: during a transfer from a bypassed peer, `cpsrvd` on this node
logs the peer's own address (`/usr/local/cpanel/logs/access_log`); through
the panel listener it sees the proxy's local address instead. For a packet count, insert a counter
rule by hand (it is gone at the next rebuild):

```bash
nft 'insert rule inet cfm_panel_redirect prerouting ip saddr 84.54.49.205 counter accept'
nft list table inet cfm_panel_redirect
```

### cPanel transfer still stuck at ~20% even with tunnel changes

A transfer through the tunnel that sits at "20% Homedir" is usually close
propagation, not buffering: `cpsrvd` finishes and sends FIN, the FIN does
not reach `whm_xfer_download-ssl` promptly, and it keeps waiting on an
established socket.

- Confirm which path the peer takes (bypassed direct `:2087` or tunnelled
  `:12087`) with a counter rule or the logs.
- Capture both ends while reproducing:

  ```bash
  tcpdump -ni any host <peer_ip> and tcp port 2087
  tcpdump -ni any host <peer_ip> and tcp port 12087
  ```

  The upstream FIN should be mirrored to the client side quickly.
  `scripts/debug/cpanel-transfer-capture.sh` runs a synchronised capture on
  both servers, with and without the bypass.
- The shipped tunnel locations already set `lingering_close off`; check a
  local edit has not removed it.
- An L4 device in the path (cloud LB, NAT gateway, IDS) can swallow a
  half-close on a long-lived flow.

To recover quickly, bypass the destination's IP on the source server
(`cfm dnat cpanel bypass add <dest_ip>`).

## Do the DNAT listener ports need to be in `TCP_IN`?

No. `cfm dnat on` (tcp/80 → `:9080`, tcp+udp/443 → `:9043` by default) and
`cfm dnat cpanel on` install scoped accepts in `inet cfm input` that match
`ct status dnat` and the original destination port, so they open the
listener ports only for connections CFM redirected. Do not add the listener
ports to `TCP_IN`.

`cfm dnat on` prints one `Firewall: opened scoped 80->9080 tcp (nft cfm/input)`
line per mapping, and `cfm dnat` (status) lists each mapping under
**Scoped DNAT accepts** as:

- `open`: present and ahead of the default drop;
- `BLOCKED`: present but after the default drop (`cfm dnat off` then
  `cfm dnat on` reinstalls it);
- `ABSENT`: not installed.

If every mapping is `open` and a client still cannot connect, the drop is
outside CFM: an external firewall filtering the listener ports (an
Imunify `INPUT` chain runs after CFM's input chain and knows nothing of
them), or an edge proxy listening only on `127.0.0.1`.

## Implementation map

| File | Role |
|---|---|
| `configs/cfm.dnat_bypass`, `configs/cfm.dnat_cpanel_bypass` | Packaged files (`/etc/cfm/`, `%config(noreplace)` / seeded by the .deb's postinst, `0600 root:root`) |
| `internal/firewall/dnat_bypass.go` | Paths, parsing, scopes, `nft` rule text |
| `internal/firewall/nft/dnat.go`, `nft/panel_dnat.go` | `nft` engine: web / panel table scripts |
| `internal/firewall/nftlib/dnat_bypass.go` | `nftlib` engine: bypass expressions |
| `internal/firewall/nftlib/challenge.go` (`installDNATRules`, `installEdgeDNATRules`) | `nftlib` engine: web chain rebuild |
| `internal/firewall/nftlib/panel_dnat.go` (`PanelDNATOn`) | `nftlib` engine: panel table rebuild |
| `internal/dnat/bypass.go` | CLI: list / add / remove, re-render |
| `internal/dnat/cli.go` | Dispatch: `cfm dnat bypass`, `cfm dnat cpanel bypass` |
