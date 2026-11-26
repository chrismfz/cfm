# Setting up a node (new server or disaster recovery)

The order of steps that takes a server from "packages installed" to "CFM and
its edge in the path, reporting to cfm-web". The steps that need a person
(a secret, a password, the switch itself) are marked **[you]**.

Written from the 2026-11-26 rebuild of a wiped cPanel + CloudLinux node, where
the `cfm` and `cfm-edge` rpms were installed and nothing more had been done.
Each subsystem's own doc stays the reference; this page holds the order, what
is per node, and what no package does for you.

## 0. Before you start

- **Is the node already in cfm-web?** `list_nodes` (CFM MCP) or the Agents
  page. A rebuilt node keeps its agent and its token (`token_manage list`: the
  token pinned to the node's IP). Its secret is shown only in the cfm-web
  admin panel, never through the connector **[you]**. A new node: create a
  `server` token pinned to its IP, then the agent (`agent_manage create`;
  `server_name` must match the node's TLS certificate, `CLAUDE.md` of cfm-web
  §5).
- **Pick a reference node** of the same kind (same panel, same Imunify
  situation) to read per-node choices from. Read its files; do not copy them
  whole. A long-running node's `/etc/cfm` keeps the layout of the release it
  was first installed with (`%config(noreplace)` / the deb seed never rewrite
  an edited file), so it lacks every section and key added since. Start from
  the new package defaults and carry over only the values in §2.

## 1. Packages

```bash
dnf install https://repo.nixpal.com/el/nixpal.rpm   # the repo (EL)
dnf install cfm cfm-edge
dnf install nixpal-clamav                            # if the node scans uploads (§4)
```

`rpm -V cfm` clean means `/etc/cfm` still holds the defaults. Keep a copy
before editing: `cp -a /etc/cfm /root/cfm-setup-$(date +%Y%m%d)/`.

## 2. Configuration: what is per node

**Per-node secrets go in `/etc/cfm/cfm.api.conf`** (0600, seeded from
`cfm.api.conf.example` on first install; read at start, so restart after an
edit). Only these keys are read there, each overriding `cfm.conf` when set:

| Key | Value |
|---|---|
| `API_URL` | `https://cfm.myip.gr` |
| `AUTH_TOKEN` | this node's cfm-web token **[you]** |
| `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY` | the fleet's MaxMind account (both empty = the IPLocate mirror) |

Setting them in `cfm.conf` instead works too (older nodes do); then make
`cfm.conf` 0640.

**In `cfm.conf`:**

| Key | When |
|---|---|
| `NFT_DNAT_PRIORITY = -101` | **Imunify360 nodes.** WebShield DNATs at -100, ahead of CFM's default -99, and a connection is NAT'd once (`docs/imunify360-gap-analysis.md`, "WebShield"). `cfm edge check` `web-dnat-order` confirms it |
| `ADMIN_TOKEN_IP_BINDING = "enforce"` | as the reference node runs it, if it does; the conf's own comment asks for a canary first on a new kind of node (`docs/security/control-plane.md` §4) |
| `MAIL_RBL_SPAMHAUS_DQS_KEY` | the fleet's Spamhaus DQS key, on mail nodes |
| `CLAMD_SOCKET` | `/run/nixpal-clamd.sock` with `nixpal-clamav` (the shipped default is `/run/cfm-clamd.sock`) |
| `SMTP_ALLOWUSER` | only if the node has local accounts that send directly |

Leave the generated tokens alone: the daemon keeps per-node values of
`CHALLENGE_TOKEN`, `OPENRESTY_TOKEN` and `SSLCOLLECTOR_SOCK_TOKEN` in
`/var/lib/cfm/secrets/`, and with `MCP_TOKEN` empty it generates one into
`/var/lib/cfm/mcp_token`. `TCP_IN` needs no edge ports (9080/9043/12xxx): the
DNAT accepts are scoped `ct status dnat` rules.

**The lists:**

- `cfm.blocklists`: the shipped file has `MYALLOW` on and `MYBLOCK`
  **commented out**; uncomment it for the fleet blacklist.
- `cfm.allow` / `cfm.dyndns`: the management hosts (cfm-web's own address
  is allowed automatically from `API_URL`).

**`notify.conf`:** the sendmail `to`, and the webhook channel (`enabled = 1`,
`webhook_url`) as on the reference node.

**`detectors.conf`:** the reference node's thresholds and `BLOCK` policies
where they are deliberate fleet choices, plus its `detectors.d/` overlays.
Leave out its site-specific entries (`CHALLENGE_VHOST_IGNORE`,
`CHALLENGE_HOST_BYPASS`, a `RULE_<id> = 0` held for one site's false
positive) and turn off detectors for software the node does not run
(`postfix_*` on an Exim node, `ngm_auth` without ngm).

## 3. The daemon

```bash
systemctl enable --now cfm
```

Check: `systemctl is-active cfm`, `tail /var/log/cfm/cfm.log` (every
`[firewall] … status=ok`), the feed sets filled (`block_ext_v4_hosts` holds
hundreds of thousands of elements), `/var/lib/cfm/maxmind/` populated, the
node UP in cfm-web and answering `node_call … whats_wrong`.

- **`209/STDOUT` on every restart** = `/var/log/cfm` is missing. The unit's
  `StandardOutput=append:` file is opened before systemd creates
  `LogsDirectory=`. Packages released after 2026.11.25 create the directory
  (CHANGELOG); with an older one, `install -d -m 0700 /var/log/cfm`.
- A fresh start also writes the edge's Lua token files
  (`/var/lib/cfm/lua/cfm_token.lua`, `cfm_bridge_token.lua`), which the edge
  installer needs (§5).

**[you]** The first cfm-admin user (the password is prompted):

```bash
cfm auth user add -u <name> -r admin
```

## 4. What no package sets up

| What | How |
|---|---|
| ClamAV (`nixpal-clamav`) | the package ships `clamd.conf`, the units and the timer. The fleet's `freshclam.conf` adds the Sanesecurity and cfm-web databases (`cfm.myip.gr/clamav/*`): copy it from the reference node, run `freshclam`, then `systemctl enable --now nixpal-clamav nixpal-freshclam.timer` (`docs/clamav.md`) |
| cPanel/WHM plugin | `bash /usr/share/cfm/plugins/cfm-plugin-cpanel/install.sh` (enables the `cfm_cpanel` feature in every feature list, restarts cpsrvd; later upgrades refresh it) |
| Apache TSV log (cPanel, optional) | `install -m 0644 /usr/share/cfm/configs/httpd-cfm.conf /etc/apache2/conf.d/`, `apachectl -t`, graceful. Only the web detector's file source for when the edge socket is off; most edge nodes run without it. Its other two parts are covered elsewhere now: `cfm realip fix` writes the loopback trust (§5) and the edge hides `Upgrade` / `Alt-Svc` itself. Rotation: `docs/log-rotation.md` |

## 5. The edge

```bash
bash /usr/share/cfm/scripts/install-edge.sh    # prepares cfm-edge only: no start, no DNAT
```

It adopts `/etc/cfm-edge/nginx.conf`, installs the sidecars, prepares the
IPv6 listen (`docs/edge-ipv6.md`) and runs `cfm realip fix`, which must end
`OK` (it reads Apache along its own Include chain, where the last
`RemoteIPHeader` wins; the edge sets all three headers it accepts,
`docs/origin-real-ip.md`). To see it for real before the switch, start the
edge out of the path and send a request from a second local address, if the
node has one:

```bash
systemctl restart cfm-edge
curl -sk -o /dev/null --interface <second-ip> --resolve <site>:9043:<main-ip> "https://<site>:9043/?realip-test"
grep realip-test /var/log/apache2/access_cfm_tsv.log | cut -f2   # must be <second-ip>, not 127.0.0.1
```

Then **[you]** the switch, as the installer prints it:

```bash
cfm edge on
cfm edge panel on --mode auto --priority -101   # as the reference node, if its panel ports go through the edge
systemctl enable cfm-edge
cfm edge check                                  # every line ok
```

Check from another host: a few sites over http and https, the panel ports
(2083/2087/2096), SSH and mail. Way back: `cfm edge panel off; cfm edge off`.

## 6. Afterwards

- Write the change into the host's own notes (`/root/OPS.md` on the fleet).
- `whats_wrong` still lists `service flapping: cfm.service` for a while if the
  first start looped (§3).
- An `output` hook "priority 0 ambiguity" against iptables-nft / cPanel's
  `cpanel_smtp_restrict` also shows on long-running nodes (rigel, 2026-11-26),
  so it is not a sign of a bad setup; it was not analysed further.
