# Panel DNAT (cPanel / WHM / Webmail / DirectAdmin)

`cfm dnat cpanel on` (alias: `cfm dnat panel on`) redirects the panel ports
to CFM's edge listeners, so the panel gets the same edge as the sites: the
exploit guard, the panel WAF and decision (block tier, enforce by default,
`PANEL_WAF_MODE` / `PANEL_DECISION_MODE`) and a challenge for un-cleared
browsers. It uses its own nft table, `inet cfm_panel_redirect`. The listener
ports need no `TCP_IN` entry: scoped `ct status dnat` rules admit the
translated traffic.

| Panel port | → CFM listener |
|---|---|
| cPanel / WHM / Webmail 2082-2096 | 12082-12096 |
| DirectAdmin 2222 | 12222 |

## Commands

```
cfm dnat cpanel status
cfm dnat cpanel on [--mode auto|chain-imunify|direct-cpsrvd|fallback] [--priority -101|-99]
cfm dnat cpanel off
cfm dnat cpanel bypass list | add <IP|CIDR> | remove <IP|CIDR>
```

`on` always enables the challenge (forced mode). The old
`--challenge …` / `challenge=` arguments and `cfm dnat cpanel challenge
on|off` are deprecated: accepted with a warning, ignored.

**Modes**

- `auto`: `chain-imunify` when Imunify360 / WebShield mappings are found,
  else `direct-cpsrvd`.
- `chain-imunify`: CFM takes the panel ports first and proxies to Imunify's
  WebShield `522xx` targets.
- `direct-cpsrvd`: CFM takes them first and proxies to local `cpsrvd` `208x`.
- `fallback`: Imunify first (priority -99). Not a complete panel mitigation
  when Imunify already redirects the ports.

**Priority:** `-101` = CFM first (the default), `-99` = Imunify first.
`cfm dnat cpanel on --priority …` persists the choice, and the daemon reuses
it on restart and reboot (`PanelStartupPriority`: the saved value, else the
`NFT_PANEL_DNAT_PRIORITY` env var, else -101). `cfm.conf`'s
`NFT_DNAT_PRIORITY` is the WEB redirect's priority and does not touch the
panel chain.

## DirectAdmin

`2222 → 12222` is TLS-terminated at the CFM listener and proxied to
`https://127.0.0.1:2222`. DirectAdmin then sees `127.0.0.1`; CFM sends the
client in `X-Forwarded-For`. To log the real visitor:

```bash
da config-set x_forwarded_from_ip "127.0.0.1" --restart
```

## Notes

- CFM never changes or deletes Imunify's chains or tables.
- API / webcall traffic skips the browser challenge, but the exploit guard
  still runs first. The list of cPanel's own API / SSO / transfer endpoints
  is `cfm_panel_hosts.is_panel_api_or_sso` (CLAUDE.md §6).
- Only CFM's own clearance cookie (`cfm_clearance_p<port>` on panel ports)
  counts as a solved challenge; third-party cookies (`cf_clearance`,
  `cp_security_token`) do not. Scope and host binding:
  `docs/security/challenge-scope-mapping.md`.
- Trusted peers that must reach `cpsrvd` directly (cluster members, WHM
  Transfer Tool sources, whose `whm_xfer_download-ssl` rsync stream breaks
  behind any HTTP proxy) go in the bypass list:
  `docs/dnat-bypass.md`.
- cPanel / WHM must still be patched; this is defence in depth.
