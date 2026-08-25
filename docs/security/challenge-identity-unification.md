# Challenge-server request identity & scheme unification (Audit Step 1, item 8)

**Status:** ✅ implemented (this change) — challenge server now derives client
identity and effective scheme from the shared `internal/reqident` rule.
**Prerequisite for:** Step 2 (mounting `/__cfm_challenge` + `/__cfm_verify` in
the apiserver control plane).

---

## 1. Why this exists

The audit (`Audit.md` Step 1, item 8; `Audit.md §"ChallengeServer direct-mount
warning"`) requires the ChallengeServer to consume the **same** request-identity
and effective-scheme rules as the apiserver control plane **before** its handlers
are mounted on a public listener. Until this change the two components had
independent, divergent implementations:

| | apiserver `request_identity.go` | challenge server (old) |
|---|---|---|
| Trusts forwarded IP from | **loopback peer only** | loopback **+ private + link-local + Cloudflare** (`isTrustedProxyPeer`) |
| Client-IP header order | `X-Real-IP` → `X-Forwarded-For` | `CF-Connecting-IP` → `X-Real-IP` → `X-Forwarded-For` |
| Multi-hop `X-Forwarded-For` | **rejected** (fail closed, one canonical IP) | took the **first element** |
| Effective scheme | `X-Forwarded-Proto` honored **only under loopback** | `X-Forwarded-Proto` honored **whenever present** (no peer gate) |
| `cfm_chal` cookie `Secure` | one effective scheme | raw `r.TLS != nil` (always `false` here) — inconsistent with `cfm_ok`/clearance |

## 2. The decisive topology fact

The challenge server's broader trust surface was built for the **retired per-IP
"Challenge-DNAT" topology**, where flagged public IPs were DNAT'd straight onto
the daemon's own listener — so the immediate socket peer could be a real public
client, a Cloudflare edge IP, or a private/LAN proxy, and forwarded headers had
to be recovered from those peers.

That path is **gone** (`docs/edge-unification-plan.md` §2/§3.2;
`configs/detectors.conf`): it is retired, self-disabled at startup, nothing
populates its sets, and the daemon TLS listener (9099) is deleted. In the **live**
architecture every request reaches the challenge server the same way:

```
client → [Cloudflare] → host :443 → Edge-DNAT :9043 → OpenResty/Angie
        (realip normalizes; sets X-Real-IP = X-Forwarded-For = CF-Connecting-IP = $remote_addr,
         X-Forwarded-Proto = $scheme)
        → proxy_bind 127.0.0.1 → challenge server 127.0.0.1:9098
```

The cPanel **panel listeners** are the same shape (TLS-terminating edge →
`proxy_bind 127.0.0.1` → 9098, with a fixed per-port `X-Forwarded-Proto`
literal). **The immediate peer is always loopback**, `9098` is externally closed
(audit R06), and there is no TLS listener on the daemon.

**Consequence:** narrowing the challenge server to the apiserver's loopback-only
rule is **behavior-preserving for all live traffic** — because
`X-Real-IP == CF-Connecting-IP == X-Forwarded-For == $remote_addr` and the peer
is loopback, the loopback-only rule resolves the identical client IP and scheme.
The only behavior that changes is the removal of trust for **non-loopback**
peers, which is exactly the latent exposure that would become live when the
handlers are mounted publicly (Step 2).

## 3. What changed

- **New leaf package `internal/reqident`** holds the one identity/scheme rule
  (`FromRequest` → `Peer{ImmediateIP, ClientIP, TrustedProxy, Scheme}`,
  `ClientIPString`, `HasForwardedClientIdentity`). It is a leaf package so both
  `internal/apiserver` and `internal/webdetector` can import it without a cycle
  (apiserver already imports webdetector).
- **apiserver `request_identity.go`** is now a thin wrapper: `requestPeer` calls
  `reqident.FromRequest` and adds the apiserver-specific `Entry` classification
  (6060/6061/edge/other); `realIPFromRequest` calls `reqident.ClientIPString`.
  Behavior is unchanged (`TestRequestPeerEntryTopologies` still passes verbatim).
- **challenge server** `clientIP` and `trustedForwardedProto` now delegate to
  `reqident`. The dead `isTrustedProxyPeer` / `isCloudflareIP` / Cloudflare-CIDR
  table (only reachable via the retired DNAT path) is removed. The inline
  log-only IP copy is folded onto `clientIP` (with a raw-socket fallback so logs
  never blank). The stale "DNAT mode peer is the real public client" comment is
  replaced.
- **Scheme-consistency fix:** the in-progress `cfm_chal` nonce cookie now derives
  `Secure` from the effective scheme (`trustedForwardedProto(r) == "https"`),
  matching the `cfm_ok`/clearance cookies instead of raw `r.TLS` (which is always
  `nil` on the plain-HTTP loopback listener).

## 4. Behavior-preservation & risk

- **Client IP (live):** identical — the edge sets `X-Real-IP = $remote_addr` on
  every challenge/panel location, so the loopback-only rule reads the same value
  the old `CF-Connecting-IP`-first helper did.
- **Scheme (live):** identical — the edge sets `X-Forwarded-Proto` alongside
  `X-Real-IP`; the rule honors it under the loopback hop.
- **Clearance cookies:** clearance is bound to `ip + normalized_host + scope`
  (`docs/security/challenge-scope-mapping.md`). Because the derived IP and scheme
  are unchanged for live traffic, existing clearances are **not** invalidated and
  there is no re-challenge/loop.
- **Fail-closed on malformed forwarded identity (behavior change):** a loopback
  request whose forwarded identity is a comma chain or unparseable now yields
  `ClientIP == nil`, and the challenge handlers already treat that as `400 bad
  client ip`. The **old** `clientIP` fell back to the loopback socket peer
  (`127.0.0.1`) in that case — which then scored/bound the challenge to
  `127.0.0.1` and could even auto-solve via `shouldIgnoreIP(127.0.0.1)`, so the
  new fail-closed path is strictly safer. It cannot trigger on live traffic: the
  edge overwrites `X-Real-IP`/`X-Forwarded-For` with a single `$remote_addr`
  (panel uses fixed literals, never `$proxy_add_x_forwarded_for`), so a
  multi-value forwarded identity never reaches `9098`. A **bare** loopback request
  with no forwarded headers still resolves to `127.0.0.1` (unchanged) — only a
  *present-but-malformed* identity fails closed.
- **Removed non-loopback trust:** a non-loopback peer forging `X-Real-IP` /
  `CF-Connecting-IP` / `X-Forwarded-Proto` is now ignored. Dead for live traffic;
  the point of the change for Step 2.
- **Blast-radius guard (defense-in-depth):** `rlFirewallBlock` now escalates a
  self-protection ban to nft only for a **public** address (`firewallBlockableIP`
  excludes loopback / RFC1918 / IPv6 ULA / link-local / unspecified). This bounds
  the realistic misconfiguration — a non-loopback front-end on a **private**
  address (a LAN load balancer) reaching `9098`, or a fail-closed identity — so
  the ban never lands on the edge, a private LB, or the host. In-memory rate
  limiting still applies; only the firewall escalation is skipped. **Limitation:**
  the guard cannot cover a **public-IP** front-end proxying to `9098`, because a
  public proxy is indistinguishable from a real public client by address alone —
  that topology collapses every client to the proxy IP and one abuser could get
  the proxy nft-banned. That case is out of the model by design (loopback-only,
  `proxy_bind 127.0.0.1`, audited externally-closed by R06); the guard covers the
  accidental private case, and the operational invariant covers the public one.
- **Residual assumption (operator-owned):** every deployment reaches `9098` from
  loopback only. Keep `9098` externally closed (audit R06 regression) and keep
  the edge `proxy_bind 127.0.0.1`. The blast-radius guard above bounds the impact
  if this is ever violated.

## 5. Scope — what this change does NOT do

- It does **not** mount the challenge handlers in the apiserver — that is Step 2,
  and it can now rely on the loopback-only identity/scheme guarantee.
- It does **not** change the edge configs. The challenge locations keep
  `X-Forwarded-Proto $scheme` (web) / fixed literal (panel); that is safe because
  the rule trusts it only across the loopback hop. (Switching the challenge
  locations to the hardened `$cf_xfp`, as the apiserver blocks use, is a separate
  optional follow-up.)
- It does **not** touch host/scope derivation (`trustedForwardedHost`,
  `clearanceScope`) — out of scope for identity/scheme.

## 6. Tests

- `internal/reqident/reqident_test.go` — exhaustive rule coverage (loopback edge,
  direct forged, direct TLS, ambiguous fail-closed, loopback-no-forwarded,
  scheme-only-under-loopback, nil request).
- `internal/apiserver/request_identity_test.go` — unchanged; proves the wrapper
  preserves apiserver behavior including `Entry`.
- `internal/webdetector/challenge_identity_test.go` — pins the challenge-server
  contract: edge → real client, direct forged → ignored, ambiguous → nil, and the
  effective-scheme → `Secure`-flag matrix.
