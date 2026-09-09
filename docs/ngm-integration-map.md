# CFM ⇄ NGM integration — the map (CFM side)

> Status: **mapping / discovery, no code yet.** This is the survey we do *before*
> deciding what to build. Its sibling on the NGM side is
> `ngm/docs/cfm-integration-map.md` (the driver/surface view); read them together.
>
> The anchor on the NGM side is the ROADMAP item **"CFM security-suite
> integration"** (ngm `ROADMAP.md`, the "Next" block): *NGM drives CFM from
> records and surfaces it — never reimplements its Lua.* This doc is the CFM-side
> answer to "what would CFM have to grow to accept NGM as a first-class panel,
> the way it already accepts cPanel?"

NGM is a Go hosting control panel (nginx vhosts, PHP-FPM multi-version, MariaDB,
BIND, per-customer systemd slices, and a built-in **Postfix + Dovecot + rspamd**
mail stack). It is *not* cPanel: no `/var/cpanel`, no PHP CGI plugin runtime, no
Exim. It is another Go daemon on the same box.

---

## 0. TL;DR — the shape of the work

CFM's **plumbing is already ~90% panel-neutral**; what is hard-wired to cPanel is
the thin **identity + metadata layer**. Adding NGM is mostly *generalising three
cPanel-specific seams* and *filling two detector gaps*, not new subsystems.

| CFM surface | State today | NGM work |
|---|---|---|
| Scoped-token store + `/api/v1/auth/token` | **generic** (viewer role, vhost/db scope, fail-closed) | reuse as-is |
| Embed code→bootstrap + postMessage/iframe transport | **generic** (`internal/apiserver/embed_bootstrap.go`, plugin `templates/index.php`) | reuse; NGM hosts its own iframe page |
| `/cfm-admin` UI + scoped nav filtering | **generic** (`internal/webui/`, `ui-scope.js`, ctx scope keys) | reuse as-is |
| `panelauth` broker identity/validation | **cPanel-baked** (`panel=="cpanel"`, cpsess/session-file, aud/HKDF `cfm-plugin-cpanel*`) | **provider interface** (§A) |
| Account metadata (vhosts/db) source | **cPanel-baked** (`/api/v1/cpanel/user-info` reads `/var/cpanel/…`) | **NGM metadata source** (§B) |
| Detectors framework | **generic** (`registry.go`, `Factory`, `detectors.conf`, `meta`) | add `ngm` detector; rspamd + php-fpm gaps (§D) |
| DNAT panel scope/chain/lua | **mostly generic** (`ScopeCPanel`, `cfm_panel_redirect`, `cfm_panel.lua`) | `panel` alias + parameterise port map (§C) |
| Edge origin contract | **shipped for nginx** (`configs/nginx-cfm.conf`) | NGM must render the realip+TSV snippet (§G) |
| sslcollector cert discovery | **panel scanners** (LE/cPanel/DA/Virtualmin/mailcow) | add `scanNGM(~/sites/…)` **or** NGM stays TLS front door (§E) |
| cfm-lsm path protection | **watched-UID, monitor-only for added paths** | add NGM paths as `persistence_path` — OBSERVE, not tamper-proof (§F) |

The recurring theme: **`panel == "cpanel"` string checks + `/var/cpanel` readers +
`cfm-plugin-cpanel` audience** are the only genuinely cPanel-shaped things. The
token mint, transport, UI, scope enforcement and DNAT chain are already generic.

Two facts that make this cheaper than it looks:

- **The two codebases already share a log-format lineage.** ngm's
  `internal/traffic/parse.go` is a hand-copy of *this repo's*
  `internal/webdetector/log_format_adapter.go` ("same author, same log sources"),
  and ngm's `internal/web/authfilelog.go` writes `/var/log/ngm/auth.log`
  *expressly* "for an external detector in the fail2ban family (CFM's
  ssh/postfix/ftp detectors)". The detector inputs were designed for us.
- **CFM already speaks NGM's mail + DB stack.** Native `postfix_*` detectors and
  MariaDB-aware `mysql` paths already exist. There is **no Exim mismatch** — the
  `exim_*` sections self-disable on an NGM box.

---

## 1. Reference pattern — the cPanel plugin (what we are generalising *from*)

`plugins/cfm-plugin-cpanel/` is the worked example. It is a PHP CGI that mints an
auth assertion, exchanges it for a **scoped viewer token**, and frames the real
`/cfm-admin/` in an iframe with a postMessage/ACK token handoff. Nothing about the
CFM-side *endpoints* it calls is cPanel-specific; the cPanel-ness is entirely in
(a) how it proves who the user is and (b) where it reads the user's domains.

Split, concretely:

- **Reusable for NGM as-is:** the embed code→bootstrap exchange
  (`GET /api/v1/embed/code` → `/cfm-admin/api/v1/embed/bootstrap?code=…`), the
  postMessage/`cfmTokenAck` transport with `cfmExpectedOrigin` (see
  `docs/cpanel-plugin-token-transport.md`), the scoped-token store
  (`internal/apiserver/token_store.go`), and the whole `/cfm-admin` UI incl.
  scoped nav filtering (`internal/webui/static/assets/shared/ui-scope.js`, ctx
  scope keys in `embed_bootstrap.go`).
- **cPanel-specific, must be replaced for NGM:** the PHP CGI shell +
  AppConfig/Jupiter install (NGM builds its own menu + iframe host — see the NGM
  doc), the identity proof (cPanel session file), and the metadata source
  (`/var/cpanel/…`).

---

## 2. panelauth — introduce a provider interface (§A)

`internal/panelauth/` is a Unix-socket broker (`/var/run/cfm-auth.sock`,
`POST /auth/issue`) that today is a single concrete cPanel implementation. There
is **no provider abstraction** yet. The cPanel-shaped pieces are:

- `validateCpanelRequest` — rejects unless `Panel == "cpanel"`; validates the
  `cpsess` token shape and scans `/var/cpanel/sessions/{cache,raw}` for a session
  file proving the user.
- The assertion audience `cfm-plugin-cpanel` and the HKDF salt/info strings
  (`secret_derivation.go`), pinned again on the API side by
  `pluginAssertionAudienceOK`.
- `mintScopedViewerToken` fetches domains via `/api/v1/cpanel/user-info` and
  labels the token `cpanel:<user>`.

**Everything downstream of identity is already generic:** the scoped-token mint
(`/api/v1/auth/token`, `role:"viewer"`, `vhosts`/`db_users`/`databases`, TTL,
fail-closed on empty scope) needs no change.

**Proposed generalisation.** Introduce a small provider interface, e.g.:

```go
type PanelProvider interface {
    Name() string                                   // "cpanel" | "ngm"
    ValidateRequest(r issueReq) (user string, err error)
    FetchUserInfo(user, assertion string) (UserInfo, error) // vhosts/db_users/databases
    AssertionAudience() string                      // per-panel aud + HKDF namespace
    TokenLabel(user string) string                  // "ngm:<user>"
}
```

Keep the mint + transport shared; register `cpanel` and `ngm` providers. The
`ngm` provider's identity proof is an **NGM-issued session/handshake token** (NGM
is a Go daemon — it can present a signed nonce over the broker socket, or CFM can
verify against an NGM endpoint) instead of a cPanel session file.

> **Shortcut to weigh (has a sharp edge):** because NGM is itself privileged on
> the box, NGM *could* call `/api/v1/auth/token` directly with CFM's admin
> `AUTH_TOKEN` and mint the scoped token itself, skipping the broker. That
> crosses the **scoped/admin boundary** (CLAUDE.md §5, §6) — NGM would hold an
> admin credential. Prefer the provider interface unless we deliberately accept
> NGM-as-trusted-admin-minter with the token kept server-side and never exposed
> to the browser. Decision belongs to the operator.

## 3. The NGM metadata source (§B)

`mintScopedViewerToken` needs vhosts/db-users/databases for the user. cPanel reads
`/var/cpanel`; the NGM equivalent is **NGM's own store** (`store.Site` rows keyed
by `UserID`, plus the `<user>_` DB namespace). Two ways to source it:

1. **NGM exposes a read endpoint** (`GET /api/v1/ngm/user-info?user=`) that the
   `ngm` provider calls — mirrors `/api/v1/cpanel/user-info`. Cleanest; NGM owns
   its own truth.
2. **CFM reads NGM's SQLite** directly (`/var/lib/ngm/ngm.db`) — rejected:
   couples CFM to NGM's schema, violates "boring, decoupled" on both sides.

Go with (1). The vhost list = the customer's domains; the DB scope = databases
under the `<user>_` prefix.

## 4. DNAT — the `panel` alias + parameterised port map (§C)

`cfm dnat cpanel on/off` is already **panel-neutral underneath**: the nft table is
`inet cfm_panel_redirect`, the Lua guard `cfm_panel.lua`, the edge var
`$cfm_panel_challenge_mode`, the scope enum `ScopeCPanel`. Only three things still
say "cpanel":

- the **command word** `cpanel` (routed in `internal/dnat/cli.go`) — add `panel`
  as an accepted alias;
- the **port-mapping set** `firewall.PanelDNATMappings()` (2082→12082 … 2222→12222)
  — these are cPanel/WHM/Webmail ports. NGM's panel port is different (default
  `9601`; see the NGM doc). Parameterise the mapping per panel rather than the
  fixed cPanel list;
- the nft comment literal `cfm_cpanel_dnat:` and the **Imunify/xfer heuristics** —
  drop or generalise.

The NGM side wants `cfm dnat panel on/off` to mean "put NGM's panel port behind
CFM's challenge/WAF guard". Feasible now with the alias + an NGM port entry.

> The alias is worth shipping **independently** of the rest: it is small, low
> risk, and correct for cPanel *and* DirectAdmin today (the doc string on
> `panel_dnat.go` already says "cPanel/DirectAdmin"). It is the natural first
> merge.

## 5. Detectors — add `ngm`, note the real gaps (§D)

The detector framework (`internal/detectors/registry.go`, `Factory`,
`configs/detectors.conf` sections, `meta.Register`) is **fully panel-agnostic**.
A new detector is: an impl of `core.PeriodicDetector`, an `ngm_register.go`
`init()`, and an `[ngm]` reference section. No framework change.

What NGM already gives us for free (its outputs were built for CFM):

- **Panel auth abuse** → `/var/log/ngm/auth.log`, single-line `event=FAIL user=…
  ip=… role=… reason=…`. This is the cleanest new detector input on the box —
  an `ngm_auth` detector modelled on `cpanel/login.go` (per-ip / per-user /
  per-admin authfail thresholds → `NGM/AUTHFAIL`, `NGM/ADMIN`).
- **Web attacks** → per-vhost `~/<user>/sites/<domain>/logs/access.log` in the
  `ngm_access` format — which our own `log_format_adapter.go` already parses (ngm
  copied it). The edge webdetector sees this automatically once CFM fronts nginx
  (§G); a file-tail detector is the CFM-absent fallback.
- **Mail auth abuse** → native `postfix_*` + `dovecot` detectors already work,
  *provided* NGM's Dovecot/Postfix log syslog-framed to `maillog`/`mail.log` or
  journald. MariaDB → `mysql` detector works unchanged (paths already probed).

Genuine gaps (net-new if we want them):

- **rspamd** — no detector anywhere. rspamd's spam/greylist/auth signal
  (`/var/log/rspamd/rspamd.log`) is invisible to CFM today. Note NGM already
  *meters* outbound abuse itself (`internal/mailmeter`) and does outbound
  submission rate-limiting in rspamd — so CFM's added value here is **IP-level
  banning of SMTP/IMAP brute-forcers**, which NGM does not do, not re-metering.
- **PHP-FPM** — no detector for FPM slow-log / worker abuse (CFM covers PHP at
  the edge WAF, not the FPM log). NGM writes per-site
  `logs/php-fpm.{slow,error}.log`.

## 6. sslcollector — mostly a non-problem: NGM already uses the LE `live/` layout (§E)

**Correction to the first-pass assumption.** NGM does *not* keep per-vhost certs
under `~/sites/<domain>/` (that is the webroot). Its real certs live at
`certs.letsencrypt_live`, which **defaults to `/etc/letsencrypt/live`**
(ngm `internal/config/config.go`), in the standard certbot layout
`<live>/<domain>/{fullchain,privkey}.pem` — NGM even maintains a `/live/<domain>`
alias there (`internal/certs/certbot.go`). CFM's `discoverPairs()` already runs
`scanLetsEncrypt("/etc/letsencrypt/live")` (`internal/sslcollector/sources.go`),
and `scanLetsEncrypt(liveDir)` reads exactly `<dir>/<name>/fullchain.pem` +
`privkey.pem`. So **on a default NGM box, sslcollector discovers every real NGM
cert with zero code changes** — the "για αρχή" answer.

The self-signed fallback (`<nginx.root>/conf/selfsigned/<domain>/…`, materialised
by NGM when no LE cert exists) is deliberately **not** discovered, and that is
correct: the edge must not serve a self-signed cert to real clients (CFM's
ranking deprioritises self-signed anyway). A domain that only has NGM's
self-signed cert is an SNI-miss at the edge until it gets a real cert — note it,
don't "fix" it by scanning the selfsigned dir.

So the only real work is the **non-default path** case:

- If the operator set a **custom** `certs.letsencrypt_live` (≠ `/etc/letsencrypt/live`),
  CFM's hardcoded call misses it. Smallest fix: `scanLetsEncrypt` is already
  path-parameterised, so add one `out = append(out, scanLetsEncrypt(ngmLiveDir)…)`
  in `discoverPairs()` reading the NGM-configured dir (a small `[sslcollector]`
  extra-dir list, or an `ngmLiveDir()` probe of `/etc/ngm/config.yaml`). Or simply
  keep NGM on the default. A dedicated `scanNGM` source const is **not** needed —
  the certs are already LE-shaped; `SrcLetsEncrypt` + `prefer()` rank apply as-is.

This still only matters **iff** CFM's edge terminates client TLS — the **hard
either/or** that remains the real topology decision:

- **Edge-in-front (CFM terminates TLS):** relies on the discovery above; NGM must
  **stop owning external 443** (DNAT hands it to the edge; NGM's nginx keeps
  binding real-IP 443 as origin) and hand over `443 quic reuseport`. Additionally
  NGM logs raw `$remote_addr` with **no inbound `real_ip`**, so it must render
  `set_real_ip_from`/`real_ip_header` (§G) or every per-vhost log line and
  `limit_req` key sees the proxy IP. **OR**
- **NGM stays the front door (NGM terminates TLS):** CFM does not need NGM certs
  at all; the edge WAF/challenge for web is out of scope, and CFM contributes
  detectors + firewall + LSM only. `cfm dnat panel` (panel port) still applies.

See the NGM doc §C for the topology decision.

## 7. cfm-lsm — NGM paths as FS-005, honestly (§F)

The ask "protect our own binaries" maps to LSM policy **CFML-FS-005**
(sensitive-file write), the only path-declaration mechanism (`internal/lsm/`,
`configs/lsm.conf`, `persistence_path = <abs path>`). Honest limits before anyone
markets this as tamper-proofing:

- **Watched-UID gated.** FS-005 fires only when the *writer* is a web-class /
  watched UID. It catches a **compromised PHP/nginx worker or vhost user** writing
  to `/usr/bin/ngm` or `/etc/ngm/…` — genuinely useful — but **not** an
  already-root attacker or a non-watched service account.
- **Added paths are monitor-only even in `enforce`.** Only the ~5 hard-coded core
  paths (`/etc/passwd`, shadow, sudoers…) can be `enforce`-denied. NGM paths get
  **alert + `/proc`/SHA-256 enrichment + binary capture**, never a block.
- It is a behavioural IDS, not an immutability guard — there is no "make this
  inode append-only" primitive.

**Net:** wire the NGM targets as `persistence_path` for monitor-mode detection —
binary (`/usr/bin/ngm` or `/opt/ngm/bin/ngm`), DB `/var/lib/ngm/ngm.db`, config
`/etc/ngm/config.yaml`, rendered artifacts (`<nginx.root>/conf/sites/`,
`/etc/systemd/system/ngm-*`, `/etc/rspamd/local.d/`). Budget a **tuning pass**:
NGM's own root daemon legitimately writes its config and execs
`systemctl`/`useradd`/`certbot`/`postfix`/`nginx` — allowlist NGM's control-plane
`comm`/paths (note `allow_comm` is monitor-only/spoofable) or it self-trips.

The more ambitious "one step further" for PHP is **`cfm-php`** (`docs/cfm-php.md`,
idea-stage): a Zend extension intercepting dangerous PHP calls on **non-Imunify
hosts** — and it *names NGM-shaped hosts as targets*. That is the real "protect the
customer PHP layer" story; LSM only sees the kernel-visible consequences after a
process spawns. Keep them as the two-layer pair the doc already describes.

## 8. kernsec — orthogonal, coordinate sysctl ownership (§H)

`internal/kernsec/` is host-level KSPP hardening (sysctls, boot args, modules,
mount audit), **not panel-aware** and correctly so. The only NGM interaction is
**double-ownership of sysctls**: if NGM's own `HARDEN.md` writes sysctl drop-ins,
kernsec's declarative `apply` will reconcile/fight them (`foreignReconcileKeys`).
Two concrete watch-points: (a) NGM uses containers (podman) — verify kernsec's
container probe fires so the tier-2 `user.max_user_namespaces=0` rules auto-skip;
(b) `fs.protected_regular` is deliberately held at `1` for panel compatibility.
Coordinate, don't merge — this is a settings-conflict review, not a build.

---

## 9. Edge origin contract for NGM (§G)

CFM's edge sits **in front of** an origin web server via port-only, IP-preserving
DNAT (80→9080, 443→9043), decides allow/challenge/block in `cfm.lua`, then
re-proxies to the origin on the box's real IP. CFM already ships the exact nginx
drop-in an origin needs: `configs/nginx-cfm.conf` (realip trust for loopback + the
12-column TSV access log the webdetector ingests over `/run/cfm/ingest.sock`).

For NGM the twist is that NGM **renders its nginx from records** and must never be
hand-edited. So the realip + TSV snippet has to be injected into **NGM's template
system** (its master conf / per-vhost include), not dropped into
`/etc/nginx/conf.d/` by hand — else NGM's next apply overwrites it. That injection
is NGM-side work (NGM doc §C); the *contract* CFM requires is exactly
`nginx-cfm.conf`. Port ownership must be arbitrated: NGM must not try to own
external 80/443 when the edge is in front.

---

## 10. Suggested sequencing (CFM side)

Independent, mergeable slices, smallest/lowest-risk first — matched to the NGM
ROADMAP phases (`light → repo → mail AV → abuse controls`):

1. **`cfm dnat panel` alias** (§C, port-map parameterised) — tiny, correct for
   cPanel+DA today, unblocks the NGM panel-port case. *Ship first.*
2. **`ngm_auth` detector** (§D) — reads the auth.log NGM already writes for us.
   Pure add, no framework change, immediate value ("abuse controls" phase, CFM
   absent-or-present).
3. **panelauth provider interface + NGM metadata source** (§A, §B) — the embed
   story; enables the scoped `/cfm-admin` page NGM wants. Medium; touches the most
   historically painful area (CLAUDE.md §6) so it gets the adversarial review.
4. **Edge origin + `scanNGM`** (§E, §G) — only if the operator chooses
   edge-in-front. Larger; gated on the TLS-termination decision.
5. **LSM FS-005 NGM paths** (§F) — monitor-only, needs a tuning pass; ship after a
   burn-in on a real NGM box.
6. **rspamd / php-fpm detectors** (§D) — net-new, optional; do when the mail-AV
   phase lands.

Every runtime slice above is a CFM PR under the repo's normal rules (feature
branch, CHANGELOG `[Unreleased]`, adversarial self-review, the CI gates in
CLAUDE.md §3). This doc is docs-only.

---

## 11. Open decisions for the operator

1. **TLS termination:** edge-in-front (CFM terminates, needs `scanNGM` + NGM
   realip render) **or** NGM stays front door (CFM = detectors + firewall + LSM,
   no edge WAF for web)? Everything in §6/§9 hangs on this.
2. **Scoped-token minting:** provider interface (broker stays authoritative) **or**
   NGM-as-admin-minter shortcut (simpler, crosses the scoped/admin boundary)?
3. **How far to go:** the "basics" (detect + surface + auth detector + panel-port
   DNAT) vs the full embed + edge WAF + LSM + eventual `cfm-php`. The ROADMAP's
   own answer is phased; this doc lets us pick the cut line per phase.

> See also: `docs/ngm-auth-detector.md` (first-slice detector sketch),
> `ngm/docs/cfm-embed-handshake.md` (first-slice embed-handshake sketch),
> `ngm/docs/cfm-integration-map.md` (NGM-side driver/surface view),
> `docs/cpanel-plugin-token-transport.md`, `docs/webui-api-curl-recipes.md`,
> `docs/ssl-collector.md`, `docs/cfm-lsm.md`, `docs/cfm-php.md`,
> `docs/dnat-bypass.md`.
