# CLAUDE.md

Guidance for AI agents (and humans) working in this repository. Keep it
current: when a build step, guardrail, or hard-won lesson changes, update
the relevant section here so we don't relearn it the hard way.

---

## 1. What CFM is

CFM (Configurable Firewall Manager) is a **single Go daemon** providing
defence-in-depth across five layers, from the HTTP edge down to the kernel:

| Layer | What it does | Code |
|---|---|---|
| **Challenge engine** | interactive proof-of-work / JS challenge | `internal/webdetector`, `configs/lua/cfm_clearance.lua` |
| **WAF** | OWASP-inspired request filtering, in-path via edge proxy | `configs/lua/cfm_waf.lua`, `internal/webdetector` |
| **Web detector** | log-driven L7 behavioural scoring → block/challenge | `internal/webdetector`, `internal/detectors` |
| **nftables firewall** | L3/L4 enforcement, autoblock, rate/conn limits | `internal/firewall` (`nft/` exec + `nftlib/` netlink) |
| **cfm-lsm** | CO-RE BPF LSM behavioural detection at syscall boundary | `internal/lsm` |
| **kernsec** | KSPP-grade kernel-surface hardening (sysctls, boot args, modules) | `internal/kernsec` |

The in-path edge proxy is **OpenResty** (default) or **Angie**; the daemon,
Lua decision files, and sslcollector socket are identical for both.
**cfm-edge** (`chrismfz/cfm-edge`: nginx.org nginx + the OpenResty Lua set,
`/usr/sbin/cfm-edge`, `/etc/cfm-edge`, `/var/log/cfm-edge`) is the third
engine the daemon knows, being adopted; it runs the same shared Lua (its
conf comes with its install script).

`README.md` is the short overview (install, config files, feature tour with
links); the reference for each subsystem is its doc under `docs/` (§7).

---

## 2. Build / test / run

```bash
make setup          # first-time: go mod tidy
make build          # builds ./bin/cfm  (runs verify-bpf-bindings first)
make run            # build + run
make lua            # syntax-check configs/lua/*.lua
make test-lua       # Lua unit tests under scripts/tests/*_test.lua
make test-js        # cfm-admin JS unit tests (node --test; e.g. webdet/rules-model.test.js mirrors traffic_rules.go)
make release        # bpf + deb + rpm (contributors; needs clang + libbpf-dev for `bpf`)
```

There is no monolithic `make test`. Run the Go suite directly:

```bash
go test -race ./...
```

### Firewall engines and nft rules

The history behind each rule below is in the code comments it names.

- **Engine selection.** The `CFM_FIREWALL_ENGINE` line in `cfm.conf`
  (`FIREWALL_ENGINE` sets the same field; the later line wins), overridden by
  the `CFM_FIREWALL_ENGINE` env var: `nft` (default, exec-based) or `nftlib`
  (netlink, zero-fork set/feed writes). The daemon AND the one-shot CLI resolve
  it the same way (`cmd/cfm/engine.go`). Set it in `cfm.conf`, never via
  `systemctl set-environment`: the CLI can't see a daemon-only env var (an
  nftlib node's `cfm dnat on` once ran the exec backend, and the daemon then
  duplicated its untagged redirect).
- **nftlib must never read `inet cfm input` over netlink.** google/nftables
  v0.3.0 fails the whole dump on the `ct original …` match every DNAT accept
  carries, so those accepts are nft text on both backends (the cPanel ones in
  one shared implementation, `internal/firewall/panel_dnat_accepts.go`).
- **The ports policy is ONE `nft -f` transaction** (TCP_IN/UDP_IN/TCP_OUT/
  UDP_OUT, debug ports, portscan tracking, the output loopback accept), planned
  by `firewall.PortsPolicyScript` for both engines; the separate runs it
  replaced left the input chain without a default drop on every apply. Don't
  add a ports-policy rule or set write outside that planner, and match rules by
  their exact printed key, never by substring: nft prints `timeout 60s` as
  `1m` (`NFTDuration`), and `"%ds"` re-added the portscan rules on every apply.
- **DNAT accepts in that chain: keep what is in place, insert before delete,
  a delete is best effort** (`EnsurePanelDNATAccepts`; `EnsureInputAccepts`
  for the web ones, which also keeps the old-port accepts until DNATOn has
  moved the redirect). A reload must not change a handle: delete-and-re-add on
  every reload dropped DNAT'd connections, and the live test pins it.
- **TTL bans live only in nft** (timed elements of `block_v4`/`block_v6`, and
  `block_v6_clients` for an IPv6 client's automatic /64 ban;
  `cfm.deny` is permanent-only and must never take one). Nothing on a restart
  or upgrade may empty the `inet cfm` table (an rpm `%post` `cfm disable` once
  freed every TTL-banned attacker). For what still does (reboot, `cfm reset`,
  `cfm disable`), `internal/ttlban` persists them to
  `/var/lib/cfm/ttlbans.json` and restores them after EnsureBase. A new unblock
  path (not an allow: the block element stays under an allow) calls
  `ttlban.Forget` next to `edgeban.Unban`, or a restart resurrects the ban.
  `cfm flush` is the intended clear. Details (the lost-bans heuristic, the
  `.flushed` marker): `docs/DETECTORS.md` "TTL bans across a restart".
- **A feed set is replaced in ONE transaction** (`ReplaceSetFlushAdd`, both
  engines: one `nft -f` script / one netlink batch holding the flush and every
  add); as a flush plus batches, the unions the base rules drop on
  (`block_ext_v4_hosts`, …) sat empty, then partial, on every hourly apply.
  Don't split a replace into transactions again: nftlib's `setWriteChunk` is
  about messages, not transactions. The batched write is only the logged
  fallback for a batch too large for the socket buffer (plus the engine cases
  named at `ReplaceSetFlushAdd` in `nft/nft.go` and `nftlib/bulk.go`); any other
  refusal keeps the old content. Skip-if-unchanged also asks the kernel for one
  element (`internal/firewall/setprobe`), because the CLI can empty the table
  behind the daemon's back; the same probe answers IP lookups
  (`setprobe.Lookup`, via `ipquery.FindMany`), and an interval-boundary answer
  the 4.18 kernel can get wrong is reported as ambiguous (the caller dumps).
- **A base input rule added after the rest needs an anchor.** Both engines'
  EnsureBase insert a missing early rule at position 0 and append a missing
  late one: on a node's existing chain a new drop would land above the self /
  allow accepts (or below the ports policy's accepts). List it in
  `firewall.BaseRuleAnchors` (rule + the rule it follows): a missing one is
  then added right after its anchor (`add rule … position <handle>`), and the
  live `LiveNFTClientSlash64` test pins the upgrade case.
- **A change here gets a live run in an isolated netns** (the fleet's kernels,
  4.18 and 5.14, are older than a dev box's):
  `unshare -rn env CFM_NFT_INTEGRATION=1 go test -p 1 ./internal/firewall/... -run 'LiveNFT|ApplyPortsPolicyIsAtomic'`;
  TTL bans `-run LiveNFTTTLBans` (both engines); feed replace
  `-run LiveNFTFeedReplace` (both engines) as real root in a netns
  (`unshare -n`), because under `unshare -r` the socket buffer is capped at
  `wmem_max`.

---

## 3. CI gates — these MUST pass before pushing

CI (`.github/workflows/security.yml`) is the source of truth. Mirror it
locally before you push; a green diff that fails one of these wastes a round-trip:

```bash
go vet ./...
go build ./...
./scripts/tests/check_test_isolation.sh arm      # record CFM's system dirs before the Go tests (see §5)
go test -race ./...
./scripts/tests/check_test_isolation.sh verify   # fail if the Go tests wrote any of them
make lua
make test-lua
make test-js                                     # node --test on internal/webui/static/assets/**/*.test.{js,cjs}
./scripts/tests/check_cli_transport.sh          # CLI transport guardrail (see §5; needs ripgrep)
./scripts/tests/check_cfm_clearance_require.sh   # Lua clearance module load check
./scripts/tests/check_bypass_list.sh             # challenge_waf_bypass.conf + trusted_proxies.conf bounds + generator tests
./scripts/tests/check_logrotate_coverage.sh      # every CFM log path is rotated (see §5)
./scripts/tests/check_origin_ka_config.sh        # origin-keepalive 443 SNI-safety: keepalive 0 (OpenResty) + proxy_ssl_session_reuse off
./scripts/tests/check_shared_lua_layout.sh       # installer CFM_LUA_MANIFEST == configs/lua/*.lua (see §5)
./scripts/tests/check_cfm_edge_conf.sh           # configs/cfm-edge.conf == a fresh render of openresty.conf (make cfm-edge-conf)
./scripts/tests/check_package_lua_delivery.sh    # Lua ships ONLY as /var/lib/cfm/lua/*, package-owned (see §5)
./scripts/tests/check_package_proxy_config_deploy.sh # upgrade tests new edge sidecars staged (-T, real nginx); a failed run leaves the live dir untouched
./scripts/tests/check_edge_listen_v6.sh          # edge IPv6 listen: script <-> conf ports/glob includes, default (script = Go) + EDGE_LISTEN_V6, the decision, deploy hook
./scripts/tests/check_rpm_spec_macros.sh         # no unescaped %macro in rpm spec comments + build-dated top %changelog entry (see §5)
./scripts/tests/check_site_cache_config.sh       # Site Cache bypass-by-default: every proxy_cache location gated on $cfm_cache_skip (see §6)
./scripts/tests/stamp_changelog_test.sh          # CHANGELOG date-stamper (make release) regression test
./scripts/tests/release_notes_test.sh            # release-notes extractor (make release) regression test
./scripts/tests/check_preflight_parity.sh        # this block + /preflight list == what security.yml runs
./scripts/tests/check_changelog_entry.sh         # CHANGELOG structure (locally); per-PR "code changed → needs entry" runs in CI
```

The per-PR gate is `security.yml`'s **build-test** job (the block above) plus a
tiny **changelog** job: it asserts `CHANGELOG.md` keeps a single,
correctly-placed `## [Unreleased]` heading (the date-stamper's invariant) and
fails a PR that changes runtime code without an `[Unreleased]` entry (escape
hatches: `[skip changelog]` in the PR title/body, or a `no-changelog` label;
docs/tests/CI-only PRs are exempt). **CodeQL + govulncheck** are advisory and
run weekly + on manual dispatch (`codeql.yml`, "Weekly Security Scans"), not
per PR: dispatch one before a release or after a risky merge, and treat its
alerts as real (it caught a reflected XSS on the challenge page). gosec and
Semgrep were dropped (CodeQL covers the same ground).

---

## 4. Repository map

```
cmd/cfm/            # binary entrypoint (main.go) + auth CLI
internal/           # all daemon logic, one package per concern:
  firewall/         #   nft/ (exec) · nftlib/ (netlink) · autoblock/ · selfip/
  webdetector/      #   L7 detection, challenge, WAF wiring, history
  detectors/        #   ssh/exim/dovecot/ftp/mysql/cpanel/modsec/health/...
  lsm/              #   cfm-lsm BPF LSM subsystem
  kernsec/          #   kernel hardening (KSPP sysctls, modules, boot args)
  apiserver/        #   HTTP API server
  webui/            #   embedded /cfm-admin UI (embed.go + static/)
  panelauth/        #   cPanel/WHM auth broker (scoped tokens) — see §6
  authstore/        #   auth/session/token storage
  clihttp/          #   the ONLY sanctioned HTTP transport for CLI runtime (§5)
  config/ detectorscfg/ ...  # config parsing
  sslcollector/     #   cert discovery + unix-socket API for the edge proxy
  ... (~45 packages total; `ls internal/` for the full list)
configs/            # REFERENCE configs (packaged to /usr/share/cfm/configs/)
  lua/              #   in-path Lua: cfm_clearance, cfm_waf, cfm_rules, cfm_panel, ...
  openresty.conf / angie.conf
plugins/cfm-plugin-cpanel/   # cPanel plugin (install/uninstall, templates, lib)
packaging/          # debian/ + rpm/ build assets
docs/               # design docs, runbooks, checklists (see §7)
scripts/tests/      # CI guardrail scripts + Lua tests
```

Config model: **reference** configs ship under `configs/` →
`/usr/share/cfm/configs/`; **live** configs are edited under `/etc/cfm/`.
Runtime/generated artifacts (incl. rendered Lua) live under `/var/lib/cfm/`.

---

## 5. Conventions & guardrails (enforced)

- **CLI HTTP goes through `internal/clihttp`.** Direct `net/http` calls in
  CLI runtime code are rejected by `check_cli_transport.sh`. The only escape
  is an inline `clihttp-exception: <reason>` comment on the same line — use
  it sparingly and justify it.
- **Lua validation gate before reloading the edge proxy.** Any change to
  `configs/lua/*` must pass `luac -p` and a LuaJIT `require` smoke-test of all
  modules. Follow `docs/challenge-waf-release-checklist.md` to the letter —
  shipping a Lua file that fails to load takes the WAF/challenge layer down.
- **Generated Lua token files have enforced ownership/mode** (`root:cfm`,
  `0640`). Don't loosen this; post-deploy checks assert it.
- **Scoped vs admin auth is a hard security boundary** (cPanel users get
  scoped viewer tokens, never admin tokens). Validators live centrally;
  out-of-scope access must fail-closed (403). See §6.
- **Code is the source of truth — keep doc-comments and docs in sync.** Stale
  scope docs/comments misled a scope audit more than once. When you change an
  endpoint's auth/scope (or any behaviour a comment/doc describes), update the
  handler doc-comment **and** `docs/endpoint_scope_inventory.md` **in the same
  change**, delete "for now / TODO" guard comments once the work lands, and
  never keep a second copy of a list/matcher that can drift. When a comment
  and the code disagree, trust the code and fix the comment.
- **Edge-engine facts live in ONE table: `edgeengine.Profiles`**
  (`internal/edgeengine/profiles.go`): unit, binaries, commands, conf/log
  dirs, the config-path marker (`PathMarker`, which attributes a listener
  config path to an engine and is wider than `ConfDir` for OpenResty), the
  legacy Lua token dir, config hooks and process aliases. Before
  it, a dozen packages each carried their own `{"angie", "openresty"}` list
  and paths. A caller derives what it needs: `Names()`, `Lookup`/`IsEdge`,
  `Units()`, `LuaTokenCandidates()`, `ConfFileCandidates`,
  `LogFileCandidates`. Never write a new literal edge list. Adding an engine
  means one Profile plus its place in `fileOrder`. `Profiles` is the
  detection order (Angie first); `fileOrder` is the precedence of
  first-readable-file lists (OpenResty first). cfm-edge is LAST in both, so a
  node without it keeps every old list plus a trailing entry; its
  `LegacyLuaDir` is empty (it never had one). Code that counted engines must
  count with `> 1`, not `== 2` (with `== 2`, three active edges fell through
  the dnat resolver's ambiguity check). Both orders are pinned, by
  `profiles_test.go` and by a parity test next to each converted caller.
  `Lookup`/`IsEdge` are exact on the canonical name, like the checks they
  replaced, so a caller that needs leniency normalises first. Still
  engine-specific on purpose:
  - the process-title parsing in `healthmodel`;
  - the `debug_capture` master heuristics;
  - Angie's native-keepalive exception in `edge_health` (cfm-edge reports
    nginx's own version, so it takes the nginx path);
  - `status`'s per-engine output fields.

  Two security allowlists are OpenResty-only today and are decided per
  engine, never derived:
  - agent file sync's `syncAllowedPrefixes`;
  - the bridge's `nginxUploadAllowedDirs`.

  A new engine must decide each of them explicitly. cfm-edge: neither (the
  decision is recorded next to each list).
- **A new log file needs a rotation entry in the same change.**
  `check_logrotate_coverage.sh` fails CI if a path CFM writes (edge
  `access_log`/`error_log`, a `*_LOG_FILE` key in `cfm.conf`, a
  `/var/log/cfm/…` literal in Go) is neither matched by `configs/logrotate-cfm`
  nor in a directory documented as vendor-rotated. Never list a path a
  distro/panel logrotate config already globs (`/var/log/{angie,nginx,apache2,
  httpd}/`, `/usr/local/apache/logs/`) or the cfm-edge package rotates
  (`/var/log/cfm-edge/`; CFM's hourly pass runs its config too): a second
  declaration is a `duplicate log entry` error that aborts the run. Prefer the existing directory glob over
  a filename (enumerated lists drifted). The OpenResty logs under `/usr/local`
  also need the `logrotate.service.d/cfm-openresty.conf` drop-in
  (`ProtectSystem=full`). `--host` checks a live server; details in
  `docs/log-rotation.md`. Every `logrotate-cfm` block sets `dateext` +
  `dateformat -%Y%m%d-%H%M%S` itself, never globally (the hourly pass runs it
  without `/etc/logrotate.conf`, alongside cfm-edge's file in one invocation);
  the same check pins it.
- **Lua has exactly ONE delivery path: `/var/lib/cfm/lua/`, owned by the
  package.** The Makefile stages `configs/lua/` there with `rsync --delete`
  (that flag, not a PKGROOT wipe, is what drops a retired module —
  `stage-pkgroot`, which the rpm path uses, never wipes), the rpm `%install`
  copies `/var` from that staged tree, and `%files` owns each file, so an
  upgrade installs, refreshes and REMOVES modules. Never add a second copy or a
  second copier: an unfiltered copy into `/usr/share/cfm/configs/` plus a
  postinst loop once overwrote the freshly installed modules.
  `check_package_lua_delivery.sh` pins it. A hand-edit under
  `/var/lib/cfm/lua/` is overwritten on upgrade with no backup; the operator
  edit surface is `/etc/cfm/*`.
- **Never write a bare `%macro` in an rpm spec COMMENT — escape it `%%`.** On
  EL, `/usr/lib/rpm/redhat/macros` makes rpm expand macros inside comments, so
  a comment mentioning `%install` injects a real section header (`error: line
  NNN: second %install`; it broke `make release`). It is **EL-only**: Debian/
  Ubuntu rpm parses the same spec happily, so an rpm parse in CI would not
  cover it. `check_rpm_spec_macros.sh` enforces the escape statically, from
  `make rpm` as well as CI. Verify a packaging change for real in an EL
  container: `docs/packaging.md` (parse-only and full-build recipes).
- **Never hand-date the top rpm `%changelog` entry.** EL10 rpmbuild takes
  `SOURCE_DATE_EPOCH` from the newest `%changelog` date and clamps every
  packaged file's mtime to it (a hand-dated top entry made files read "May 4"
  for months). The top entry is `%{cfm_changelog_date}`, and `make rpm` exports
  `SOURCE_DATE_EPOCH` = build time (unless set). Add hand-written entries BELOW
  the auto one, never above: out of order, EL9/EL10 silently drop the rest of
  the changelog (EL8 fails). `check_rpm_spec_macros.sh` enforces the top entry.
  To verify for real, run `make -o build rpm` inside almalinux:10 (build
  `bin/cfm` on the host first); the bare-rpmbuild recipe in `docs/packaging.md` bypasses the
  Makefile and still clamps today's files to 00:00 UTC.
- **A guardrail that cannot run its matcher must FAIL, never report OK.**
  `check_cli_transport.sh` once piped `rg … || true` on a runner without
  ripgrep and passed while checking nothing. CI installs ripgrep next to
  luajit, and every rg-using script hard-fails when `rg` is absent. For any new
  guardrail: `|| true` may swallow "no matches", never "no tool".
- **Tests never touch CFM's live system paths.** Production defaults used to
  be literals, so the suite, run as root anywhere, wrote the LIVE files
  (manual challenges, WAF excludes, notifier history and `notify.conf`, a
  kernsec rollback snapshot of test boot args); CI, not root, never saw it.
  Each such default is now a var the tests point at a temp dir:
  - `webdetector` `defaultStateDir`/`defaultLogDir` (via `TestMain`, and
    `SetDefaultDirsForTest` from the `TestMain` of another package whose tests
    build an Engine, as apiserver does);
  - the `kernsec` rollback snapshot paths;
  - the `sslcollector` `defaultCacheDir`;
  - the `nft` `selfIPsLuaPath` (EnsureBase rewrites the edge's self-IP list);
  - the `notify` and `detectorscfg` `systemConfigPath` (via
    `SetSystemConfigPathForTest` from the apiserver `TestMain`; the
    detectors-config code otherwise prefers the live `/etc/cfm/detectors.conf`);
  - the `edgeban` `DefaultPath` (`/var/lib/cfm/edgeban.json`, `SetPathForTest`);
  - the `ttlban` `DefaultPath` (`/var/lib/cfm/ttlbans.json`, `SetPathForTest`);
  - the `hostsecrets` `Dir` (`/var/lib/cfm/secrets`; `SetDirForTest`, which
    also clears the per-process token caches, from a `TestMain` or per test
    before resolving a token);
  - the `wafconfig` `SourcePath` / `LuaPath` (set per test; the sync is
    started only by the daemon, never by the detectors manager).

  A new default path goes through the same kind of var
  (`TestFillDefaultsPathsFollowTheRedirectableDirs` fails a webdetector store
  added as a literal; the detectors' init-time states create no
  `detectors.state.d`). `check_test_isolation.sh` (`arm` before `go test`,
  `verify` after) is the net: any change to content, mode or ownership of
  CFM's four dirs, which CI creates writable and seeds like a packaged node
  (`ci_seed_cfm_dirs.sh`). Blind spots: paths outside those dirs
  (`/etc/default/grub`, `/etc/sysctl.d`), and root-only tests (lsm enable, nft
  integration) never run in CI. Never "fix" an unwritable watched dir by
  re-owning it (that hands a node's live state to that account). To find a
  writer, run the suite in a mount namespace with an overlay on `/etc`, `/var`
  and `/run` and a tmpfs over the CFM dirs (seeded), then look at what landed.
- **Match surrounding style.** Go packages are small and single-purpose;
  keep new code in the right package rather than widening `main.go`.
- **A per-client key is `ipkey.Client` (Go) / `cfm_ipkey.client` (Lua):** an
  IPv6 client is its /64 (`docs/edge-ipv6.md` "IPv6 /64 grouping"). Never key
  an allow, an exact match, a clearance cookie or a log line on it, and never
  add another private "IPv4 or /64" helper: both twins run
  `scripts/tests/fixtures/ipkey.txt`. A counter or rate limit keys on
  `firewall.CountKey` (`core.ClientKey` in a detector): the /64 only where a
  ban could take it (a guarded /64 counts per address, as its ban does). Its
  alert carries a real address (`Extra["ip"]`), which the sink's checks read
  and `firewall.ExtendClientBlock` widens itself; the kernel nft meters stay
  per address (spoofable sources).
- **`detectors.conf` readers tolerate an inline `;`/`#` comment — don't
  regress it.** `kvInt`/`kvBool`/`kvDur` (`internal/detectors/registry.go`)
  strip it via `cleanScalar`; before that, `KEY = 5 ; note` failed to parse and
  **silently fell back to the built-in default** fleet-wide. `cleanScalar` cuts
  at the first `;`/`#` and is NOT quote-aware. The string readers
  (`kvStrClean` → `detconf.CleanValue`, quote-aware) rely on the parser reading
  a quoted value followed only by a comment as the text between the quotes
  (`detconf.unquoteValue`); without it `BLOCK = "15m" ; note` read as block
  mode `no`. Prefer comments on their own line; scalars must never
  legitimately contain `;`/`#`.

---

## 6. Where we historically lost the ball (read before touching these)

The areas that generated the most rework and "fix-the-fix" churn. Each rule
here is the short form; the subsystem doc it names holds the incidents,
measurements and as-built detail. Move carefully.

### cPanel / panel-auth integration — the single most painful area
The iframe + token transport flow is subtle and easy to regress. Before
changing it, read `docs/cpanel-plugin-token-transport.md` and
`docs/scoped-postdeploy-verification.md`. Specifically:
- Token delivery is **postMessage-first** (with `cfmTokenAck`); URL-token
  fallback is deliberately *not* used when ACK times out.
- `cfmExpectedOrigin` is injected into the iframe URL and is the
  highest-priority expected `postMessage` origin — always validate origin
  AND source.
- Avoid assertion **nonce reuse**; watch for `token_replay`.
- `panelauth` mints scoped viewer tokens; the plugin must not use admin
  tokens.
- cPanel **account transfers** (DNAT/rsync `/acctxfer*`, WHM live-transfer)
  need challenge/WAF bypass and generous timeouts (several hang incidents).
- **One list for cPanel's own API/SSO/transfer endpoints:**
  `cfm_panel_hosts.is_panel_api_or_sso` (panel listeners 2083/2087/2096); the
  443 proxy subdomains (`cpanel.`/`whm.`/`webmail.`, `cfm.lua` Step 0d) pass
  only its `/cpsess<N>/` subset (`is_session_api`). Change the list there,
  never in a copy. Step 0d trusts the Host prefix only behind three gates —
  `proxysubdomains=1` + `proxysubdomainsoverride=0`
  (`proxy_hosts_reach_panel`) and a registrable-domain host (`cpanel.com.gr`
  is a tenant's own domain). Never drop them: without them a spoofed
  `Host: cpanel.x` bypasses the WAF into a docroot. The Go decision engine
  mirrors all three (`panel_session_api.go`); both sides run
  `scripts/tests/fixtures/panel_session_api.txt`. Detail: `docs/waf.md` FP
  case 11.

### WAF false positives — never "done"
The WAF needs continuous tuning against real apps (Joomla K2 / elFinder
`cmd=<verb>`, `/.well-known/` DCV, WP migration-plugin imports tripping 402).
For an import that trips 402 the remedy is an operator-side temporary
rule-scoped exclude, NOT a code carve-out: an `action`-keyed exemption was
tried and reverted, because no edge-time keying on admin-ajax's `action` is
safe (`docs/waf.md` FP case 6). When adding/strengthening a rule, check it
doesn't trip legitimate panel/app traffic, and promote `logonly` →
`challenge` → `block`, never straight to block. Reference: `docs/waf.md`
(FP case studies, excludes, the promotion playbook),
`docs/challenge-waf-release-checklist.md`.

### Challenge excludes & scoping
- Exclude/bypass matching must be scope-aware for scoped users; excludes are
  increasingly **file-presence based** rather than config flags. Pre-auth
  login challenge behaviour differs between DNAT and OpenResty modes — verify
  both.
- **A path-based challenge exemption needs both sides.** `/.well-known/` has
  the in-path serving carve-out (`cfm.lua` Step 0a1) AND the decision engine's
  scoring exclusion (`isWellKnownChallengeExempt` in `engine.go`); without the
  second a CA's ACME/DCV validator gets flagged as a scanner (it once broke SSL
  issuance). Both sides run `scripts/tests/fixtures/wellknown_exempt.txt`.
- **A client exemption has mirrors; change them together.** The challenge page
  itself is reached directly (`/__cfm_challenge?next=…`, a location that
  bypasses cfm.lua), so `challengePageExempt` mirrors the three
  `handleDecision` blocks (verified good-bot downgrade, Challenge
  Access-Control entry, exclude-file serve-time match) and sends those clients
  to `next` — except a `next` carrying a `cfm_rt` (that challenged POST would
  be lost). The vhost uniqIP count is a third mirror
  (`vhostChallengeExemptClient`, `uniqip_exempt.go`).
- **A vhost in LOCKDOWN withdraws every client exemption**
  (`vhost_lockdown.go`, `docs/vhost-lockdown.md`): Step 0 stops bypassing
  crawler (`1`) prefixes for that host (CDN `2` prefixes keep it; a held
  crawler also skips the inline WAF, or bait would get Googlebot nft-banned),
  and the decision and challenge-page mirrors stand down. A new client
  exemption must check `vhostLockedDown` too. The uniqIP count is deliberately
  NOT locked down (it would arm an automatic v2 that outlives the lockdown).
- **Never serve challenge CONTENT at a content URL:** a CDN that ignores the
  origin's `Cache-Control` caches it despite `no-store` (it once served a
  cached challenge with another visitor's token). The page lives only at
  `/__cfm_challenge`; a cleared client bounced back gets one `cfm_nc`
  cache-busting retry, and `edge_health` Check F names the host
  (`docs/edge-health.md`). The edge strips `cfm_nc` before the origin
  (`strip_cdn_bust_arg`, or a signed URL fails), but only on a plain path —
  rebuilding a changed query would send the origin the DECODED path.

### Traffic rules — `Simulate` IS the enforcement path
`trafficRuleStore.Simulate` is wired as the nginx bridge's `RuleDecision`, so
whatever it returns is what the edge enforces; the `/rules/simulate` API just
exposes the same call (it once ignored `Enabled`, so every "start disabled"
preset was live; `disabled_match` carries the would-be match). A rule `allow`
only ends rule evaluation — it never bypasses WAF / vhost challenge / IP
block (OR'd in `cfm.lua` Step 3) — and clearance-cookie holders return at
Step 2b before rules run. A request only a rule blocks is logged
`up=cfm_block_rule` and skipped by the 403 counters (`isRuleBlock403`): a
rule's block never escalates into a 403_flood nft ban. Rule semantics live in
`rules-model.js` on the UI side; change it in the same PR as
`traffic_rules.go`. Docs: `docs/traffic-rules.md`,
`docs/traffic-rules-ux-proposal.md`.

### cfm-lsm — signal, then noise
New LSM rules ship noisy (the first burst needed extensive CRED/OBS/FS
false-positive silencing) — budget for a tuning pass and honour prior LSM
decisions. BPF bytecode can go stale: `make build` runs `verify-bpf-bindings`
and `make release` regenerates objects; don't bypass these. Reference:
`docs/cfm-lsm.md`, `docs/kernsec.md`.

### WAF → autoblock (`waf_security`) — move carefully
Turns in-path WAF hits into a persistent nft block via the detector framework
(`internal/detectors/wafsec/` + `waf_security_register.go`, published from
`webdetector.RecordWAFTrigger` via `SubscribeWAFHitEvents`). Design, the
family/rule arming table and the decision records:
`docs/waf-autoblock-design.md`.
- **Phase 1 feeds edge-`block` hits ONLY** (the subscribe callback drops any
  hit whose action != `block`). Never key autoblock on reason family alone: a
  family spans tiers (`WAF_RCE`, `WAF_BACKDOOR` mix block with challenge_v2 /
  logonly rules), so family-only keying bans lower-tier recon. Which families
  can fire is the Go registry (`DefaultMode: "block"` in `waf_rule_ids.go`),
  never a hand-kept list; the rendered `[waf_security]` template derives from
  it.
- **Adding a block-tier rule to a family SILENTLY arms its autoblock**: the
  default is `1 iff WAFFamilyHasBlockRule(fam)`, and existing
  `/etc/cfm/detectors.conf` files inherit it on upgrade. When you promote a
  rule to `block`, decide the autoblock intent in the SAME change: arm, hold
  the rule (`HoldAutoblock` on its `WAFRule`, the default for its `RULE_<id>`
  key, so it reaches configs that predate the rule), or hold the family
  (`heldAutoblockFamilies`). Arming a newly block-promoted family is a
  deliberate opt-in after its own burn-in. Block tier is also what the
  panel-port gate (`cfm_panel.lua`) enforces, so a block promotion arms the
  rule on `:2083/:2087/:2096` too — check the `waf_rule_detail` panel section
  for that rule in the same review.
- **A held block family or rule shadows armed ones** (the first block hit owns
  the headline `record()`, `goto done` ends evaluation, and `cfm.lua` pushes
  only the headline), so held rules and the held `WAF_TRAVERSAL` family run in
  the late group of `cfm_waf.lua`, after every armed block family, as does
  rule 201's block. Keep them there, or arm them. **`WAF_TRAVERSAL` is held
  at `0`** in code (`heldAutoblockFamilies`, the one source
  `wafSecurityFamilies` reads), the reference `detectors.conf` and the coverage
  test; arming it is the operator's `TRAVERSAL = 1`. "Push every
  block-tier hit" was rejected (it removes the cheap-rules-first short
  circuit); revisit only if a second held FAMILY appears, and then by letting
  `record()` continue past a held family's block only (decision record in the
  design doc).
- **The Lua edge de-dups pushes per `(ip, reason family, action tier)`**
  within `push_cooldown` (`cfm_waf.lua should_push`), and per RULE for the
  `block` tier (a held rule's push must not swallow an armed one's). An
  accumulate threshold counts cooldown windows, not raw hits — retune when
  Phase 2 turns on challenge-tier families.
- **An nft ban never stops a client behind a trusted proxy** (Cloudflare): on
  the wire it is the proxy's address. The web-related bans (the waf_security /
  webdetector / challenge_* / modsec / cfm_endpoints / cpanel /
  login_bruteforce sections, the challenge server, manual API/CLI bans) also
  go to the edge ban store (`internal/edgeban`), answered `ip_action=block`
  for PROXIED requests only. It is NOT an nft mirror, and every nft allow set
  wins. **A new web blocker or unblock / allow path must call `edgeban.Ban` /
  `edgeban.Unban`.** An automatic blocker bans through
  `firewall.ExtendClientBlock` / `BlockClientPermanent` (an IPv6 client is its
  /64, in its own set `block_v6_clients`; the kernel L3/L4 autoblock stays per
  address, its source can be spoofed) and hands the element they return to
  `edgeban.BanElem`; an unblock also calls `firewall.RemoveClientNet` and
  `ttlban.ForgetClient`. The edge checks its copy (`cfm_edgeban.lua`) at cfm.lua
  Step 0e, before every exemption but the static IP/CIDR bypass: **a new
  exemption step goes AFTER it**, or a banned proxied client walks through.
  `[webdetector] EDGE_BAN_MODE` = `enforce` (default) | `log`; kill switch
  `EDGE_BAN`. The rest of nft's IP filter (fleet feeds, `block_v4`, every
  allow) reaches a proxied client through `internal/proxyipfilter` (daemon
  memory, never Lua), after the edge ban store, allows first;
  `PROXIED_IPFILTER_FEED` / `_LOCAL` = `log` (default) | `enforce` | `off`
  (`docs/proxied-ipfilter.md`).
- **Never a static `listen [::]` in the reference edge confs.** On a host
  without an IPv6 stack it fails the config test and the edge does not
  start. The IPv6 listens live only in the generated
  `cfm-listen-v6-{http,https}.conf`, included through a glob (absent = IPv4
  only) and decided before every edge start by `cfm-edge-listen-v6.sh`
  (`docs/edge-ipv6.md`; `check_edge_listen_v6.sh` pins the includes). An
  IPv6 origin hop binds `::1`, so the origin must trust `::1` too: without it
  every IPv6 visitor is localhost to the origin, which is why the script asks
  `cfm realip` (which requires ::1 as soon as the host can do IPv6) before it
  writes the files. Off by default (`V6_DEFAULT` in the script =
  `edgeIPv6Default` in Go, pinned equal) until per-IP defences group IPv6 by
  /64: keyed on the full address, a direct IPv6 client rotating in its /64
  evades bans and limits. Do not flip the default before that lands.
- **A connection is NAT'd once, by the first nat chain that rewrites it.**
  Imunify360 DNATs its sets (Cloudflare's ranges among them) to WebShield at
  -100, ahead of CFM's -99 default web redirect, so Cloudflare visitors
  skipped the edge for months. Imunify nodes run `NFT_DNAT_PRIORITY = -101`;
  `edge_health` check H (`web-dnat-order`) warns. Detail:
  `docs/imunify360-gap-analysis.md` ("WebShield").
- **The detector only emits `core.Alert`.** Blocking, leniency (GR/CY
  temp-ban), API reporting and email are the section sink's job
  (`autoblock_sink.go`) — don't reimplement them. A plain alert blocks per the
  section `BLOCK` policy; `Extra["enforcement"]="dryrun"` logs without
  blocking.
- Ships a **soft TTL block** (`BLOCK = "6h"`, self-healing), not `permanent`;
  `DRY_RUN = 1` gives a watch-first burn-in. Every WAF family is a config knob
  (key = family minus `WAF_`); `TestWAFSecurityFamilyCoverage` asserts the
  whole registry and the armed / held defaults.

### WAF CVE detectors (`WAF_CVE`) — named-vulnerability rules
Per-CVE in-path detectors live in the `10000+` rule-id band and emit
`WAF_CVE:CVE_<year>_<suffix>:PRODUCT:TAG`, which the notifier turns into a
`WAF/CVE-YYYY-NNNN` alert (`cveFromReason`). **Read `WAF_CVE.md` before
adding one** (as-built table, "CVE hunting" recipe, backlog, design
decisions, the body burn-in's `BURNIN_ENFORCE_IDS`).
- **Never write a CVE signature from memory.** The assistant's knowledge
  cutoff predates most target CVEs — get the exact method/endpoint/marker from
  a public PoC, the vendor patch, NVD references, or operator-supplied
  logs/captures. A param *name* legit traffic also sends is not exact enough.
- **`WAF_CVE` is armed by default** (`CVE = 1`): an un-armed family is dropped
  by `wafsec` before the sink, so `CVE = 0` would notify nothing. Hold a
  lower-confidence CVE rule per rule (`RULE_<id> = 0` / `HoldAutoblock`), not
  the family. (`WAF_WEBSHELL` is armed too: exempt a benign `/c99.php` scanner
  with `ALLOW_UA_CONTAINS`/`ALLOW_NETS` or hold `RULE_413 = 0` rather than
  un-arming the family.)
- **Lua↔Go id AND mode parity are enforced.** A new `10xxx` id needs matching
  entries in `configs/lua/cfm_waf.lua` `RULE_IDS` **and**
  `internal/webdetector/waf_rule_ids.go` (`TestWAFRuleIDs_LuaParity`), plus
  positive+negative Lua tests. A promotion/demotion edits the Lua CFG default
  **and** the Go `DefaultMode` in the same change
  (`TestWAFRuleIDs_DefaultModeLuaParity`): the Lua CFG is what runs, but
  `DefaultMode == "block"` is the `waf_security` arming source.
- Key the detector on the exact endpoint/marker, reuse hardened helpers
  (`detect_upload_content`, not a raw `<?php` scan), and decide autoblock
  intent in the same change. **A rule keyed on a request FIELD reads it through
  `php_request_fields`** (`cfm_waf_detectors.lua`), never a hand-rolled split:
  a field the edge reads differently from PHP is a bypass. Change that reader
  only with `scripts/tests/php_request_fields_oracle.py check` passing against
  a real PHP (`php -S` runs the same rfc1867.c as php-fpm), then `record` the
  CI fixture.

### Concurrency / process lifecycle
- When spawning subprocesses or background refreshers, ensure reaping, bounded
  backoff, and stale-snapshot markers rather than advancing heartbeats on
  failure (early bugs: zombie tailers, panics, snapshot-refresh races). An
  unknown must never read as OK: a failed read is an error, not a clean empty
  result.
- **mmap'd readers: the lock must cover the READ, not just the pointer
  load.** `internal/enrich` GeoLite2 readers are mmap'd (`Close` munmaps); a
  lookup that dropped `mu.RLock` before reading crashed the daemon (SIGSEGV)
  when a database refresh closed the reader. `readGeo` holds the RLock for the
  whole read; a reader is closed only after it is detached under `mu.Lock`.
  Apply the same rule to any mmap'd or otherwise closeable shared resource.
  Corollary: then never take the WRITE lock on a hot path (even for a
  nanosecond rate-limit check — with Go's writer preference it stalls every
  reader); `statChk` is an atomic for that reason. Test mmdb code with
  `internal/enrich/mmdb_testutil_test.go` (spec-valid `.mmdb` at test time;
  `TestHotSwapNeverReadsAClosedReader`).
- **Both geo schemas must be read everywhere**: MaxMind's and IPLocate's flat
  one land under the GeoLite2 file names, and both readers (`geodb.go`,
  `cfm_geo.lua`) must read both (for a long time neither read IPLocate's and
  the node silently had no geo). Measure a third-party schema on the REAL file,
  never from its docs (IPLocate's `asn` is a string; a typed-`uint` decode
  failed the whole record).

### Traffic classifier / fingerprint reputation ("evidence ledger") — shadow-first signals, operator-armed enforcement
Read **`docs/abuse-defense-progress.md`** first (where we are), then
**`docs/abuse-defense-master-plan.md`** (THE plan of record and decision log;
other docs' phase checklists are frozen). Every tell, line key, measurement and
the observability contract: `docs/traffic-classifier.md` (§7 lists the rest).

**The invariant — do not cross it: no SIGNAL keys enforcement on a fingerprint
automatically.** A fingerprint (TLS/JA4) is a **population, not one client**
(a legit browser shares a coarse TLS bucket with a farm). The
`WAFHitEvent` published to `waf_security` carries **no** fingerprint, and WAF
attribution uses the handshake-derived `cfm_tlsfp`, never the spoofable
`X-CFM-TLS` client header. A request relayed by a trusted proxy carries the
PROXY's handshake, so `cfm_tlsfp.value()` returns no fingerprint for it.
Likewise origin is never innocence and datacenter-ASN alone never drives an
adverse decision. The ONE fingerprint enforcement path is the
**operator-armed** per-fingerprint policy: cfm-web `fingerprint_policies` →
agent pull → `fppolicy.go` → `/nginx/fppolicy` → `cfm.lua` Step 0c (`deny`
403s pre-clearance; challenge tiers are a floor for uncleared clients); the
panel ports enforce an armed `deny` too (`cfm_panel.lua` step 2f,
`PANEL_FP_POLICY_MODE`, default enforce) while challenge-tier fingerprints
stay observe-only there (the panel serves no per-request challenge). The
same feed carries **country / ASN policy kinds, challenge tiers ONLY** (a geo
`deny` is excluded by doctrine).
Knobs `[webdetector] FP_POLICY` (`0` kills all kinds) / `FP_POLICY_ALLOW_FPS`.

**ChallengeV2 — couplings a code change can break:**
- The edge serves `challenge_v2` as the same page as `challenge`; the rung is
  enforced at verify. The wire/ipState stays plain "challenge"; the verbatim
  tier reaches cfm.waf.log/history; challenge-tier hits never feed
  `waf_security`. An OLDER edge maps an unknown WAF mode to `disabled` —
  upgrade before setting the tier (`docs/waf.md`).
- **Arm grains** (the list also lives in `challenge_v2.go`'s header):
  fingerprint policy, geo policy, a per-vhost v2 tier, `unsolicited` (a web
  solve no challenge covered: withheld, never refused), and rung marks from
  three writers — a traffic rule with action `challenge_v2` (per ip+host;
  `rules-model.js` and `traffic_rules.go` change together), a WAF rule at
  `"challenge_v2"` (per IP, recorded in `handleIPPush`), and the malpath
  challenge (`CHALLENGE_PATHS`, per IP, `CHALLENGE_V2_PATHS`). Marks are read
  for web-scope verifies only, and only a web-scope solve releases the IP's
  decision. An unblock clears every rung mark (`clearChallengeV2Marks`).
- **Exemptions at verify are grain-scoped.** The FCrDNS good-bot waiver
  (`CHALLENGE_GOODBOT_EXEMPT`, `v2_waived=`) applies only under a geo / vhost
  arm (the grains the decision exemption softens) and never in lockdown; fp
  policy and rule/WAF marks stay strict. The real-input rescue
  (`v2_rescued=input`) applies under every grain but never above its fixed cap
  (`rescueMaxScore`) and never with a certain tell (webdriver / headless UA).
  Making webdriver / headless UA reject at every tier was measured and
  rejected (unarmed, they are mostly site owners' own tools).
- **ONE resolver for "is this vhost v2": `challengeV2VhostTier`**, serving
  the gate and every surface — never read the manual rung alone. A manual v1
  arm never downgrades an automatic v2 (that was a scoped bypass of an
  operator's v2 pin).
- The malpath challenge also revokes the IP's clearance (the edge must not
  honour, nor the challenge page wave through, a revoked cookie), and its
  failed visits hold, then ban — malpath-marked IPs only: other grains'
  rejects are site owners' own bots and arm-held farms. Detail: master plan
  §5 slice E.
- **A reject writes its own `challenge_v2_reject` history row, never
  `challenge_solved`** (`detection_history type=challenge_v2_reject
  node="all"` is the FP-hunting query).
- **Scoped callers never see operator policy**: the whole `v2` / `v2_*`
  payload family (by prefix), `ms`, `src`, `scope` and `sig` are stripped for
  scoped callers (`docs/endpoint_scope_inventory.md`); stripping `v2` alone
  leaked the grain through its siblings. Payload `ptr` is stripped too, as
  defence in depth only (scoped drilldowns already show a per-IP PTR).
- **Report what was reported**: absent keys mean not reported, never a
  fabricated zero; humanity keys are omitted when the scorer did not run.
  Corpus-only readings (`dm`/`dpr`/`raf`, trajectory, `hid`, `rf`) are scored
  by nothing until the corpus says so; a new tell is written from the corpus,
  never from memory, and a single spoofed device claim never rejects alone.
  The real-input rescue only ever clears. `src=` and `scope=` are log-only,
  never an arm. Kill switches: `CHALLENGE_V2_HW_TELLS`,
  `CHALLENGE_V2_INPUT_RESCUE`, `CHALLENGE_V2_UNSOLICITED`,
  `CHALLENGE_V2_PATHS`, `CHALLENGE_PATHS_REVOKE`,
  `CHALLENGE_V2_PATHS_REJECT_BAN`. The client-authored humanity report stays
  spoofable by a signal-aware farm (the HONEST LIMITS block of `challenge_v2.go`); a farm
  running real browsers is the operator fingerprint / geo policy's job.

### Site Cache (per-vhost edge caching) — bypass-by-default, the rails are absolute
CFM once shipped a GLOBAL cache and it broke redirects, SSO, webmail and
cPanel — every rule here exists because of that. Design + as-built:
`docs/site-cache-design.md`; operating it: `docs/site-cache-runbook.md`.
- **Bypass-by-default, pinned by `check_site_cache_config.sh`.** The confs
  pre-set `$cfm_cache_skip "1"`; only `cfm_cache.lua` (`static_gate` /
  `micro_gate`) flips it. Keep the guard strict and mutation-test any change
  to it (its header lists what it pins). nginx `set` / `map` / a regex named
  capture / `set_by_lua*` on a `$http_*` / `$upstream_http_*` / `$cookie_*` /
  `$arg_*` variable SHADOWS the real value (a `map` for the whole http block),
  so a stray `map … $http_authorization` would silently turn the
  credentialed-request rail off — the guard refuses every such writer.
- **Tier B: arming a vhost's micro tier is the opt-in.**
  `MICRO_CACHE_ENFORCE` (default `1`) is a node-wide kill switch like
  `SITE_CACHE`; the per-vhost arm is what guards a tenant. Before arming micro
  on a new kind of app (a shop, a membership site), follow runbook §7. The
  edge reader treats an ABSENT field as off (fail-safe). Micro is entered ONLY
  at cfm.lua's Step 4 (after WAF, challenge, bridge decisions);
  `cfm_micro_entry_structure_test.lua` pins it.
- **Tier A's static recipe/TTL are labels.** The static locations follow the
  origin's Cache-Control/Expires with a 1 h fallback; don't document or
  promise a static TTL the edge doesn't apply. Micro TTL snaps to
  MICRO_BUCKETS {1,2,5,10,30,60,90,120}s; the guard pins the Lua list to the
  conf zones/locations.
- **Go↔Lua parity via a generated fixture.** `site_cache_edge_parity_test.go`
  renders `scripts/tests/fixtures/site_cache_edge_parity.lua` for the real
  `cfm_cache.lua`. Regenerate with `-update-edge-parity` and REVIEW the diff —
  a changed key is a behaviour change, not fixture noise.
- **The cfm-admin page model is a pinned copy.** `site-cache-model.js`
  mirrors the daemon's host / TTL / recipe / cookie rules and the edge's
  bucket snapping; `site-cache-model.test.js` and
  `scripts/tests/fixtures/site_cache_ui_parity.txt` (run against the daemon's
  set path and `parseCacheTTL`, and `cfm_cache.lua`) tell you when the page
  must follow a rule, recipe or bucket change. The page's saves are merge
  patches carrying only what the operator decided; never make one resend the
  whole form (it silently reverted concurrent changes and switched caching
  off).
- **Every edge counter goes through `cfm_shdict.incr(dict, key, n, ttl)`**,
  never `shdict:incr(key, n, init)`, which loses counters on a crc32 collision
  (lua-nginx-module 0.10.26; per-IP rate counters hit it routinely).
  `cfm_shdict_test.lua` fails a new direct `incr` call with an init argument
  (`d:incr`, `d.incr`, `d["incr"]`, in modules and confs' inline Lua; an alias
  is not seen) and requires the helper to be bound as `local shd`.
- **A shared dict's size change resets it on reload** (a same-size reload
  keeps it); key counters on a fixed-size digest so capacity is a fixed
  number of counters.
- **The never-cache rules differ by tier. Don't document them as one list.**
  Both tiers: Authorization, `Set-Cookie`/private/no-store, non-200,
  panel/webmail hosts, GET/HEAD only, script paths; session cookies,
  credential headers and admin paths are Tier B only. ONE Tier B exception: a
  response whose Set-Cookie headers are ALL tracking cookies is stored, and the
  tracking lines are stripped from every micro response by
  `cfm_cache.micro_setcookie_filter` (`$cfm_sc_unsafe`, fail-closed "1"). That
  filter must stay in the server-level `header_filter_by_lua_block` (a
  location-level one replaces it). A cookie the EDGE adds before the micro
  exec (`cfm_clearance`) keeps `$cfm_sc_unsafe` at "1": wiring the clearance
  fast path to micro (design §5.5.1) must exclude those first, in the filter
  AND in `micro_note`. A node can run new Lua with an old conf: keep the
  old-conf fallbacks in `cfm_cache.lua`. Cookie list: runbook; details: design doc.
- **`SITE_CACHE = 0` freezes each worker's policy table** (no feed poll while
  off). Incident procedure: purge, reload the edge WHILE the switch is still
  0, then restore it (runbook §8); reloading after the restore leaves a
  window of the old generation.
- **`detectors.conf` edits apply without a reload** (the manager polls it).
  SIGHUP ends the daemon (its only handler saves the TTL bans, then re-raises),
  so `systemctl reload cfm` restarts it (systemd `Restart=always`). A config
  reload builds a new webdetector Engine, which empties the in-memory Site
  Cache stats view; it follows any save (file mtime) and the rotation of a
  tailed detector log (inode).

---

## 7. Key docs (pointers, not duplication)

| Topic | Doc |
|---|---|
| Roadmap (where CFM is going: in-flight + backlog) | `docs/ROADMAP.md` |
| WAF behaviour & tuning | `docs/waf.md` (hub) |
| Challenge/WAF release gate | `docs/challenge-waf-release-checklist.md` |
| cPanel token transport | `docs/cpanel-plugin-token-transport.md` |
| Scoped-mode post-deploy checks | `docs/scoped-postdeploy-verification.md` |
| MFA rollout | `docs/mfa_rollout_regression_checklist.md` |
| BPF LSM | `docs/cfm-lsm.md` · Kernel hardening: `docs/kernsec.md` |
| Detectors (incl. leniency §6) | `docs/DETECTORS.md` |
| Detectors config unification (design: srcresolve / detectors.d overlays / converged defaults) | `docs/detectors-config-unification.md` |
| `what's_wrong` root-cause engine (contract + roadmap) | `docs/whats-wrong-rootcause.md` |
| Challenge engine design (PoW/solver/TLS-fp) | `docs/roadmaps/challenge-engine.md` |
| Abuse defense (challenge / classifier / fingerprint) — **PLAN OF RECORD** | `docs/abuse-defense-master-plan.md` (the one roadmap + decision log, both repos) |
| Abuse defense — **progress journal** (start here: current picture, fleet state, weekly reads) | `docs/abuse-defense-progress.md` |
| Traffic classifier / fingerprint evidence ledger (node side) — design hub | `docs/traffic-classifier.md` (node design: evidence grains + actuator ladder + ChallengeV2 rung) · per-IP score `docs/challenge-score.md` · central store in **cfm-web** (`cfm-web:docs/fingerprint-reputation.md`) |
| Web detector abuse-targeting refactor (living) | `docs/webdetector-refactor.md` |
| Under-Attack Mode (design: escalation state + campaign fingerprinter) | `docs/under-attack-mode.md` |
| Edge unification & shared Lua (angie/openresty) | `docs/edge-unification-plan.md` |
| Scope/host-bound clearance model | `docs/security/challenge-scope-mapping.md` |
| sslcollector (cert discovery + socket API) | `docs/ssl-collector.md` |
| WAF → autoblock (`waf_security`) | `docs/waf-autoblock-design.md` |
| WAF CVE detectors (`WAF_CVE`) | `WAF_CVE.md` (as-built + backlog + design decisions + "CVE hunting" recipe) |
| Admin/WebUI API | `docs/webui-api-curl-recipes.md` (recipes + sample responses) |
| DNAT bypass | `docs/dnat-bypass.md` · Debug capture: `docs/debug-capture-runbook.md` |
| Proxy latency: measuring & origin keepalive | `docs/proxy-performance.md` |
| Endpoint scope inventory | `docs/endpoint_scope_inventory.md` |
| Traffic rules: match fields, semantics, examples, API | `docs/traffic-rules.md` · UX review + open proposals: `docs/traffic-rules-ux-proposal.md` |
| Panel DNAT (cPanel / WHM / DirectAdmin ports through the edge) | `docs/panel-dnat.md` |
| CLI commands no topic doc owns (`webtop`, `bots`, `firewall status/path`, `health`) | `docs/cli.md` |
| MySQL Governor | `docs/mysql-governor.md` |
| Outbound Abuse Sentinel (per-uid outbound SMTP / scan / HTTP abuse) | `docs/outbound-sentinel.md` |
| Packaging: verifying an rpm change in an EL container | `docs/packaging.md` |
| Log rotation (who rotates what) | `docs/log-rotation.md` |
| Origin real IP (the origin sees the visitor, not the edge's 127.0.0.1; `cfm realip`) | `docs/origin-real-ip.md` |
| Edge IPv6 listen (`EDGE_LISTEN_V6 = on`, off by default until IPv6 /64 grouping; generated listen files decided before every edge start) | `docs/edge-ipv6.md` |
| ClamAV upload scanning (scope, inline mode, signature excludes) | `docs/clamav.md` |
| Backup check (JetBackup / Virtualmin / Proxmox → detection_history) | `docs/backup-check.md` |
| Mail abuse findings (hacked site / contact form, mailbox spike, hijacked mailbox → detection_history) | `docs/mail-abuse.md` |
| Alert log (every notifier event + its delivery outcome → `/var/lib/cfm/alerts.db`, `/api/v1/alerts`, cfm-admin Alerts, MCP `alerts`) | `docs/alerts.md` |
| Site Cache (per-vhost edge caching): design + as-built / operating it | `docs/site-cache-design.md` · `docs/site-cache-runbook.md` |
| Vhost lockdown (no client exemption on a manual vhost challenge: crawler storms) | `docs/vhost-lockdown.md` |
| Proxied-client IP filter (fleet feeds, local bans and allows for clients behind Cloudflare) | `docs/proxied-ipfilter.md` |
| Imunify360 vs CFM: what Imunify catches that CFM does not (measured on earth; status of each gap) | `docs/imunify360-gap-analysis.md` (WebShield included) |
| PHP runtime defense (CFM-managed Snuffleupagus; CFM writes no PHP extension of its own) | `docs/roadmaps/php-runtime-defense.md` |
| Targeted challenges (audience floor on the automatic vhost challenges + under-attack confirm step) — design; the confirm step built for a manual `attack on` (`CHALLENGE_V2_CONFIRM`) | `docs/targeted-challenge-design.md` |

Comments citing "audit Fnn" (Lua, confs, tests) refer to the closed
2026-07 edge-Lua audit, deleted 2026-11-18: `git log --diff-filter=D --
docs/edge-lua-audit-2026-07-08.md` finds the commit; read it at that
commit's parent. Its two open items are in `docs/ROADMAP.md` §1.

**Docs policy.** A doc earns its place by being current or by holding a
decision that would otherwise be reopened. Finished audits, closed plans and
"as-built" notes the code now states are deleted, not archived: git history
keeps them, and a stale doc read as current misleads (code moves on, the doc
does not). A standing "no" goes into `docs/ROADMAP.md` as a `[decided]` line.

---

## 8. Releasing & CHANGELOG

**The version IS the date, in UTC.** The Makefile sets
`VERSION ?= $(date -u +%Y.%m.%d)` (every release timestamp is `date -u`, so a
build never lands on a different day by host timezone). The `.deb` and the git
tag carry a `-HHMMSS` UTC suffix (`vYYYY.MM.DD-HHMMSS`); the CHANGELOG heading
is **date-only** (`YYYY.MM.DD`) — the date is the unit of release. There is no
separate semver to bump. The release ritual is:

```bash
make release    # builds bin/cfm, then the .deb and .rpm; also stamps CHANGELOG (below)
make sync       # rsyncs today's .deb/.rpm (+ checksums) to the remote repo
```

- `make release` runs `bypass-list bpf deb rpm` (BPF needs `clang` +
  `libbpf-dev`). `bypass-list` re-fetches `configs/challenge_waf_bypass.conf`
  (crawler + CDN ranges) and `trusted-proxies` refreshes
  `configs/trusted_proxies.conf` (Cloudflare's ranges for `CF-Connecting-IP`),
  both fail-safe (`--strict`: a failed, shrunk, out-of-bounds or poisoned feed
  ships the last-good file, never a partial list; rules in
  `scripts/build_bypass_list.py` and the Makefile). The offline validator
  failing, or no Python >= 3.9, stops the release; `BYPASS_REFRESH=0` skips
  both for an offline build.
- Bypass prefixes are `<cidr> 1;` (crawler) or `<cidr> 2;` (a `CDN_SOURCES`
  entry, QUIC.cloud); a vhost lockdown withdraws only the `1` kind, and the
  validator fails a list that lost its `2` lines. **Never add a source whose
  target URL anyone can choose** (ChatGPT-User, Stripe webhooks, uptime
  monitors): a bypass skips the WAF too (`cfm.lua` Step 0), so it becomes a
  free WAF-bypass proxy; such callers need a path-scoped exclude.
  `trusted_proxies.conf` is Cloudflare-only on purpose: a proxy that passes a
  client-supplied `CF-Connecting-IP` through (QUIC.cloud does) must never be
  added.
- `make release` also cuts a **tag-only GitHub release** (that day's
  CHANGELOG section as notes, `scripts/release-notes.sh`) with **no
  `.deb`/`.rpm` attached**; `make sync` is what ships the binaries
  (+ `checksums.txt`) to the apt/yum repo.

### CHANGELOG discipline (dating is now automated)

1. **While working (the only manual step):** add a bullet under
   `## [Unreleased]`, grouped by **Added / Changed / Fixed / Security /
   Removed**. Keep entries operator-facing (what changed, why it matters) — not
   "fixed typo".
2. **`make release` stamps, commits and pushes it**: `scripts/stamp-changelog.sh
   $(REL_DATE)` moves `[Unreleased]` under a `## YYYY.MM.DD` (UTC) heading and
   leaves a fresh empty `## [Unreleased]`. The commit is path-scoped to
   `CHANGELOG.md`, `configs/challenge_waf_bypass.conf` and
   `configs/trusted_proxies.conf` (`git commit -- <those>`), never the whole
   tree, so built binaries / BPF objects are never swept in. A failed
   commit/push warns but never aborts a good release.

The stamp is idempotent: an empty `[Unreleased]` (only `_Nothing yet._`) is a
no-op, and a second build the same day appends under the existing
`## YYYY.MM.DD` section (one section per day). `make changelog` runs it
standalone (edits only, no commit). The date always comes from the Makefile
(`REL_DATE := date -u +%Y.%m.%d`), so it can never drift from the package/tag
date. The CI `changelog` guard (`scripts/tests/check_changelog_entry.sh`, §3)
keeps `[Unreleased]` stampable and nudges every runtime-code PR to carry an
entry.

## 9. Workflow

- Develop on the feature branch you were assigned; create it from `main` if
  missing. Don't push to `main` directly.
- Keep PRs focused — this repo favours many small, single-concern PRs.
- **Adversarial self-review on every code PR, before opening it.** Run a
  high-effort review of the diff (the `code-review` skill, or an equivalent
  skeptical read that tries to *break* the change), and fold the confirmed
  findings into the **same** PR. This is not optional and not only for "risky"
  changes — retro-reviews have caught real issues in already-merged PRs (a
  case-inconsistent join that false-flagged tenants; a `%.2g` value misrender).
  Docs-only / config-comment PRs may skip it; anything with runtime behaviour
  does not. Note in the PR body that the review ran and what it found.
- **Never retire a signal/detector on reasoning alone — check the fleet
  first** (`docs/abuse-defense-master-plan.md` §4 D3a). "It fed no decision"
  is not evidence: a log-only signal feeds no decision by construction. Before
  deleting, show two things with the CFM MCP (`edge_error_tail` /
  `cfm_log_tail` / `abuse_shadow`, `node="all"`): that it actually emitted,
  and — if the case is "signal Y already covers it" — that Y's own output
  contains the same events. Zero emissions is a DEPLOYMENT finding, not a
  verdict on the signal.
- After edge-affecting changes, run the relevant runbook/checklist in `docs/`
  before considering the change done.
- Update `CHANGELOG.md` (`[Unreleased]`) as part of the change, per §8.
- Don't create a PR unless explicitly asked.
