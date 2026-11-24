# SSL Collector

The SSL Collector (`internal/sslcollector`) finds the TLS certificates and
keys on the host and hands them to the OpenResty/Angie workers over a unix
socket, so the edge selects a certificate per SNI at handshake time with no
per-domain nginx config and no reload.

---

## Architecture

```
cfm daemon (root)
  │
  │  unix socket 0660 root:cfm, /var/run/sslcollector.sock
  │
  ▼
OpenResty/Angie worker (cfm user)
  │
  │  init_worker_by_lua_block  ← can yield / do I/O
  │    start_background()
  │      load_from_snapshot()  ← warms the store from dump.json (if offline cache on)
  │      do_dumpall()          ← fetches ALL cert+key pairs via /dumpall
  │      poll_stats()          ← background poll loop
  │
  │  ssl_certificate_by_lua_block  ← NO yield, NO I/O
  │    M.set_cert()
  │      _store["e:" .. sni], then "w:" suffixes  ← worker-local table lookup only
  │      ssl.set_cert / ssl.set_priv_key on the pre-parsed DER
  ▼
TLS handshake completes with the domain's certificate
```

### No I/O in the handshake path

`M.set_cert()` performs no socket I/O and never yields, which is what makes
it safe for HTTP/3 (QUIC). Every pair must already be in the worker's store
before a handshake for that name; the background timers load it, the
handshake only reads it. That is why `/dumpall` returns every `cert_pem` and
`key_pem` in one payload. A name not in the store gets the static fallback
`ssl_certificate` of the server block.

### Worker-local store, not a shared dict

Pairs live in a worker-local Lua table (`_store`), parsed to DER once at
ingest. A shared dict (`ngx.shared.sslcache`, which this module uses only for
`meta:*` health keys and locks) is enumerable by any Lua code in the process
via `get_keys()`; a worker-local table is reachable only through this module.

---

## Discovery and freshness

**1. The daemon picks up the cert** (`internal/sslcollector`, configured in
`cmd/cfm/main.go`):

| Mechanism | Cadence | Catches |
|-----------|---------|---------|
| fsnotify watcher (`watcher.go`) | 2s debounce | New domains/users and renewals under any watched tree (primary path) |
| Stat loop (`StatEvery`) | 60s | mtime/size changes to already-known cert files |
| Discovery rescan (`DiscoveryEvery`) | 1h | Full re-scan; safety net for anything the watcher missed |

On a `Create` event for a directory (`handleNewDir`) the watcher watches the
new tree and schedules a rescan before its cert/key filename filter runs:
panels create per-domain and per-user directories (`/etc/letsencrypt/live/<domain>`,
`/var/cpanel/ssl/apache_tls/<domain>`, `/home/<user>`) whose names match no
cert/key pattern.

Home trees are watched shallowly (one level): the `/home[0-9]*` mount tops,
the per-user dirs and each user's `domains/` dir, which is exactly the layout
the home scanner reads (Virtualmin `<home>/<user>/domains/<domain>/ssl.{cert,key}`).
The watcher and the scanner share one list of home mounts (`homeMounts()`,
every `/home[0-9]*`), so `/home2`, `/home3`, … are both watched and scanned.

Scanned sources (`sources.go` `discoverPairs`):

- Let's Encrypt: `/etc/letsencrypt/live`
- Mailcow: `/opt/mailcow-dockerized/data/assets/ssl`, the root pair plus its
  immediate SNI host directories; `acme/` and `backups/` are never read
- cPanel: `/var/cpanel/ssl/apache_tls`, `/var/cpanel/ssl/installed/hosts`,
  `/var/cpanel/ssl/cpanel` (service bundles)
- DirectAdmin: `/usr/local/directadmin/data/users`, `/usr/local/directadmin/data/admin`
- Virtualmin/Webmin: `/etc/ssl/virtualmin`, every `/home[0-9]*` (with the
  `ssl.ca` / `ssl.combined` chain), `/etc/webmin/miniserv.pem`
- Exim hostname certs under `/etc` (`exim.crt`/`exim.cert`/`exim.pem` + `exim.key`)

A pair whose key file is missing, empty or a dangling symlink is not indexed
(`buildEntry`). A pair that was indexed and fails to build for a moment (a
cert or key caught mid-rewrite) keeps its entry for 10 minutes
(`buildFailCarry`); while carried its files are re-read at payload time and
sent if they hold a PEM block, else left out (the payload is then
incomplete, see below). A cert file that is gone, or a cert symlink that
dangles, drops the entry at once. A pair that stays broken leaves at the
first Refresh after the 10 minutes (a watcher event, a stat-loop change or
the hourly rescan).

**2. The workers pull it** (`configs/lua/sslcollector.lua`):

- Each worker polls `/stats` every 10s (`POLL_SECS_MIN`). Until the first
  success it retries every 5s; after that failures back off by doubling up
  to 10 minutes (`POLL_SECS_MAX`).
- When the daemon's `Version` differs from the worker's, the worker fetches
  `/dumpall` after `worker_id × step`, where step is
  `min(2s, 20s / worker_count)` (`DUMPALL_STAGGER_SECS`,
  `DUMPALL_STAGGER_WINDOW`): decoding a large list blocks a worker's event
  loop for about a second, so the workers must not all stall at once.
- A worker makes at most one version-triggered fetch per 30s
  (`DUMPALL_MIN_GAP_SECS`) and none while one is scheduled or running or
  once it holds the newest version. AutoSSL renews in bursts and the daemon
  publishes a version per Refresh; the first change of a burst goes out on
  the stagger alone, later ones fold into one fetch per gap.
- The startup fetch and the age-forced fetch (a worker whose store is older
  than 1h, `FORCE_DUMPALL_AFTER`, retried at most every 10 minutes across
  workers) take the shared `lock:dumpall`; a version-triggered fetch does not.
- A worker that has never ingested anything retries the snapshot on every poll.

A new domain is live on every worker within about 30s (2s watcher debounce +
≤10s poll + ≤20s stagger; longer for a change inside a burst, up to the 30s
gap). The 1h fallbacks bound the worst case.

On a cold boot the edge usually starts before the daemon's socket is ready.
Once the socket is bound and the index holds at least one entry, the daemon
issues one `systemctl reload` of `angie`/`openresty` if that service started
before that moment (`reload_edge.go`, `NudgeEdgeOnFirstReady`), so the
workers re-run their init against a ready socket and snapshot. The
`CFM_SSLCOLLECTOR_RELOAD_EDGE_ON_READY=0` environment variable (daemon
environment) disables it.

---

## How an ingest updates the worker store

Each `/dumpall` or snapshot ingest builds a new table and, when it may,
swaps it in whole, so a name the daemon dropped stops being served (an
exact entry outranks a wildcard, so a stale exact entry would otherwise keep
serving an old cert next to a new wildcard). Because a replace also strips
every name the payload lacks, a payload replaces the store only when both
hold:

- **It says `"complete": true`.** The daemon leaves out a name whose PEM it
  cannot read rather than send it empty; only this flag tells the edge that
  something was left out. The snapshot and the per-version `/dumpall` build
  carry it; the last-resort streamed `/dumpall` (no room for a temp file)
  never does. Every incomplete payload is merged into the store.
- **It is not a sudden shrink.** A payload under two thirds of the last
  payload taken is merged while the shrink is younger than an hour
  (`SHRINK_HOLD_SECS`); a shrink that lasts is taken after that, at the next
  version change or forced refresh. The baseline is the last payload taken
  (a worker that has only merged so far uses its store size). The hold is
  timed on the monotonic clock when `resty.core.time` provides it
  (lua-resty-core 0.1.22+), else on the wall clock. Stores of fewer than 3
  names are not guarded.

A payload entry whose PEM is missing or does not parse keeps the worker's
current pair for that name. A held shrink logs `merged, not replaced` and
sets `meta:last_error`. Every ingest logs one line,
`ingest src=… mode=replace|merge_shrink|merge_incomplete|none`.

**A full GC after every ingest that changed the store.** Each pair is OpenSSL
memory (the parsed X509 chain and EVP_PKEY) behind a few bytes of cdata, so
LuaJIT's GC, which counts only those bytes, ran rarely, and the stores an
ingest let go of piled up: titan (3513 names, 2026-11-23) had workers at
410-530 MB PSS. In a container, 20 loads of 3000 pairs took a worker from 51
to 238 MB RSS without it, and a late collect still left 215 MB (the freed
memory is not returned to the OS once fragmented); with a collect right after
each swap it stayed at 92 MB. The collect (`collect_released`) runs in the
ingest's caller, `do_dumpall` (after the shared lock is released) or the
snapshot load, once `ingest_dumpall` has returned: inside it the raw body
(~20 MB on titan) and the decoded payload were still referenced and survived
it. It runs only when the payload stored at least one pair, in a timer, but on
the worker's own event loop: while it runs the worker serves nothing (~50 ms
for 3000 pairs in a container; 85-300 ms on titan, 2026-11-24, on a ~500 MB
heap, after an ingest that already blocks for about a second).

**Then `malloc_trim(0)`** (glibc, through the FFI). The collect frees the
pairs, but glibc keeps the freed pages, and the worker's traffic allocations
living between them stop it from reusing them whole. On titan (collect
only, the night of 2026-11-23/24) a worker's RSS after each ingest rose in
three steps (333 → 432 → 524 MB), then crept ~4 MB/h (535 → 573 MB over 9 h),
and fell back to ~460 MB between ingests. malloc_trim hands the free pages
back to the OS, the middle of the heap included. In a container (3500 pairs,
a 17.6 MB payload, live allocations between 16 ingests) collect only settled
at 227 MB, collect + trim at 165 MB, for ~25-40 ms more. On titan's far bigger
heap the cost is what `trim_ms=` reports, and the next ingest faults the
returned pages back in (inside its own stall, in no log field). Where it does not exist (no
glibc, no FFI) it is skipped. It is thread-safe, and CFM's edge config runs
no thread pool on any engine (no `aio` / `thread_pool`), so the arena locks
it takes contend with nothing.

The collect logs its own line,
`gc src=dumpall|snapshot gc_ms= trim_ms= lua_kb= rss_mb=`: the wall time of
the collect and of the trim (`-` when none ran), the Lua heap after them, and
the worker's resident set (from `/proc/self/status`), which is where the
OpenSSL side shows.

---

## The snapshot and `/dumpall`

The daemon writes `/var/lib/cfm/sslcollector/dump.json` (mode `0640`,
`root:cfm`) after a Refresh, through a randomly named temp file
(`dump.json.tmp-*`, O_EXCL) renamed into place. Workers only read it. The
write:

- is skipped when the file on disk is already this version and complete
  (its mtime is re-stamped instead);
- is refused for an empty index;
- is refused when it would shrink the file by more than a third, unless the
  file is over an hour old or the daemon runs with
  `CFM_SSLCOLLECTOR_FORCE_SNAPSHOT=1`.

`/dumpall` streams the snapshot when it is the current version. Otherwise
(between a Refresh's swap and its snapshot write, a write the guard
refused, a failed write) it builds the payload once per version into an
unlinked temp file next to the snapshot, serves it to every concurrent
request and reuses it for 30s when complete. With no room for a temp file it
streams the payload to the worker as it is written (never `complete`). The
payload is written entry by entry and is never whole in the daemon's memory;
its header carries `version`, `generated_at`, `exact_n`, `wild_n` and
`complete` ahead of the entries.

Each entry's `key_pem` holds only the PRIVATE KEY block(s) of its key file
(`privateKeyBlocksOnly`), `/cert` too. Panels write key files as bundles
(cPanel's combined key+leaf+chain, DirectAdmin `.combined`, Virtualmin
`ssl.combined`), and the chain is already in `cert_pem` (with any key
scrubbed from a chain file, `stripPrivateKeyBlocks`): sent whole, every chain
went twice (on virgo, 2026-11-23, 4181 of 4193 key files were bundles, and
`dump.json` shrank from 56 to ~32 MB). A key file with no key block is sent
as it is.

---

## Socket endpoints

Every endpoint requires the `X-SSLCollector-Token` header (403 without it);
the server refuses to start without a token.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/dumpall` | GET | All cert+key pairs (exact + wildcard). Used by workers at startup, on a version change and on the age-forced refresh. |
| `/cert?host=X` | GET | Cert+key (and metadata) for one hostname. Uses the in-process PEM cache (`SSLCOLLECTOR_SOCK_PEM_TTL` / `_MAX`). |
| `/stats` | GET | Collector stats, including `Version`. Polled by every worker. |
| `/refresh` | POST | Runs a Refresh now (204). |
| `/dump?host=X` | GET | The index entry for a host (paths, source, names, expiry; no PEM). |

### Authentication

- The token is kept in `/var/lib/cfm/secrets/sslcollector_sock_token` (dir
  `0700`, file `0600`, root), created once per host by `internal/hostsecrets`:
  copied from `SSLCOLLECTOR_SOCK_TOKEN` in `cfm.conf` when that holds a
  strong token, else generated. After that `cfm.conf` is not consulted, and
  the daemon never writes it. To rotate: set the `cfm.conf` line to
  `placeholder`, delete the file, restart.
- It is mirrored atomically to `/var/lib/cfm/lua/cfm_token.lua`
  (`0640 root:cfm`) for the edge.
- It is compared in constant time (`crypto/subtle.ConstantTimeCompare`).

---

## Offline snapshot (`SSLCOLLECTOR_OFFLINE_CACHE`)

With the offline cache on (the default), a worker loads `dump.json` before
its first `/dumpall`, so the edge serves every known certificate even when
the daemon is down at edge start (upgrade, crash; `cfm.service` has
`Restart=always`).

`SSLCOLLECTOR_OFFLINE_CACHE = 0` only stops the **workers reading** the
snapshot (the daemon passes it to them in
`/var/lib/cfm/lua/cfm_sslcollector_config.lua`). Workers then serve the
fallback cert until their first successful `/dumpall`. **The daemon still
writes `dump.json`** (`Refresh` → `WriteSnapshot` does not read the knob) and
`/dumpall` is served from it, so the knob does not keep key material off the
disk.

---

## Security model

### Trust boundary

The `cfm` OS group is the trust boundary. The cfm daemon runs as root and
writes the token and the socket; the OpenResty/Angie workers run as the `cfm`
user (`user cfm;` in the shipped confs; the packages and
`install-openresty.sh` create it as a system user with `/sbin/nologin`) and
read the token and connect to the socket. Nothing enforces that no other
account joins the group; keep it that way.

| Scenario | Can reach socket? | Incremental risk from socket |
|----------|------------------|------------------------------|
| Remote attacker | No: the socket is local-only and no API exposes it | None |
| Local root | Yes | None: root reads the cert files directly |
| Local account that joins the `cfm` group | Yes: can read the token and connect | Gains cert+key access |
| nginx worker RCE | Yes | None: the worker already holds every pair in `_store` |

### The snapshot file

`dump.json` (`0640 root:cfm`) holds the cert+key pairs of every hosted
domain. Unlike the socket it needs no token or live daemon: anything that can
read a file as the `cfm` group gets every key. As above,
`SSLCOLLECTOR_OFFLINE_CACHE = 0` does not remove it.

### Hardening options (not implemented)

Referenced from `socketapi.go` and `sslcollector.lua`:

1. **SO_PEERCRED.** Verify the connecting process's UID with
   `getsockopt(SO_PEERCRED)` (in `ServeSock` / `authOK`) instead of a
   group-readable token. Removes the "another cfm-group process reads the
   token" vector; does nothing against a compromised worker, which already
   holds the keys.
2. **Encrypted snapshot.** Encrypt `dump.json` with a key only the running
   daemon holds (e.g. generated per start under `/run`), handed to workers
   over the socket. The file alone becomes useless; but with the daemon down
   the workers cannot decrypt it, so the warm-restart benefit is lost exactly
   when it matters.

---

## Configuration reference (`cfm.conf`)

| Key | Default | Description |
|-----|---------|-------------|
| `SSLCOLLECTOR_SOCK_ENABLE` | off when absent; the shipped `cfm.conf` sets `1` | Run the unix socket server. Without it the edge gets no certs from CFM. |
| `SSLCOLLECTOR_SOCK_PATH` | `/var/run/sslcollector.sock` | Fixed. The edge Lua connects to this path only (`SOCKS` in `sslcollector.lua`), so the daemon and the `cfm ssl` CLI ignore any other value and log a warning; `cfm config test` lists it under "ignored values". (`cfm ssl --sock` still points one CLI run elsewhere.) |
| `SSLCOLLECTOR_SOCK_TOKEN` | `placeholder` | Read only to create `/var/lib/cfm/secrets/sslcollector_sock_token` when that file is missing. Keep the line with `placeholder`. |
| `SSLCOLLECTOR_SOCK_PEM_TTL` | `10m` | `/cert` PEM cache TTL per entry. |
| `SSLCOLLECTOR_SOCK_PEM_MAX` | `50000` | `/cert` PEM cache size; when full the whole cache is cleared. |
| `SSLCOLLECTOR_OFFLINE_CACHE` | `1` | Workers load `dump.json` at startup. `0` stops that only (see above). |
| `SSLCOLLECTOR_LUA_TOKEN_PATH` | — | Parsed but ignored: the token mirror is always `/var/lib/cfm/lua/cfm_token.lua`. |

Daemon environment variables: `CFM_SSLCOLLECTOR_FORCE_SNAPSHOT=1` (bypass the
snapshot shrink guard), `CFM_SSLCOLLECTOR_RELOAD_EDGE_ON_READY=0` (no edge
reload on first ready).

## Diagnostics

```bash
cfm ssl stats [--json]          # pairs, exact hosts, wildcards, sources
cfm ssl dump <host> [--json]    # what the disk scan and the daemon index hold for a host
cfm ssl refresh                 # ask the daemon to Refresh (POST /refresh)
```

Each first asks the daemon to Refresh (skip with `--no-daemon-refresh`) and
runs its own scan in the CLI process. That scan only reads the cert files:
it never writes `dump.json`, which is the daemon's. On the edge, the `meta:*` keys in the
`sslcache` shared dict (listed at the top of `sslcollector.lua`) and the
`[sslcollector]` lines in the edge error log show each worker's state.

## Related files

| Path | Purpose |
|------|---------|
| `internal/sslcollector/socketapi.go` | Unix socket HTTP server, endpoint handlers |
| `internal/sslcollector/lifecycle.go` | Socket start/stop wired to config; token and Lua config mirrors |
| `internal/sslcollector/token.go` | Lua file writers (`0640 root:cfm`) |
| `internal/sslcollector/scan.go`, `sources.go`, `watcher.go` | Refresh, scanners, fsnotify watcher |
| `internal/sslcollector/dumpall.go`, `snapshot.go` | Payload writer, `/dumpall` build, snapshot write and guard |
| `internal/sslcollector/reload_edge.go` | One edge reload on first ready |
| `configs/lua/sslcollector.lua` | Edge module (background poll + handshake hook) |
| `configs/openresty.conf`, `configs/angie.conf` | `init_worker_by_lua_block` bootstrap + `ssl_certificate_by_lua_block` wiring |
| `/var/lib/cfm/lua/cfm_token.lua` | Token mirror (`0640 root:cfm`) |
| `/var/lib/cfm/lua/cfm_sslcollector_config.lua` | Runtime flags for the workers (`offline_cache`; `0640 root:cfm`) |
| `/var/lib/cfm/sslcollector/dump.json` | Snapshot (`0640 root:cfm`, contains key material) |

---

## Panel listeners

The HTTPS panel listeners in `configs/cfm-panel-listeners.conf.in` (12083,
12087, 12096 and the DirectAdmin 12222; rendered for Angie or OpenResty by
the installers and the package's proxy-config deploy) each carry:

- the static fallback cert `ssl_certificate /var/lib/cfm/certs/selfsigned/fullchain.pem;`
  + `ssl_certificate_key /var/lib/cfm/certs/selfsigned/privkey.pem;`
- the dynamic hook `ssl_certificate_by_lua_block { local sc = require "sslcollector"; sc.set_cert() }`
- `ssl_protocols TLSv1.2 TLSv1.3`, as on the main HTTPS listener.

Until a worker has loaded the certs (startup) a handshake gets the
self-signed fallback; after that SNI selects the domain's certificate.
`scripts/tests/check_angie_panel_ssl_hooks.sh` fails if a `listen … ssl`
panel server block lacks either fallback directive or the hook (it is not in
the CI gate list; run it after editing the template).
