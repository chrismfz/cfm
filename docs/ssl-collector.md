# SSL Collector

The SSL Collector (`sslcollector`) is the subsystem that distributes TLS
certificate and private-key material from the cfm daemon to OpenResty/Angie
nginx workers so they can perform dynamic SNI-based certificate selection at
TLS handshake time.

---

## Why it exists

OpenResty and Angie support `ssl_certificate_by_lua_block`, a hook that runs
on every incoming TLS handshake.  The hook can inspect the SNI hostname and
set an arbitrary certificate+key pair from Lua code.  This lets cfm act as a
dynamic certificate distributor: the web server serves whatever certificate
cfm knows about for a given domain without requiring a static nginx config
reload.

---

## Architecture

```
cfm daemon (root)
  │
  │  unix socket 0660 root:cfm
  │  /var/run/sslcollector.sock
  │
  ▼
OpenResty/Angie worker (cfm user)
  │
  │  init_worker_by_lua_block  ← can yield / do I/O
  │    start_background()
  │      load_from_snapshot()  ← warms store from disk (if offline cache enabled)
  │      do_dumpall()          ← fetches ALL cert+key pairs via /dumpall
  │      poll_stats()          ← starts background poll loop
  │
  │  ssl_certificate_by_lua_block  ← NO yield, NO I/O
  │    M.set_cert()
  │      _store["e:" .. sni]   ← worker-local table lookup only
  │      ssl.set_cert(der)
  │      ssl.set_priv_key(der)
  ▼
TLS handshake completes with the domain-specific certificate
```

### Key constraint: no I/O in the TLS handshake path

The `ssl_certificate_by_lua_block` handler (`M.set_cert()`) is explicitly
**QUIC-safe**: it performs no socket I/O and never yields.  This is required
for HTTP/3 over QUIC, where the TLS handshake runs in a tight UDP path.  All
cert+key pairs must be pre-loaded into the worker-local `_store` table before
the first handshake for each domain.  The background timer (`do_dumpall()`)
handles this loading; the handshake path only reads from `_store`.

This is why the `/dumpall` endpoint exists and why it returns both `cert_pem`
and `key_pem` in bulk: the entire certificate inventory must be atomically
available in each worker before any handshake can be served.

### Worker-local store (not shared dict)

Cert+key pairs are stored in a worker-local Lua table (`_store`), not in
`ngx.shared.sslcache`.  Shared dicts are accessible to any Lua code in the
same OpenResty process via `dict:get_keys()` + `dict:get()`.  A worker-local
table is only reachable by code that holds a reference to this module, which
is a significantly smaller blast radius for key material enumeration.

---

## Socket authentication

The socket is authenticated with a bearer token carried in the
`X-SSLCollector-Token` HTTP header.  The token is:

- Auto-generated at daemon startup if absent or a known placeholder (see
  `internal/sslcollector/token.go:ValidateOrGenerateToken`).
- Written atomically to `/var/lib/cfm/lua/cfm_token.lua` at mode `0640`
  (owner `root`, group `cfm`).
- Compared in constant time (`crypto/subtle.ConstantTimeCompare`) on every
  request to prevent timing side-channels.

---

## Socket endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/dumpall` | GET | Returns all cert+key pairs (exact + wildcard). Used by workers at init and on version change. |
| `/cert?host=X` | GET | Returns cert+key for a single hostname. |
| `/stats` | GET | Returns version string and health metadata. Polled every 5–20 min. |
| `/refresh` | POST | Forces an immediate re-scan of the certificate store. |
| `/dump?host=X` | GET | Returns raw `Entry` metadata for a host (no PEM). |

---

## Offline snapshot (SSLCOLLECTOR_OFFLINE_CACHE)

When a worker starts, it first tries to warm its `_store` from a disk snapshot
before calling `/dumpall` over the live socket.  This means nginx can serve
all previously known certificates even if cfm is temporarily unavailable
(e.g. during a cfm upgrade or crash recovery).

The snapshot is written to `/var/lib/cfm/sslcollector/dump.json` at mode
`0640` (root:cfm) atomically via a write-tmp + rename sequence every time a
live `/dumpall` succeeds and the payload contains a `Version` field.

**To disable the offline snapshot:**

```ini
# cfm.conf
SSLCOLLECTOR_OFFLINE_CACHE = 0
```

When disabled:
- Workers do not write the snapshot file after `/dumpall`.
- Workers do not read the snapshot file at startup.
- If cfm is unreachable at nginx startup, workers serve the fallback cert
  (the static `ssl_certificate` directive in openresty.conf / angie.conf)
  until the first successful `/dumpall` completes.

The cfm systemd service has `Restart=always`, so the window of fallback-cert
usage is typically a few seconds after any cfm crash.

---

## Security model

### Trust boundary

The `cfm` OS group is the trust boundary.  The group contains exactly:

- The cfm daemon process (running as `root`) — writes tokens and sockets.
- OpenResty/Angie nginx worker processes (running as `cfm` user, `nologin`
  shell) — read the token and connect to the socket.

No other service, user, or process should be in the `cfm` group.  This is
enforced by `install-openresty.sh` and `install-angie.sh`, which create the
`cfm` system user with `/sbin/nologin`.

### Realistic attack paths

| Scenario | Can reach socket? | Incremental risk from socket |
|----------|------------------|------------------------------|
| Remote attacker, unauthenticated | No — socket is local-only | None |
| Remote attacker, authenticated API user | No — API does not expose the socket | None |
| Local attacker with root | Yes — root can do anything | None — root can read cert files directly |
| Local attacker who joins cfm group | Yes — can read token + connect | Gains cert+key API access |
| nginx RCE exploit | Yes — code runs inside nginx worker | None incremental — worker already holds all keys in `_store` memory; SO_PEERCRED would still pass |

The practical conclusion: the socket does not materially expand the blast
radius of any realistic attack class given the current group membership policy.

### The snapshot file

The on-disk snapshot (`/var/lib/cfm/sslcollector/dump.json`, mode `0640`)
contains cert+key pairs for all hosted domains.  Unlike the socket (which
requires an active token+connection), the file is a passive persistent
artifact.  If something with cfm-group access can exfiltrate a file (e.g. a
file-read vulnerability in a future service added to the group), the snapshot
exposes all keys without requiring any socket interaction.

This is the primary reason `SSLCOLLECTOR_OFFLINE_CACHE = 0` exists as an
option for operators who prefer availability-on-demand over warm-restart
availability.

---

## Future hardening options

### 1. SO_PEERCRED verification

Replace the group-readable bearer token with kernel-verified process
credentials.  On Linux, `getsockopt(SO_PEERCRED)` on a unix socket returns
the UID, GID, and PID of the connecting process.  The socket server could
verify that `uid == <nginx worker uid>` before serving any response, without
needing a token file at all.

**What this improves:** eliminates the "another cfm-group process obtains the
token file and calls the socket" vector.

**What this does NOT improve:** a compromised nginx worker process already
holds all cert+key pairs in its `_store` memory.  SO_PEERCRED would pass for
a request originating inside that process, so it provides no protection
against a nginx RCE exploit.

**Implementation note:** requires changes to `internal/sslcollector/socketapi.go`
(`ServeSock` / `authOK`) to extract peer credentials from the `net.UnixConn`
via `syscall.GetsockoptUcred`.

### 2. Encrypted offline snapshot

Encrypt the snapshot file with a key that only the running cfm daemon holds
(e.g. an ephemeral key generated at startup and held only in memory, or a
key stored at `0600` root-only).  Workers would request the decryption key
from the cfm daemon socket at startup, decrypt the file locally, then discard
the key.

**What this improves:** the on-disk file becomes useless without the running
daemon.  Exfiltrating `dump.json` alone yields nothing.

**What this does NOT improve:** if the daemon is down, workers cannot get the
decryption key, so the fallback behavior is the same as `OFFLINE_CACHE = 0`.
The availability benefit of the snapshot is only preserved if the daemon is
available anyway.

**Implementation note:** this option is most useful in combination with
`OFFLINE_CACHE = 1` for operators who want both warm-restart availability and
protection against snapshot exfiltration.  A symmetric key (e.g. AES-256-GCM)
generated fresh on each cfm start and written to a `/run/cfm/snapshot.key`
tmpfs path (root-only, lost on reboot) would achieve this.

---

## Configuration reference

| Key | Default | Description |
|-----|---------|-------------|
| `SSLCOLLECTOR_SOCK_ENABLE` | `1` | Enable the unix socket server |
| `SSLCOLLECTOR_SOCK_PATH` | `/var/run/sslcollector.sock` | Socket path |
| `SSLCOLLECTOR_SOCK_TOKEN` | *(auto-generated)* | Bearer token; weak/placeholder values are replaced at startup |
| `SSLCOLLECTOR_SOCK_PEM_TTL` | `10m` | In-process PEM cache TTL per entry |
| `SSLCOLLECTOR_SOCK_PEM_MAX` | `50000` | Maximum PEM cache entries before eviction |
| `SSLCOLLECTOR_OFFLINE_CACHE` | `1` | Write/read on-disk snapshot for warm restart; set to `0` to disable |

## Related files

| Path | Purpose |
|------|---------|
| `internal/sslcollector/socketapi.go` | Unix socket HTTP server, endpoint handlers |
| `internal/sslcollector/token.go` | Token validation, generation, Lua file writers |
| `internal/sslcollector/lifecycle.go` | Start/stop/restart lifecycle wired to config |
| `configs/sslcollector.lua` | OpenResty/Angie Lua module (background poll + handshake hook) |
| `configs/openresty.conf` | `init_worker_by_lua_block` + `ssl_certificate_by_lua_block` wiring |
| `configs/angie.conf` | Same for Angie |
| `/var/lib/cfm/lua/cfm_token.lua` | Auto-generated bearer token (0640 root:cfm) |
| `/var/lib/cfm/lua/cfm_sslcollector_config.lua` | Auto-generated runtime flags (0640 root:cfm) |
| `/var/lib/cfm/sslcollector/dump.json` | Offline snapshot (0640 root:cfm, contains key material) |
| `docs/security/root_compromise_audit_2026-04-15.md` | Privilege audit with Finding 1 (socket key access) |
