# Privileged Exploit Path Audit (2026-04-15)

> Updated after removal of the `internal/vhostmap` subsystem.

## Scope and method
This audit focused on **reachable privileged sinks** and traced input/control flow backward from those sinks, prioritizing realistic exploit chains over theoretical code smells.

Primary sink classes reviewed:
- command execution (`exec.Command`, `sh -c`, service control)
- privileged file writes under `/etc`, `/run`, `/var`, `/usr/local/openresty`
- privileged unix sockets and localhost APIs
- nftables/system state mutation paths
- token/cookie/auth boundaries guarding privileged operations

---

## 1) Privileged attack surface map

### A. Network/API-triggered privileged actions
- `/unblock` endpoint can remove IPs from nft + trigger additional cleanup flows (`csf`, `fail2ban`, `imunify360-agent`) through `unblock.Do` as root context. (Auth middleware governs access globally.)
- `/api/v1/firewall/block` directly adds block entries in firewall backend.
- `/api/v1/system/*` executes local `cfm` commands and returns output.
- Webdetector + challenge API endpoints eventually influence firewall/challenge behavior through in-process and nft sinks.

### B. Local unix sockets with privileged impact
- SSL collector unix socket (`/var/run/sslcollector.sock`) serves certificate metadata and PEM/private-key material.
- Nginx bridge unix socket (`/var/run/cfm_nginx.sock` by config) drives challenge/block/observe state.
- Panel auth unix socket (`/var/run/cfm-auth.sock`) mints actor assertions/scoped plugin tokens.

### C. Privileged file mutation paths
- sysctl writer mutates `/proc/sys/...` and `/etc/sysctl.d/99-cfm.conf`.
- token writers patch config/token artifacts under privileged paths.
- agent file sync writes to selected privileged directories.

### D. Command execution sinks
- direct `exec.Command(...)` in many code paths (nft/system status helpers/unblock integrations)

---

## 2) Root-sensitive sink inventory (key/high-risk subset)

1. `internal/sslcollector/socketapi.go`
   - `/cert` and `/dumpall` read and return `key_pem` from disk.
   - `ServeSock` binds unix socket with group-accessible permissions.

2. `internal/webdetector/nginx_bridge.go`
   - privileged socket control plane for challenge/block/observe/upload.
   - upload source-path checks are lexical (`Clean`/prefix), not symlink-resolved.

3. `internal/apiserver/unblock_endpoint.go` + `internal/unblock/unblock.go`
   - reachable unblock sink mutating nft + invoking system tools.

---

## 3) Reachable exploit chains and ranked findings

## Finding 1: Group-readable SSLCollector token + group-accessible socket enables private-key extraction
- **Severity:** High
- **Confidence:** High
- **Type:** local low-priv user -> privileged secret access (root-equivalent TLS key material)
- **Locations:**
  - token written group-readable for `cfm` group (`0640`) in `WriteLuaToken`
  - socket exposed as `0660` and chowned to configured group
  - socket endpoints return `key_pem`

### Attacker starting point
A local low-priv principal that can read `cfm_token.lua` (group `cfm`) or otherwise obtain socket token, and can connect to the unix socket as that group.

### Exploit path
1. Read token from Lua token file (explicitly created group-readable for OpenResty workers).
2. Connect to `/var/run/sslcollector.sock` (group-readable/writable socket).
3. Call `/cert?host=...` or `/dumpall` with `X-SSLCollector-Token`.
4. Receive certificate **and private key PEM** (`key_pem`) for one or many hosts.

### Privileged sink reached
Root-only secret disclosure path (`os.ReadFile(e.KeyPath)` returned over privileged local socket API).

### Impact
- Full theft of TLS private keys for hosted domains/services.
- Enables long-lived MITM/impersonation and decryption of future traffic (depending on key/cipher suite/rotation).
- In practical control terms, this is frequently “root-equivalent” for service trust and appliance integrity.

### Preconditions
- Local access in socket/token trust domain (e.g., compromised worker process in `cfm` group).

### Minimal remediation
- Remove private-key return from runtime API (serve cert only; key handling in-memory only for strict caller).
- Enforce peer credential checks (`SO_PEERCRED`) instead of bearer token in group-readable file.
- Tighten permissions: dedicated service account + `0600` token material where possible.
- Add host allowlist/rate-limits and split privileged `/dumpall` to root-only maintenance path.

### Regression test to add
- Integration test: process in allowed group can/cannot call key-return endpoints under new policy.
- Assert `/dumpall` never returns `key_pem` in normal mode.

---

## Finding 2: Nginx upload source path validation is lexical only; symlink-in-allowed-dir can bypass intent
- **Severity:** Medium
- **Confidence:** Medium
- **Type:** local/service-compromise -> privileged file read primitive (limited)
- **Location:** `internal/webdetector/nginx_bridge.go` (`validateUploadSourcePath`, `validatePathWithinDir`, `copyFile`).

### Attacker starting point
Ability to call bridge upload endpoint with valid token (typically same trust domain as OpenResty worker).

### Exploit path
1. Place symlink inside allowed base (`/tmp`, `/var/tmp`, etc.) pointing to sensitive file.
2. Submit upload request referencing symlink path.
3. Prefix check passes because it validates only lexical path prefix.
4. `copyFile` opens and reads symlink target as daemon user.

### Privileged sink reached
Root-context file read operation on attacker-chosen target via symlink traversal.

### Impact
- Sensitive file read may feed malware scanner flow/log side channels.
- Primitive is weaker than direct exfil, but violates trust boundary and can compose with other bugs.

### Preconditions
Bridge token/socket access.

### Minimal remediation
- Resolve and enforce `EvalSymlinks`-based containment within allowed directories.
- Open with anti-symlink controls (`O_NOFOLLOW`) where supported.
- Consider removing `/tmp` from allowed sources or use dedicated root-owned staging dir only.

### Regression test to add
- Symlink-in-`/tmp` pointing outside allowed tree must be rejected.

---

## 4) Remote / local exploitability summary

### Remote -> root
- No direct unauthenticated remote->root chain was confirmed in this pass.
- Auth middleware appears to gate privileged HTTP endpoints before sink execution.

### Remote -> privileged action (non-shell)
- Authenticated API users/tokens can drive firewall state by design.
- This is expected behavior, but impact is root-equivalent operationally and should be tightly scoped.

### Local low-priv -> root/privileged takeover
- Confirmed high-risk local chain for privileged secret extraction via sslcollector socket/token model.
- Additional local abuse surface exists via nginx upload source-path symlink handling in the bridge path.

### Config-dependent -> root
- No current high-confidence config-dependent root chain was confirmed after vhostmap removal.

### Authenticated-admin misuse only
- Many sinks are intended admin operations; treated as expected unless guardrails are weak.

---

## 5) Recommended hardening priorities
1. **Immediate:** remove key material return and strengthen sslcollector authentication/authorization boundary.
2. **Short-term:** normalize privileged path validation to symlink-safe canonical checks.
3. **Ongoing:** add abuse-focused tests (symlink races, token theft simulation, scoped auth bypass attempts).
