# Sketch — the `ngm_auth` detector (CFM side)

> As-built reference for the first code slice (the detector shipped in
> `internal/detectors/ngmauth/`). Companion to `docs/ngm-integration-map.md` §D.
> The smallest, lowest-risk, immediately-useful CFM slice of the NGM integration:
> a log-tail detector for **abusive NGM control-panel logins**, because NGM
> already writes the input file *for us*. The code blocks below are illustrative;
> the package is the source of truth.

## Why this one first

NGM's `internal/web/authfilelog.go` appends every panel auth event to
`/var/log/ngm/auth.log` (default; `security.auth_log`) **expressly** "for an
external detector in the fail2ban family (CFM's ssh/postfix/ftp detectors)". The
format is stable, single-line, quoted key=value, forgery-safe:

```
2026-08-05T17:30:00Z event=FAIL user="bob" ip=1.2.3.4 role=admin reason=bad_password
```

So the detector is pure add: no framework change, no NGM change, and it slots into
the existing OBSERVE→ENFORCE pipeline (the section sink does the nft ban / leniency
/ alerting per the `BLOCK` policy — the detector only emits `core.Alert`).

Scope: this detector covers **panel-login** abuse only (brute force against the
NGM web panel). SSH, mail and FTP on an NGM box are already covered by the
existing `ssh`/`postfix_*`/`dovecot`/`ftpd` detectors; web-request abuse against
customer vhosts is a separate future `ngm_web` detector (the `ngm_access` log),
out of scope here.

## Which events count — auth.log is a combined auth+AUDIT log

**Important:** `/var/log/ngm/auth.log` is not a failures-only file. The same
`authLog(event, …)` choke point emits a rich event vocabulary (verified in
`internal/web/auth.go`), only some of which is abuse signal:

- **Count as abuse** (key on these): `FAIL` (reasons `bad_password`, `lockout`,
  `account_locked`, `reseller_suspended`, `account_suspended`,
  `bad_mailbox_login`, `session_create`), `RATELIMIT`, `MFA_FAILURE`, `DAV_FAIL`
  (WebDAV/CalDAV mailbox auth), `PWRESET_FAILURE`, `RECOVERY_VERIFY_FAILURE`,
  `TOKEN_FAIL`. **`TOKEN_IP_REJECT` is deliberately excluded** — see the token
  bullet below.
- **Ignore** (audit/lifecycle noise): `SUCCESS`, `LOGOUT`, `MFA_REQUIRED`,
  `MFA_SUCCESS`, `MFA_ENABLE`, `MFA_DISABLE`, the audit DAV verbs
  (`DAV_DISCOVERY`/`DAV_HOST`/`DAV_IMPORT_FAIL`), `PWRESET_REQUEST`/`_SENT`/
  `_SUCCESS`, `SERVICE_ENABLE_DENIED`, `CONTAINER_*`, and any future audit verb.
  Key on an **allowlist** of abuse events, not "anything not SUCCESS" — new audit
  verbs get added over time and must not become false bans. (`DAV_FAIL` is an
  *auth* failure and IS counted; only the audit DAV verbs are ignored.)

Two events matter more than a naive "count FAIL":

- **`RATELIMIT` is high-confidence abuse** — NGM's *own* per-source-IP login
  throttle already fired (`auth.go` backoff), i.e. NGM already judged this IP
  abusive. Count it; do not treat it as benign.
- **NGM already does per-account lockout + per-IP throttle** (`IncrementFailedAttempts`
  → `lockout`, `RATELIMIT`). That is app-layer and **per-account, per-box**. This
  detector's distinct value is a **fleet-wide L3/L4 nft ban** of the source IP —
  a second layer, not a duplicate. It also means raw `FAIL` volume *under-counts*
  a sustained attack (later attempts convert to `RATELIMIT`), so thresholds must
  count `RATELIMIT` too, or be set lower than an SSH/cPanel detector would use.
- **`TOKEN_FAIL`** (bad token value, `role=token`) is API-token brute-force — its
  own `TOKEN|ip` bucket, distinct from interactive login. **`TOKEN_IP_REJECT`** (a
  *valid* token presented from a not-yet-allowlisted source IP) is **not** counted:
  NGM already refused it on its own CIDR gate, and a legit token retried from a new
  office/CI egress would otherwise self-ban that IP fleet-wide.

## Model it on `cpanel/login.go`

The cPanel login detector (`internal/detectors/cpanel/login.go` +
`cpanel_register.go`) is the exact template — same shape, simpler parser (NGM's
line is key=value, not three positional regex variants). Reuse verbatim: the
`core` window primitives (`SlidingCounter`, `AlertGate`, `SampleRing`), the
`FileTailer` source with inode/offset resume (`State` + `FileStateKey`), the
`PeriodicDetector`/`PositionAware` method set. Only `processLine` and the
thresholds differ — and, unlike `cpanel/login`, this detector does **no** IP
enrichment of its own: the section sink already decorates IP alerts with a
cached, timeout-bounded PTR/ASN and overwrites the alert `Key`, so a detector-side
`net.LookupAddr` would be redundant and an unbounded-DNS risk on the 2s tick.

### Package `internal/detectors/ngmauth/auth.go` (skeleton)

```go
package ngmauth

// AuthConfig mirrors cpanel.LoginConfig; only the thresholds and the default
// LogPath differ (NGM panel-login instead of cPanel login_log).
type AuthConfig struct {
    Mode    string        // "file" (auth.log is a file; opened per-write, rotate-safe)
    LogPath string        // default /var/log/ngm/auth.log

    Every, Window, Cooldown time.Duration
    SampleLimit             int

    AuthFailPerIP   int // default 25
    AuthFailPerUser int // default 15
    AdminFailPerIP  int // default 5  — stricter for privileged roles admin+reseller (cf. cpanel ROOT_IP)
    TokenFailPerIP  int // default 10 — API-token brute (TOKEN_FAIL only)
}

type Auth struct {
    cfg      AuthConfig
    name     string
    src      core.LineSource
    state    *core.State
    stateKey string
    pending  map[string]pend
    samples  *core.SampleRing
    gate     *core.AlertGate
    counts   *core.SlidingCounter
}

// --- PeriodicDetector / PositionAware: identical to cpanel/login.go ---
// Name(), Every(), ApplyPosition(), Position(), SetState/SetName/SetSource,
// RunOnce() (resume → Open → ReadNext loop → processLine → flush → save pos).
// Copy those verbatim; they are source-agnostic.

// kvLine parses one auth.log line into fields. The line is RFC3339 + space-
// separated key=value with values quoted only when needed (authLogValue on the
// NGM side). A quote-aware scanner — NOT strings.Fields — because reason= can
// carry spaces inside quotes.
func kvLine(line string) map[string]string { /* scan key="…"/key=… tokens */ }

// abuseEvents is the ALLOWLIST of events that count (everything else — SUCCESS,
// LOGOUT, MFA_SUCCESS/ENABLE/DISABLE, DAV_*, CONTAINER_*, … — is audit noise and
// is ignored, so a new audit verb can never become a false ban).
var abuseEvents = map[string]bool{
    "FAIL": true, "RATELIMIT": true, "MFA_FAILURE": true,
    "DAV_FAIL": true, "PWRESET_FAILURE": true, "RECOVERY_VERIFY_FAILURE": true,
    "TOKEN_FAIL": true,
    // TOKEN_IP_REJECT intentionally omitted (valid token from a new IP → self-ban).
}

func (a *Auth) processLine(now time.Time, line string) {
    f := kvLine(line)
    ev := strings.ToUpper(f["event"])
    if !abuseEvents[ev] {
        return
    }
    ip, user, role := f["ip"], strings.ToLower(f["user"]), strings.ToLower(f["role"])

    // API-token brute is its own bucket (role=token, may have no user).
    if ev == "TOKEN_FAIL" {
        if ip != "" { a.bump(now, "TOKEN|ip", ip, line) }
        return
    }
    // Interactive / credential-verification abuse (FAIL / RATELIMIT / MFA_FAILURE
    // / DAV_FAIL / PWRESET_FAILURE / RECOVERY_VERIFY_FAILURE).
    if ip != "" {
        a.bump(now, "AUTHFAIL|ip", ip, line)           // every failure counts to the per-IP total
        if (role == "admin" || role == "reseller") && a.cfg.AdminFailPerIP > 0 {
            a.bump(now, "ADMIN|ip", ip, line)           // AND the stricter privileged bucket (admin+reseller)
        }
    }
    if user != "" && user != "-" {
        a.bump(now, "AUTHFAIL|user", user, line)
    }
}

func (a *Auth) threshold(kindKey string) (limit int, kind string) {
    switch kindKey {
    case "AUTHFAIL|ip":   return a.cfg.AuthFailPerIP,   "NGM/AUTHFAIL"
    case "AUTHFAIL|user": return a.cfg.AuthFailPerUser, "NGM/AUTHFAIL"
    case "ADMIN|ip":
        lim := a.cfg.AdminFailPerIP
        if lim <= 0 { lim = a.cfg.AuthFailPerIP }
        return lim, "NGM/ADMIN"
    case "TOKEN|ip":
        lim := a.cfg.TokenFailPerIP
        if lim <= 0 { lim = a.cfg.AuthFailPerIP }
        return lim, "NGM/TOKEN"
    }
    return 0, ""
}
```

`bump` and `flush` follow `cpanel/login.go` (they only touch the shared `core`
primitives), with two differences: there is **no** `enrichDisplay` (IP decoration
is the sink's job), and a per-**user** alert sets `Extra[core.ExtraIPScope] =
core.IPScopeHost` so the sink treats it as a per-account notify rather than banning
an arbitrary sample IP (a single-source attack is already caught by `AUTHFAIL|ip`).
Alert `Extra` carries `ip` (IP buckets) / `user`+`ip_scope` (user bucket),
`window`, `cooldown`, `limit`, `log` — keys the sink understands.

### Registration `internal/detectors/ngmauth_register.go`

```go
func init() {
    meta.Register(meta.DetectorMeta{
        TypeKey:     "ngm_auth",
        Title:       "NGM panel login",
        Description: "Detect abusive NGM control-panel login attempts.",
        DefaultsTemplate: map[string]string{
            "ENABLED": "1", "LOG_PATH": "/var/log/ngm/auth.log",
            "EVERY": "2s", "WINDOW": "10m", "COOLDOWN": "20m", "BLOCK": "dryrun",
        },
        LeniencySupported: true,
    })
    Register("ngm_auth", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
        cfg := ngmauth.AuthConfig{
            Mode:    "file",
            LogPath: kvStrClean(kv, "LOG_PATH", "/var/log/ngm/auth.log"),
            Every:    kvDur(kv, "EVERY",    kvDur(global, "DEFAULT_EVERY",    2*time.Second)),
            Window:   kvDur(kv, "WINDOW",   kvDur(global, "DEFAULT_WINDOW",   10*time.Minute)),
            Cooldown: kvDur(kv, "COOLDOWN", kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)),
            SampleLimit:     kvInt(kv, "SAMPLE_LIMIT",  10),
            AuthFailPerIP:   kvInt(kv, "AUTHFAIL_IP",   25),
            AuthFailPerUser: kvInt(kv, "AUTHFAIL_USER", 15),
            AdminFailPerIP:  kvInt(kv, "ADMIN_IP",       5),
            TokenFailPerIP:  kvInt(kv, "TOKEN_IP",      10),
        }
        d := ngmauth.New(cfg)
        d.SetName(section)
        d.SetSource(core.NewFileTailer(cfg.LogPath))
        if ngmState != nil {
            d.SetState(ngmState, core.FileStateKey(section, cfg.LogPath))
        }
        return d, nil
    })
}
```

### Reference config — `[ngm_auth]` in `configs/detectors.conf`

Mirror the `[cpanel]` section (derived from the same `DefaultsTemplate`):

```ini
[ngm_auth]
ENABLED       = 1
EVERY         = 2s
WINDOW        = 10m
COOLDOWN      = 20m
LOG_PATH      = /var/log/ngm/auth.log
AUTHFAIL_IP   = 25
AUTHFAIL_USER = 15
ADMIN_IP      = 5          ; stricter, for privileged roles (admin + reseller)
TOKEN_IP      = 10         ; API-token brute (TOKEN_FAIL only)
BLOCK         = dryrun     ; watch-first; flip to a TTL ban after burn-in
```

## Notes / gotchas

- **`BLOCK = dryrun` ships first** — same burn-in discipline as every new detector
  (CLAUDE.md §6). Flip to a soft TTL ban only after watching real traffic.
- **False-positive profile to watch during burn-in:** the interactive bucket now
  also counts `DAV_FAIL`, `PWRESET_FAILURE`, `RECOVERY_VERIFY_FAILURE` and
  `RATELIMIT`. DAV/mail clients and password-reset flows **auto-retry**, so a
  stale-password device or a NAT/office egress can accumulate failures far faster
  than an interactive SSH/cPanel login would — `AUTHFAIL_IP = 25` may be too low
  there. Watch `DAV_FAIL`/`RATELIMIT` volume per source before arming and tune
  `AUTHFAIL_IP` to the fleet (that is exactly what the dryrun window is for).
- **Privileged bucket = admin + reseller.** A reseller administers many customer
  accounts, so it feeds the stricter `ADMIN_IP` bucket alongside `admin`; a plain
  customer (`role=user`) and mailbox failures do not. A sustained single-IP
  privileged brute can emit `NGM/ADMIN` + `NGM/AUTHFAIL` (per-IP) + a host-scoped
  per-user notify — accepted noise (the extra nft ban is a no-op).
- **Rotation:** NGM opens the file per-write and its logrotate uses plain rename
  (a new inode); the `FileTailer` resume already handles inode change. No
  `copytruncate` here (that's the php-fpm/panel logs, not auth.log).
- **`kvLine` must be quote-aware** — `reason="…"` can contain spaces; don't
  `strings.Fields`. NGM sanitises control chars out on the write side, so a
  hostile username can't forge a second line, but still parse defensively.
- **Presence / non-NGM hosts:** `/var/log/ngm/auth.log` only exists on an NGM
  host. The shipped `[ngm_auth]` ships `ENABLED = 1` (consistent with `[cpanel]`,
  `[dovecot]`, etc., which also ship enabled and idle when their log/service is
  absent): the `FileTailer` tolerates a missing file, so each tick is a cheap
  `Open` that fails and no-ops — no alerts, no spam. A future `srcresolve`/presence
  gate (`mta_presence.go` style) could self-disable it at render time, but that is
  not required for correctness.
- **Lua/id parity, CHANGELOG, adversarial review:** this is a Go-only detector
  (no edge Lua), so no `waf_rule_ids` parity; still carries a `[Unreleased]`
  CHANGELOG entry and the pre-PR adversarial review per CLAUDE.md §3/§9.

> See also: `docs/ngm-integration-map.md` (§D detectors, the rspamd/php-fpm gaps),
> `docs/DETECTORS.md`, `internal/detectors/cpanel/login.go` (the template),
> `internal/detectors/registry.go` (`kv*` helpers, `Factory`).
