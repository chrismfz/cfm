# Sketch — the `ngm_auth` detector (CFM side)

> First-slice design, not merged code. Companion to `docs/ngm-integration-map.md`
> §D. This is the smallest, lowest-risk, immediately-useful CFM slice of the NGM
> integration: a log-tail detector for **abusive NGM control-panel logins**,
> because NGM already writes the input file *for us*.

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
  `bad_mailbox_login`, `session_create`), `RATELIMIT`, `MFA_FAILURE`,
  `TOKEN_FAIL`, `TOKEN_IP_REJECT`.
- **Ignore** (audit/lifecycle noise): `SUCCESS`, `LOGOUT`, `MFA_REQUIRED`,
  `MFA_SUCCESS`, `MFA_ENABLE`, `MFA_DISABLE`, `DAV_*`, `CONTAINER_*`, and any
  future audit verb. Key on an **allowlist** of abuse events, not "anything not
  SUCCESS" — new audit verbs get added over time and must not become false bans.

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
- **`TOKEN_FAIL` / `TOKEN_IP_REJECT`** are API-token brute / CIDR-violation
  events (`role=token`) — a distinct bucket from interactive login.

## Model it on `cpanel/login.go`

The cPanel login detector (`internal/detectors/cpanel/login.go` +
`cpanel_register.go`) is the exact template — same shape, simpler parser (NGM's
line is key=value, not three positional regex variants). Reuse verbatim: the
`core` window primitives (`SlidingCounter`, `AlertGate`, `SampleRing`), the
`FileTailer` source with inode/offset resume (`State` + `FileStateKey`), the
`PeriodicDetector`/`PositionAware` method set, and the enrichment (`enrich` +
PTR). Only `processLine` and the thresholds differ.

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
    AdminFailPerIP  int // default 5  — stricter for role=admin (mirrors cpanel ROOT_IP)
    TokenFailPerIP  int // default 10 — API-token brute (TOKEN_FAIL / TOKEN_IP_REJECT)

    UseEnrich, UsePTR bool
    EnrichDirs        []string
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
    enr      *enrich.Enricher
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
    "TOKEN_FAIL": true, "TOKEN_IP_REJECT": true,
}

func (a *Auth) processLine(now time.Time, line string) {
    f := kvLine(line)
    ev := strings.ToUpper(f["event"])
    if !abuseEvents[ev] {
        return
    }
    ip, user, role := f["ip"], strings.ToLower(f["user"]), strings.ToLower(f["role"])

    // API-token brute is its own bucket (role=token, may have no user).
    if ev == "TOKEN_FAIL" || ev == "TOKEN_IP_REJECT" {
        if ip != "" { a.bump(now, "TOKEN|ip", ip, line) }
        return
    }
    // Interactive login abuse (FAIL / RATELIMIT / MFA_FAILURE).
    if ip != "" {
        if role == "admin" && a.cfg.AdminFailPerIP > 0 {
            a.bump(now, "ADMIN|ip", ip, line)   // stricter bucket, like cpanel ROOT
        } else {
            a.bump(now, "AUTHFAIL|ip", ip, line)
        }
    }
    if user != "" && user != "-" {
        a.bump(now, "AUTHFAIL|user", user, line)
    }
}

func (a *Auth) thresholdAndKey(kindKey, raw string) (limit int, kind, base string) {
    switch kindKey {
    case "AUTHFAIL|ip":   return a.cfg.AuthFailPerIP,   "NGM/AUTHFAIL", raw
    case "AUTHFAIL|user": return a.cfg.AuthFailPerUser, "NGM/AUTHFAIL", raw
    case "ADMIN|ip":
        lim := a.cfg.AdminFailPerIP
        if lim <= 0 { lim = a.cfg.AuthFailPerIP }
        return lim, "NGM/ADMIN", raw
    case "TOKEN|ip":
        lim := a.cfg.TokenFailPerIP
        if lim <= 0 { lim = a.cfg.AuthFailPerIP }
        return lim, "NGM/TOKEN", raw
    }
    return 0, "", raw
}
```

`bump`, `flush`, `enrichDisplay` and the helpers are copied unchanged from
`cpanel/login.go` (they only touch the shared `core` primitives). Alert `Extra`
carries `ip`/`user`, `window`, `cooldown`, `limit`, `log` — same keys the sink
already understands.

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
            UseEnrich: kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true)),
            UsePTR:    kvBool(kv, "PTR",    kvBool(global, "PTR",    true)),
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
ADMIN_IP      = 5          ; stricter for role=admin
TOKEN_IP      = 10         ; API-token brute (TOKEN_FAIL / TOKEN_IP_REJECT)
BLOCK         = dryrun     ; watch-first; flip to a TTL ban after burn-in
```

## Notes / gotchas

- **`BLOCK = dryrun` ships first** — same burn-in discipline as every new detector
  (CLAUDE.md §6). Flip to a soft TTL ban only after watching real traffic.
- **Rotation:** NGM opens the file per-write and its logrotate uses plain rename
  (a new inode); the `FileTailer` resume already handles inode change. No
  `copytruncate` here (that's the php-fpm/panel logs, not auth.log).
- **`kvLine` must be quote-aware** — `reason="…"` can contain spaces; don't
  `strings.Fields`. NGM sanitises control chars out on the write side, so a
  hostile username can't forge a second line, but still parse defensively.
- **Presence self-disable:** unlike cPanel's `login_log`, `/var/log/ngm/auth.log`
  only exists on an NGM host. Follow the `srcresolve`/presence pattern
  (`mta_presence.go` style) so the section idles cleanly on non-NGM boxes rather
  than erroring — or simply let the `FileTailer` no-op on a missing file (it
  already tolerates absence), and gate `ENABLED` from NGM detection
  (`/etc/ngm/config.yaml`) in the rendered config.
- **Lua/id parity, CHANGELOG, adversarial review:** this is a Go-only detector
  (no edge Lua), so no `waf_rule_ids` parity; still carries a `[Unreleased]`
  CHANGELOG entry and the pre-PR adversarial review per CLAUDE.md §3/§9.

> See also: `docs/ngm-integration-map.md` (§D detectors, the rspamd/php-fpm gaps),
> `docs/DETECTORS.md`, `internal/detectors/cpanel/login.go` (the template),
> `internal/detectors/registry.go` (`kv*` helpers, `Factory`).
