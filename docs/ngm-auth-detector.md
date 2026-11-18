# The `ngm_auth` detector (NGM panel logins)

Bans sources that brute-force the NGM control panel. NGM (the operator's own
hosting panel, `chrismfz/ngm`) appends every panel auth event to a file
written for an external fail2ban-family detector; this detector tails it.
Code: `internal/detectors/ngmauth/auth.go`, registration
`internal/detectors/ngmauth_register.go`, reference config `[ngm_auth]` in
`configs/detectors.conf`. The NGM side of the integration:
`ngm/docs/cfm-integration-map.md`.

Scope: panel, DAV and API-token logins only. SSH, mail and FTP on an NGM box
are the `ssh` / `postfix_*` / `dovecot` / `ftpd` detectors' job.

What it adds over NGM's own defences: NGM already locks accounts and throttles
logins per source IP, per box, at the app layer. This detector turns that into
an nft ban of the source IP, a
second layer, not a duplicate.

## Input

`LOG_PATH` (default `/var/log/ngm/auth.log`, NGM's `security.auth_log`). One
line per event, an RFC3339 timestamp then `key=value` fields. NGM writes `ip=`
first and always quotes `user` and `reason`, with quotes, whitespace and
control characters stripped from inside them:

```
2026-08-05T17:30:00Z ip=1.2.3.4 event=FAIL role=admin user="bob" reason="bad_password"
```

The parser (`kvLine`) is quote-aware: a quoted value is read whole, so text
inside `user="…"` or `reason="…"` cannot be taken for another field. A missing
file (a non-NGM host) is a no-op each tick, so the shipped section is enabled
everywhere and idle where NGM is absent. NGM opens the file per write and
rotation renames it; the file tailer's inode/offset resume follows the new
file.

## Which events count

The file is a combined auth + audit log. The detector counts an **allowlist**
of credential-failure events (`abuseEvents`) and ignores every other verb, so
a new NGM audit verb can never become a false ban:

| Event | Bucket |
|---|---|
| `FAIL`, `RATELIMIT`, `MFA_FAILURE`, `DAV_FAIL`, `PWRESET_FAILURE`, `RECOVERY_VERIFY_FAILURE` | interactive: per IP, per user, and per IP privileged when `role` is `admin` or `reseller` |
| `PASSWORD_CHANGE_FAIL`, `MFA_DISABLE_FAIL`, `RECOVERY_SET_FAIL` | interactive, as above, except the `account_disabled` / `account_suspended` reasons |
| `TOKEN_FAIL` | API token: per IP only |

- `RATELIMIT` means NGM's own per-IP throttle already fired: counted. A
  sustained attack turns later attempts from `FAIL` into `RATELIMIT`, so `FAIL`
  alone would under-count it.
- The `*_FAIL` step-up verbs (NGM's `stepUp` / `mailboxStepUp`) are a
  logged-in session failing the re-authentication for a password change,
  turning 2FA off or setting a recovery address: a hijacked session guessing
  the password. NGM bounds them itself (the panel's on the login form's
  failed-attempt counter and lockout, the mailbox's on its own step-up
  budget); this detector counts them like a failed login. Their `account_disabled` /
  `account_suspended` reasons refuse on account state, not on a guess, and
  are skipped.
- `TOKEN_IP_REJECT` (a **valid** token from a source not yet on the token's
  CIDR allowlist) is deliberately not counted: NGM already refused it, and a
  legitimate token retried from a new office or CI egress would otherwise get
  that address banned.
- `API_ACCOUNT_DENIED` (a **valid** API token asking for an account it does
  not own) is not counted: an authorization refusal, not a credential guess,
  and a misconfigured integration would loop on it.
- `DYNDNS_DENY` (reason `badauth`) is not counted. NGM writes the same line
  for a wrong token and for a suspended account's valid one, and the router
  keeps polling: ddclient updates each hostname separately, so a suspended
  customer with three hostnames on a one-minute schedule makes 30 a window and
  would be banned fleet-wide. The tokens are random, so guessing one is not a
  practical attack. It can count once NGM gives the suspended case its own
  reason.
- `internal/detectors/ngmauth/testdata/ngm_auth_events.txt` classifies every
  event NGM emits. `TestNGMEventFixture` pins it to the allowlist, and with
  `NGM_SRC=<ngm checkout>` also fails on an NGM event the file does not list
  (literal `authLog("X")` sites and the step-up `X_FAIL` verbs; an event NGM
  passes in a variable is listed by hand). Run it against a current ngm checkout when
  ngm adds an auth event; CI has no ngm checkout, so it does not run there.

## Buckets, thresholds, alerts

Counts are per `WINDOW`; an alert is gated by `COOLDOWN`.

| Key | Default | Bucket | Alert kind | `0` means |
|---|---|---|---|---|
| `AUTHFAIL_IP` | 25 | interactive, per source IP | `NGM/AUTHFAIL` | bucket off |
| `AUTHFAIL_USER` | 15 | interactive, per username | `NGM/AUTHFAIL` (host-scoped) | bucket off |
| `ADMIN_IP` | 5 | `role=admin` / `reseller` failures, per IP; these also count toward `AUTHFAIL_IP` | `NGM/ADMIN` | bucket off (no fallback) |
| `TOKEN_IP` | 10 | `TOKEN_FAIL`, per IP | `NGM/TOKEN` | falls back to `AUTHFAIL_IP` |

- An IP-bucket alert carries `Extra["ip"]`; the sink bans it per the section's
  `BLOCK` and decorates it with PTR/ASN (the detector does no DNS).
- A per-user alert carries `Extra["user"]` and `ip_scope=host`: the sink
  notifies and bans no sample IP (a distributed attack on one account is not a
  single-IP finding; a single source is caught by the per-IP bucket).
- A sustained single-IP privileged brute fires `NGM/ADMIN`, `NGM/AUTHFAIL`
  (per IP) and the per-user notify. Accepted: the second ban is a no-op.
- Every alert's `Extra` also has `window`, `cooldown`, `limit`, `mode`, `log`.

`ngm_auth` is not an edge-ban section (`edgeban.WebSection`): its bans are nft
only, so they do not stop a client reaching the panel through a trusted proxy.

## Config

```ini
[ngm_auth]
ENABLED = 1
EVERY = "2s"
WINDOW = "10m"
COOLDOWN = "20m"
LOG_PATH = "/var/log/ngm/auth.log"
SAMPLE_LIMIT = 16
AUTHFAIL_IP = 25
AUTHFAIL_USER = 15
ADMIN_IP = 5
TOKEN_IP = 10
BLOCK = dryrun
BLOCK_COOLDOWN = 30m
```

`EVERY` / `WINDOW` / `COOLDOWN` fall back to `[global]`'s `DEFAULT_*`.
Leniency is supported (section sink).

**`BLOCK = dryrun` until burned in on a real NGM host**, then a TTL ban. The
false positives to watch: DAV/mail clients and password-reset flows retry on
their own, so a device with a stale password or a NAT/office egress can pile up
`DAV_FAIL` / `RATELIMIT` far faster than an interactive login. Read their
volume per source and tune `AUTHFAIL_IP` before arming.
