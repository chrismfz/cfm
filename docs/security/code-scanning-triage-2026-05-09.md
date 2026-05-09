# Code-scanning triage — 2026-05-09 (Critical + High)

This document records the triage decisions for the Critical + High severity
alerts surfaced by CodeQL on `chrismfz/cfm` as of 2026-05-09. All 11 alerts
in this batch were inspected against the actual code at the cited
file:line, with data flow traced from source to sink before forming a
verdict. Medium / Low alerts are deferred to a follow-up pass.

The companion fixes land in the same branch as this document
(`claude/codescan-fixes-J2EBW`).

## Summary

| Verdict | Count |
|---|---|
| real-bug | 1 |
| false-positive | 9 |
| accepted-risk | 1 |

**Headline:** the only real finding is the High-severity reflected XSS at
`internal/webdetector/challenge_server.go:865`. The two Critical
"Email content injection" alerts and the rest of the High-severity
findings are all false positives or accepted-risk, with the safety
reasoning documented below.

---

## Real bugs (fix in code)

### CodeQL #565 — Reflected XSS in challenge page (HIGH) — REAL

- **Path:** `internal/webdetector/challenge_server.go:865`
- **Sink:** `jsStringLiteral(next)` rendered into `<script>...</script>`
  block via `fmt.Fprintf(w, challengeHTML(), …)`.
- **Source:** the `?next=` query parameter (`r.URL.Query().Get("next")`),
  passed through `normalizeChallengeNext`.

#### Why it's real

`jsStringLiteral` was implemented as a one-line wrapper over
`strconv.Quote`. `strconv.Quote` produces a *Go* string literal — it
escapes `\`, `"`, control chars, non-printables, but **not** `<`, `>`,
`&`, U+2028, or U+2029. In a Go program that's fine; embedded inside an
HTML `<script>` block it isn't:

```html
<script>
  var next = "<<the strconv.Quote output>>";
</script>
```

If the input string contains the literal sequence `</script>`, the HTML
parser tokenises it as the closing tag of the script element, terminates
JavaScript context early, and the trailing bytes become regular HTML —
giving an attacker arbitrary HTML execution. Standard JS-in-HTML
embedding rules require escaping `<`, `>`, `&`, and the JS-only line
terminators U+2028 / U+2029.

`normalizeChallengeNext` applies a length cap, requires `/` prefix, runs
the value through `url.ParseRequestURI`, and rejects nested challenge
URLs. None of those reject `<`/`>` in the path:

```
$ url.ParseRequestURI("/foo</script><img src=x onerror=alert(1)>")
ACCEPT  Path="/foo</script><img src=x onerror=alert(1)>"
```

So the literal `</script><img src=x onerror=alert(1)>` survives
normalisation and reaches `jsStringLiteral` unchanged.

#### Fix

Make `jsStringLiteral` HTML-script-context-safe by post-processing the
`strconv.Quote` output to escape the four HTML-context-sensitive bytes
plus the two JS line terminators. The replacement uses `\uXXXX` escapes,
which are valid in both JS string literals and JSON. After this, an
input of `/foo</script>...` renders as
`/foo</script>...` and the HTML parser does not see the
closing tag.

The existing `host` placeholder going through `htmlEscape` is unaffected
— `htmlEscape` already covers HTML element-content context correctly
(see #765 below).

#### Resolution

- Code fix: see commit `fix(webdetector): escape HTML-sensitive chars in jsStringLiteral`
- Closes CodeQL #565.

---

## False positives (suppress / document)

### CodeQL #606 + #605 — Email content injection (CRITICAL) — FP

- **Paths:**
  - `internal/notify/channels_smtp.go:100` (`w.Write([]byte(msg))`)
  - `internal/notify/channels_smtp.go:121` (`smtp.SendMail(...)`)
- **Source:** `subj`, `body` arguments to `smtpChannel.Send`, ultimately
  rendered from operator-configured `SubjectTmpl` / `BodyTmpl` against
  the internal `Event` struct.

#### Why it's a false positive

The `msg` byte slice at line 52-55 is built as:

```go
msg := "From: " + from + "\r\n" +
    "To: " + strings.Join(to, ", ") + "\r\n" +
    fmt.Sprintf("Subject: %s\r\n", safeSubj) +
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body
```

Three independent defences make header injection structurally impossible:

1. **From/To addresses** are validated by `sanitizeAddress`
   (`channels_smtp.go:131`), which rejects CRLF and parses through
   `mail.ParseAddress` — only RFC-valid addresses survive.
2. **Subject** is validated by `sanitizeHeaderValue`
   (`channels_smtp.go:124`), which explicitly rejects any input
   containing CR or LF.
3. **Body** is concatenated *after* the literal `\r\n\r\n` separator
   that ends the headers section. By RFC 5322 construction, every byte
   in `body` is parsed as message body, never as headers. CRLF inside
   `body` is legitimate body content and cannot escape the body section.

The CodeQL rule is missing the body-section boundary semantic — it sees
attacker-derivable data flowing into the SMTP write but does not
recognise the pre-existing CRLF rejection on header inputs and the
positional invariant on `body`.

#### Resolution

- Dismiss in GitHub Security UI with rationale "header inputs
  CRLF-rejected upstream; body bytes are positionally constrained to the
  RFC 5322 body section after the literal `\r\n\r\n` separator".
- Inline comment near `msg :=` documenting the boundary contract for
  future reviewers (added in this branch's suppression commit).

---

### CodeQL #765 — Reflected XSS via host placeholder (HIGH) — FP

- **Path:** `internal/webdetector/challenge_server.go:862`
- **Sink:** `htmlEscape(host)` rendered into the `<code>%s</code>`
  element-content position in `challengeHTML()`.

#### Why it's a false positive

`htmlEscape` (challenge_server.go:1020-1029) is a `strings.NewReplacer`
covering all five HTML-context-sensitive characters:

| char | escape |
|---|---|
| `&` | `&amp;` |
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&#39;` |

The placeholder is in HTML *element-content* position
(`<code>%s</code>`). For element content the four characters `& < > "`
are sufficient; `'` is included as defence-in-depth for attribute
contexts. There is no way to break out of the `<code>` element with the
remaining alphabet.

CodeQL likely flags this because it does not recognise the bespoke
`htmlEscape` function as a sanitiser. (The same alert pattern fires on
many projects that use a custom escaper rather than `html/template`.)

Note: the alert pair #765 / #565 share the same `fmt.Fprintf` call site;
#765 specifically points at the `host` argument while #565 points at
`next`. The XSS is real for `next` (see Real bugs above). For `host` the
escape is correct and the alert is FP.

#### Resolution

- Dismiss in GitHub Security UI with rationale "`htmlEscape` covers all
  five HTML-sensitive chars; placement is HTML element-content, no
  attribute or script context here".

---

### CodeQL #677 — Disabled TLS certificate check (HIGH) — ACCEPTED RISK

- **Path:** `internal/healthmodel/collector.go:1096`
- **Sink:** `&tls.Config{InsecureSkipVerify: true}` used by an internal
  HTTPS liveness probe.

#### Why it's accepted risk (not a fix)

The TLS client is used solely for `https://127.0.0.1/hello` — a local
loopback probe that checks whether the in-process nginx/openresty
listener is alive. The probe target is not configurable and never
contacts a remote host.

Threat model: an attacker capable of MITM-ing 127.0.0.1 has already
achieved code execution as root on the same host (only root can bind to
loopback as another process or insert into the local routing table for
loopback traffic). At that point the integrity of the local certificate
chain is irrelevant — the attacker can simply read process memory or
modify the binary.

The existing inline comment "local liveness probe only" documents
intent. No change to behaviour; the alert is dismissed with the
rationale recorded here.

#### Resolution

- Dismiss in GitHub Security UI with rationale linking back to this
  document.
- Comment expanded slightly for clarity in this branch's suppression
  commit (no functional change).

---

### CodeQL #613 — Uncontrolled data in path (HIGH) — FP

- **Path:** `internal/notify/admin_config.go:308`
- **Sink:** `os.OpenFile(dst, …)` inside `copyFileSafe(src, dst)`.

#### Why it's a false positive

`copyFileSafe` is internal-only. The single caller in
`internal/notify/` is `RestoreAdminConfigBackup` (`admin_config.go:249`).
That function builds `restorePath` as:

```go
restorePath := path + ".bak-" + restoreID
// where:
//   path comes from resolveConfigPath(cfgDir)  -- operator-set CFM
//                                                  config directory
//   restoreID = backupID + "-restore-" + UTC timestamp
//   backupID is validated by resolveBackupPath earlier in the same
//     function: rejects '/' and '..' in the id (admin_config.go:279)
```

Every byte in `dst` is therefore inside the operator-controlled config
directory: a fixed prefix path, the literal `.bak-`, a sanitised id, the
literal `-restore-`, a server-generated timestamp. There is no
attacker-controlled path traversal vector.

CodeQL is missing the `resolveBackupPath` validation upstream of the
`restorePath` construction.

#### Resolution

- Dismiss in GitHub Security UI with rationale.
- Inline comment near the `restorePath` build site documenting the
  upstream sanitisation, so a future reviewer doesn't reopen the alert.

---

### CodeQL #560 + #562 + #563 — Slice memory allocation with excessive size (HIGH) — FP

- **Paths:**
  - `internal/webdetector/waf_engine_api_handlers.go:113`
    (`make([]wafEngineEvent, 0, limit)`)
  - `internal/webdetector/history_api_handlers.go:114`
    (`make([]HistoryEvent, 0, boundedLimit)`)
  - `internal/webdetector/history_api_handlers.go:115`
    (`make([]HistoryEvent, 0, boundedLimit)` — sibling slice)

#### Why they're false positives

In each case the allocation size is clamped *before* the `make` call:

- `waf_engine_api_handlers.go:113`: the inline comment at that very line
  reads "*limit is clamped to a maximum of 2000 above before this
  allocation*". The clamp is at the start of the same handler.
- `history_api_handlers.go:114-115`: `boundedLimit` is derived from
  `queryLimit` after the explicit clamp at lines 100-102:

  ```go
  if queryLimit > maxQueryLimit {
      queryLimit = maxQueryLimit
  }
  ```

The maximum `make` size in all three sites is therefore a small fixed
constant (2000 events for the WAF path, `maxQueryLimit` for the history
path), well within safe heap allocation bounds. CodeQL's interprocedural
constant propagation isn't tracking through the conditional clamp.

#### Resolution

- Dismiss in GitHub Security UI for all three with rationale "allocation
  size clamped upstream within the same function".
- Inline comments at each clamp site (already present at the WAF site;
  added at the history site in this branch).

---

### CodeQL #561 — Incorrect integer conversion (HIGH) — FP

- **Path:** `internal/nflog/smtp_snoop.go:230`
- **Sink:** `uint16(group)`

#### Why it's a false positive

The `group` value is range-checked at lines 225-227 *immediately above*
the conversion:

```go
if group < 0 || group > int(math.MaxUint16) {
    group = 0
}
return SnoopConfig{
    Group: uint16(group),
    …
}
```

The comment at lines 222-224 explicitly documents the bound:

> Bound the int->uint16 conversion locally so this constructor does not
> depend on external callers to pre-validate ranges.

CodeQL doesn't appear to recognise the inline range check as a guard.

#### Resolution

- Dismiss in GitHub Security UI with rationale.
- No code change needed (existing comment is already adequate).

---

### CodeQL #711 — Incorrect integer conversion (HIGH) — FP (with cheap defence-in-depth)

- **Path:** `internal/firewall/nftlib/lifecycle.go:39`
- **Sink:** `nftables.ChainPriority(prio)` where `prio` is `int`,
  destination type is `int32`.

#### Why it's a false positive

`prio` is sourced from operator configuration:

```go
prio := -50
if b.cfg != nil && b.cfg.NFT.InputPriority != 0 {
    prio = b.cfg.NFT.InputPriority
}
```

`b.cfg.NFT.InputPriority` is read from the parsed CFM config TOML; not
attacker-controllable. The default `-50` and any reasonable operator
override fits in int32.

#### Resolution (defence-in-depth fix)

A one-line clamp closes the alert without behaviour change. The clamp
also acts as a guardrail if a future config-loader bug or a misuse
allows a wildly out-of-range value to land in `b.cfg.NFT.InputPriority`.

- Code change: clamp `prio` to int32 range before conversion.
- See commit `fix(nftlib): clamp ChainPriority input to int32 range`.
- Closes CodeQL #711.

---

## Suppression mechanism summary

CodeQL alerts cannot be suppressed by inline comments; the project has
no `.codeql` query-config that would let us flag specific call sites as
sanitisers. The suppression workflow is:

1. **Dismiss in the GitHub Security UI** with the rationale from this
   document (use the alert-specific section). GitHub categorises
   dismissals as "won't fix" with the reason text preserved.
2. **Add an inline rationale comment** at the suppressed call site (or
   keep the existing one if already present). This makes the safety
   reasoning durable across re-scans, code moves, and future reviewers
   who don't have GitHub Security access.

Both steps are needed: the UI dismissal closes the alert; the inline
comment prevents the next reader from re-opening it.

## Out of scope

- Medium / Low alerts. Triaged in a separate pass once this batch
  closes cleanly.
- The remaining ~290 alerts. Same.
- Re-triaging the existing 49 `// #nosec` annotations across the
  codebase. They are trusted unless a new alert reopens one.
- Adding `.semgrepignore` / CodeQL custom queries to mark
  `htmlEscape` / `jsStringLiteral` / `sanitizeHeaderValue` as
  sanitisers. Worth doing but is its own change.
