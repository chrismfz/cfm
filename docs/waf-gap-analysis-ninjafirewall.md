# WAF gap analysis — CFM vs. an app-level PHP WAF (clean-room)

Prompted by a real incident (2026-06-26): `myip.gr` migrated WordPress →
Astro; the WHMCS billing app (`/clients/`) had been protected by an app-level
PHP WAF (NinjaFirewall, `auto_prepend_file` "Full WAF") that was removed with
WordPress, leaving WHMCS exposed to a sqlmap scan. This document captures a
**capability gap analysis** between that class of app-level PHP WAF and CFM's
edge WAF, and the resulting clean-room additions.

> **Licensing boundary.** The reference WAF is **GPLv3**; CFM is **Apache-2.0**.
> GPLv3 code/regex/signature databases were **not** copied — that would impose
> copyleft on CFM. This analysis records only *capability categories* and
> *architectural techniques* (uncopyrightable ideas), independently
> reimplemented. Do not paste GPLv3 code or rule patterns into this repo.

## Structural difference

An app-level PHP WAF runs **inside** the PHP request (`auto_prepend_file`), so
it can see `$_GET`/`$_POST`/`$_FILES`/sessions, **unset** poisoned keys, and
**rewrite app-emitted cookies**. CFM's WAF runs at the **edge** (OpenResty/
Angie, in-path). The edge can **detect** the same classes but cannot mutate
PHP internals — and, conversely, it protects **non-PHP** backends (Astro,
static, anything) that an app-level PHP WAF never sees. The genuinely
app-level-only capabilities (unset superglobal, rewrite app cookie, DB-aware
escaping) are out of scope for an edge WAF; everything else is detection we can
add.

## Coverage summary

Most categories are already covered by CFM's WAF (49 detectors), plus L3/L4
nftables, cfm-lsm (syscall behavioural), kernsec, geo/ASN, and the fleet
control plane — areas a PHP-only WAF has nothing for.

The candidate additions and their **final dispositions** (decided 2026-06-27):

| # | Addition | Rule | Disposition |
|---|---|---|---|
| 1 | **Superglobal / variable-override** — param KEY named like a PHP superglobal (`_GET`/`_SERVER`/`GLOBALS`/…) = variable poisoning | 318 `rule_superglobal_override` (`WAF_SUPERGLOBAL`) | ✅ **shipped, `logonly`** |
| 2 | Loopback/localhost-IP & reflected `DOCUMENT_ROOT` in params | — | ❌ **dropped (marginal)** — see below |
| 3 | Broader pre-match decode (HTML-entity + octal/hex/`\x`/`\u`) across the scan surface | — | ❌ **dropped (FP storm + not isolatable)** |
| 4 | Known-webhook IP allowlists (PayPal IPN, Stripe) as shipped FP-prevention | — | ⏸ **on-demand** — only if a real gateway-callback FP is observed |
| 5 | Response security-header hardening (nosniff/XFO/HSTS/CSP + cookie flags) | — | ❌ **skipped (out of scope)** |

Net: of the five, **only #1 was a genuine, edge-feasible gap** and shipped. The
rest were dropped/deferred for the reasons below — recorded so they are not
reopened without new evidence.

### Why #3 was dropped (broader pre-match decode)
1. **Cannot ship `logonly`.** Adding entity/octal/hex/`\x`/`\u` decode to
   `normalize()` changes the input fed to **every** rule, including the ones
   already at `challenge`/`block`, fleet-wide — it cannot be isolated to one
   observe-only rule, breaking the rollout discipline below.
2. **Instant FP storm.** `\uXXXX` is ubiquitous in legitimate traffic — every
   JSON API body / SPA POST encodes non-ASCII as `\u00XX`; HTML entities
   (`&lt;`, `&#39;`) ride in legitimate CMS/forum content. Decoding before
   matching makes legitimate JSON/content look like it is full of `<`/`'` →
   mass XSS/SQLi false positives on existing enforcing rules.
3. **Highest resource cost** of the set (extra decode passes on every body)
   for marginal gain — the injection detectors that matter already do their
   own targeted decoding (SQLi comment-strip, the backdoor opener's
   entity/unicode handling, the base64 body decode-and-rescan, rule 7).

### Why #2 was dropped (loopback-IP / DOCUMENT_ROOT in params)
- The **evasion** SSRF forms attackers actually use — non-`http` schemes
  (`gopher`/`file`/`dict`/…) and obfuscated octal/hex/dword IPs in `://`
  context — are **already caught** by the SSRF-proto detector (rule 23).
- The only genuinely-new slice is **plain** `127.0.0.1`/`localhost` in a
  param, which is **heavy legitimate traffic** (config saves, redirect/callback
  URLs, internal-microservice apps, health-checks) → noisy, low signal.
- The one low-FP/high-value subset is the cloud-metadata IP
  (`169.254.169.254`) — but that only matters on **cloud/VPS**; on
  dedicated/cPanel hosts there is no metadata service, so ~zero value. If the
  fleet ever moves to cloud, add a **sharp metadata-only** rule then.
- The `DOCUMENT_ROOT`-reflection check does **not** port to the edge at all:
  it relies on the in-PHP `$_SERVER['DOCUMENT_ROOT']` value, which an edge
  proxy does not know per-vhost. Absolute-path LFI to sensitive files is
  already partly covered by the traversal detector's sensitive-sink list.

Out of scope from the start (app-level only or different layer): unset
superglobal / rewrite app cookie / DB-aware escaping (need in-PHP position);
classic File Integrity Monitoring snapshot/diff (covered behaviourally by
cfm-lsm); response-body "web filter" defacement scanning (costly, low value).

## Rollout discipline

Every addition ships **`logonly`** so it cannot break production, and its
reason family is added to the WAF FP-review checklist (see
`docs/waf.md` → "SQLi blind-family expansion"). The same ~weekly
`cfm.waf.log` review that clears `WAF_SQLI` / `WAF_SQLI_LEXICAL` also clears
these new families; a family is promoted `logonly` → `challenge`/`block` only
after a clean window. Per CFM convention (`CLAUDE.md` §6): never go straight to
block; `logonly` → `challenge` → `block`.
