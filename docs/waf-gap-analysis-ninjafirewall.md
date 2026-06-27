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
control plane — areas a PHP-only WAF has nothing for. Genuine, edge-feasible
gaps worth adding (all clean-room, all shipping `logonly` first):

| # | Addition | Rule | Status |
|---|---|---|---|
| 1 | **Superglobal / variable-override** — param KEY named like a PHP superglobal (`_GET`/`_SERVER`/`GLOBALS`/…) = variable poisoning | 318 `rule_superglobal_override` (`WAF_SUPERGLOBAL`) | **shipped, `logonly`** |
| 2 | Loopback/localhost-IP & reflected `DOCUMENT_ROOT` in params (small SSRF/LFI signals) | TBD | planned |
| 3 | Broader pre-match decode (HTML-entity + octal/hex/`\x`/`\u`) across the injection scan surface | — (normalize change) | planned — **medium FP risk**, logonly trial |
| 4 | Known-webhook IP allowlists (PayPal IPN, Stripe) as shipped FP-prevention | — (allowlist) | planned |
| 5 | Response security-header hardening (nosniff/XFO/HSTS/CSP/Referrer-Policy + cookie HttpOnly/SameSite) as an edge option | — | planned — overlaps operator nginx config |

Out of scope (app-level only or different layer): unset superglobal / rewrite
app cookie / DB-aware escaping (need in-PHP position); classic File Integrity
Monitoring snapshot/diff (covered behaviourally by cfm-lsm); response-body
"web filter" defacement scanning (costly, low priority).

## Rollout discipline

Every addition ships **`logonly`** so it cannot break production, and its
reason family is added to the WAF FP-review checklist (see
`docs/waf.md` → "SQLi blind-family expansion"). The same ~weekly
`cfm.waf.log` review that clears `WAF_SQLI` / `WAF_SQLI_LEXICAL` also clears
these new families; a family is promoted `logonly` → `challenge`/`block` only
after a clean window. Per CFM convention (`CLAUDE.md` §6): never go straight to
block; `logonly` → `challenge` → `block`.
