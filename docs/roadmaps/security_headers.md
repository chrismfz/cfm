# Per-vhost response headers: the shared-hosting-safe subset

**Status:** proposal, not started (scope cut 2026-11-18). The earlier 92 KB
design (CSP packs, HSTS ramps, CORS preflight, COOP/COEP, templates in
SQLite) was dropped: on shared hosting the edge does not own the sites, and a
header that changes browser behaviour breaks a tenant's site in ways the
tenant cannot see or undo. git history keeps the old design.

## Rule

The edge only adds a header that **cannot change how a working site
behaves**, and only when the origin did not send one (`add_if_missing`, never
replace). Opt-in per vhost, default off. Applied in the HTTPS server's header
filter, next to the existing ones (`configs/openresty.conf` /
`configs/angie.conf`; keep the two header-filter blocks identical).

## In

| Header | Value | Why it is safe |
|---|---|---|
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Already every modern browser's default; making it explicit changes nothing for a site that works today |
| `X-Content-Type-Options` | `nosniff` | Low risk, not zero: an old site serving its JS / CSS with a wrong `Content-Type` stops loading it. Hence per vhost, off by default |
| Strip `X-Powered-By` | (removed) | Hides the PHP version from scanners; no browser reads it. The edge already sets `server_tokens off` for its own `Server` header |

## Out, and why (do not re-add without a new reason)

- **HSTS**: a one-way door. Browsers cache it per host for `max-age`, with
  `includeSubDomains` for every subdomain; a tenant whose certificate lapses,
  or who serves one subdomain over HTTP, is locked out of their own site with
  no way for us to take it back. A tenant who wants it sets it in their app.
- **CSP** (even report-only): needs per-app knowledge of scripts and third
  parties; report-only needs a collector and someone reading it.
- **`X-Frame-Options` / `frame-ancestors`**: breaks sites legitimately
  embedded elsewhere (payment pages, widgets, previews).
- **`Permissions-Policy`, COOP / COEP / CORP**: break embeds, popups (OAuth,
  payment) and cross-origin assets.
- **CORS answered by the edge**: the app owns its API's CORS.

Same reasoning as the admin UI's declined CSP / frame / HSTS
(`docs/security/control-plane.md` §7).

## Open when it is picked up

- Where the per-vhost switch lives: a field in the Site Cache-style per-vhost
  policy feed, or a plain list in `detectors.conf [webdetector]`.
- Whether `nosniff` gets a dry-run: log responses whose `Content-Type` would be
  refused (a script served as `text/plain` / `text/html`) before arming it.
