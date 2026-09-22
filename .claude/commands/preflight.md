---
description: Run all CFM CI gates locally before pushing (mirrors security.yml)
---
Run the full CFM preflight, mirroring `.github/workflows/security.yml`, and
report a concise pass/fail summary. Run each step; if one fails, show the
relevant output and stop (don't keep going past a hard failure).

1. `go vet ./...`
2. `go build ./...`
3. `go test -race ./...`
4. `make lua`
5. `make test-lua`
6. `make test-js`
7. `./scripts/tests/check_cli_transport.sh`
8. `./scripts/tests/check_cfm_clearance_require.sh`
9. `./scripts/tests/check_bypass_list.sh`
10. `./scripts/tests/check_logrotate_coverage.sh`
11. `./scripts/tests/check_origin_ka_config.sh` (origin-keepalive 443 SNI-safety
   config invariant: `keepalive 0` on OpenResty origin upstreams, none on Angie,
   `proxy_ssl_session_reuse off` on every 443 origin location)
12. `./scripts/tests/check_shared_lua_layout.sh`
13. `./scripts/tests/check_package_lua_delivery.sh`
14. `./scripts/tests/check_rpm_spec_macros.sh`
15. `./scripts/tests/check_site_cache_config.sh` (Site Cache bypass-by-default:
   every `proxy_cache` location gated on `$cfm_cache_skip`)
16. `./scripts/tests/stamp_changelog_test.sh`
17. `./scripts/tests/release_notes_test.sh`
18. `./scripts/tests/check_preflight_parity.sh` (this list and the CLAUDE.md §3
   block == the commands `security.yml` runs)
19. `./scripts/tests/check_changelog_entry.sh` (CHANGELOG structure; the per-PR
   "code changed → needs a `[Unreleased]` entry" leg only runs in CI)

Keep this list in sync with `security.yml`. It drifted twice — once silently
dropping seven gates, later missing `check_site_cache_config.sh` — the same
false-confidence failure the guardrails exist to prevent; step 18 now fails CI
on any difference, in either direction.

If everything passes, say so explicitly. If something fails, summarize what
broke and the most likely fix. Do not commit or push.
