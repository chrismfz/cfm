---
description: Run all CFM CI gates locally before pushing (mirrors security.yml)
---
Run the full CFM preflight, mirroring `.github/workflows/security.yml`, and
report a concise pass/fail summary. Run each step; if one fails, show the
relevant output and stop (don't keep going past a hard failure).

1. `go vet ./...`
2. `go build ./...`
3. `./scripts/tests/check_test_isolation.sh arm` (records CFM's system dirs —
   `/var/lib/cfm`, `/run/cfm`, `/etc/cfm`, `/var/log/cfm`; fails with the
   one-time `sudo install -d …` if they don't exist or aren't writable by you.
   CI also seeds them like a packaged node first — `ci_seed_cfm_dirs.sh`, CI-only)
4. `go test -race ./...`
5. `./scripts/tests/check_test_isolation.sh verify` (fails if the Go tests wrote
   any of them; on a CFM node the running daemon's writes show up too)
6. `make lua`
7. `make test-lua`
8. `make test-js`
9. `./scripts/tests/check_cli_transport.sh`
10. `./scripts/tests/check_cfm_clearance_require.sh`
11. `./scripts/tests/check_bypass_list.sh`
12. `./scripts/tests/check_logrotate_coverage.sh`
13. `./scripts/tests/check_origin_ka_config.sh` (origin-keepalive 443 SNI-safety
   config invariant: `keepalive 0` on OpenResty origin upstreams, none on Angie,
   `proxy_ssl_session_reuse off` on every 443 origin location)
14. `./scripts/tests/check_shared_lua_layout.sh`
15. `./scripts/tests/check_package_lua_delivery.sh`
16. `./scripts/tests/check_rpm_spec_macros.sh`
17. `./scripts/tests/check_site_cache_config.sh` (Site Cache bypass-by-default:
   every `proxy_cache` location gated on `$cfm_cache_skip`)
18. `./scripts/tests/stamp_changelog_test.sh`
19. `./scripts/tests/release_notes_test.sh`
20. `./scripts/tests/check_preflight_parity.sh` (this list and the CLAUDE.md §3
   block == the commands `security.yml` runs)
21. `./scripts/tests/check_changelog_entry.sh` (CHANGELOG structure; the per-PR
   "code changed → needs a `[Unreleased]` entry" leg only runs in CI)

Keep this list in sync with `security.yml`. It drifted twice — once silently
dropping seven gates, later missing `check_site_cache_config.sh` — the same
false-confidence failure the guardrails exist to prevent; step 20 now fails CI
on any difference, in either direction.

If everything passes, say so explicitly. If something fails, summarize what
broke and the most likely fix. Do not commit or push.
