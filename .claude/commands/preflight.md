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
15. `./scripts/tests/stamp_changelog_test.sh`
16. `./scripts/tests/release_notes_test.sh`
17. `./scripts/tests/check_changelog_entry.sh` (CHANGELOG structure; the per-PR
   "code changed → needs a `[Unreleased]` entry" leg only runs in CI)

Keep this list in sync with `security.yml` — it drifted once and silently
stopped covering seven gates, which is the same false-confidence failure the
guardrails themselves exist to prevent.

If everything passes, say so explicitly. If something fails, summarize what
broke and the most likely fix. Do not commit or push.
