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
6. `./scripts/tests/check_cli_transport.sh`
7. `./scripts/tests/check_cfm_clearance_require.sh`
8. `./scripts/tests/check_bypass_list.sh`
9. `./scripts/tests/check_origin_ka_config.sh` (origin-keepalive 443 SNI-safety
   config invariant: `keepalive 0` on OpenResty origin upstreams, none on Angie,
   `proxy_ssl_session_reuse off` on every 443 origin location)
10. `./scripts/tests/check_changelog_entry.sh` (CHANGELOG structure; the per-PR
   "code changed → needs a `[Unreleased]` entry" leg only runs in CI)

If everything passes, say so explicitly. If something fails, summarize what
broke and the most likely fix. Do not commit or push.
