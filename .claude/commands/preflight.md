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

If everything passes, say so explicitly. If something fails, summarize what
broke and the most likely fix. Do not commit or push.
