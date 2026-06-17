#!/bin/bash
# SessionStart hook for CFM (Go daemon).
# Installs/warms dependencies so tests and linters work in Claude Code on the
# web sessions. Idempotent and non-interactive.
set -euo pipefail

# Only run in Claude Code on the web (remote) sessions. Local devs already
# have their toolchain set up and don't need this on every session.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

echo "[cfm session-start] downloading Go modules..."
go mod download

# Warm the build/vet caches so the first in-session test/lint is fast.
# Best-effort: a transient build issue must not block the session.
echo "[cfm session-start] warming build cache (best-effort)..."
go build ./... || echo "[cfm session-start] warning: go build had issues (non-fatal)"

echo "[cfm session-start] done."
