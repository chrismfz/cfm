#!/bin/bash
# ============================================================
# STEP 6 — CLI AUTH_TOKEN hardening
# Run from the root of the cfm repo on devel.
#
# What this does:
#   1. Creates internal/clihttp/client.go (copy it first — see below)
#   2. Replaces http.Get/http.Post/http.DefaultClient.Do in CLI files
#   3. Adds clihttp import to each modified file
#   4. Patches governor_cli.go helper functions
#   5. Patches main.go (manual step — see PART B below)
# ============================================================

set -e
cd "$(git rev-parse --show-toplevel)"

echo "=== Step 6: CLI AUTH_TOKEN hardening ==="

# ── PART A: Automated replacements ──────────────────────────

WEBDET_CLI_FILES=(
  internal/webdetector/cli.go
  internal/webdetector/cli_waf.go
  internal/webdetector/cli_history.go
  internal/webdetector/cli_exclude.go
)

for f in "${WEBDET_CLI_FILES[@]}"; do
  echo "  Patching $f"
  # Replace http.Get( and http.Post( with clihttp equivalents
  sed -i \
    -e 's/\bhttp\.Get(/clihttp.Get(/g' \
    -e 's/\bhttp\.Post(/clihttp.Post(/g' \
    "$f"
  # Add clihttp import after the "net/http" import line
  # (only if not already present)
  if ! grep -q '"cfm/internal/clihttp"' "$f"; then
    sed -i 's|"net/http"|"net/http"\n\t"cfm/internal/clihttp"|' "$f"
  fi
done

# cli_rules.go: doJSON uses http.DefaultClient.Do — replace that too
echo "  Patching internal/webdetector/cli_rules.go"
sed -i \
  -e 's/http\.DefaultClient\.Do(/clihttp.Do(/g' \
  internal/webdetector/cli_rules.go
if ! grep -q '"cfm/internal/clihttp"' internal/webdetector/cli_rules.go; then
  sed -i 's|"net/http"|"net/http"\n\t"cfm/internal/clihttp"|' internal/webdetector/cli_rules.go
fi

# governor_cli.go: patch getGovernorJSON and postGovernorJSON
echo "  Patching internal/detectors/mysql/governor_cli.go"
# getGovernorJSON uses http.Get internally — replace
sed -i \
  -e 's/\bhttp\.Get(/clihttp.Get(/g' \
  -e 's/http\.DefaultClient\.Do(/clihttp.Do(/g' \
  internal/detectors/mysql/governor_cli.go
if ! grep -q '"cfm/internal/clihttp"' internal/detectors/mysql/governor_cli.go; then
  sed -i 's|"net/http"|"net/http"\n\t"cfm/internal/clihttp"|' internal/detectors/mysql/governor_cli.go
fi

echo ""
echo "=== Automated replacements done. Now do PART B manually. ==="

# ── PART B: Manual changes to cmd/cfm/main.go ───────────────
cat << 'MANUAL'

In cmd/cfm/main.go, make two changes:

─── Change 1: Add clihttp import ───────────────────────────────

In the import block, add:
  "cfm/internal/clihttp"

─── Change 2: Add apiAuthToken() function ──────────────────────

Add this function anywhere in main.go (e.g. near apiBaseURL()):

// apiAuthToken reads AUTH_TOKEN from cfm.conf for use by CLI commands.
// Returns empty string if config cannot be read or token is not set.
func apiAuthToken() string {
	dir, _ := cli.ResolveConfigDir("")
	if dir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, "cfm.conf"))
	if err != nil {
		return ""
	}
	cfg, err := cli.LoadConfigWithAPIOverride(dir, b)
	if err != nil || cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.Debug.AuthToken)
}

─── Change 3: Set token before CLI commands ────────────────────

Find this block in main():

  case "webtop", "nginx-top", "httpd-top":
      addr := apiBaseURL()
      if err := webdet.RunWebTop(addr, os.Args[2:]); err != nil {

Replace with:

  case "webtop", "nginx-top", "httpd-top":
      addr := apiBaseURL()
      clihttp.SetToken(apiAuthToken())
      if err := webdet.RunWebTop(addr, os.Args[2:]); err != nil {

And for mysqltop:

  case "mysqltop", "mysql-top", "mysql":
      addr := apiBaseURL()
      clihttp.SetToken(apiAuthToken())
      if err := mysql.RunMySQLTop(addr, os.Args[2:]); err != nil {

─── Note on cfg.Debug.AuthToken ────────────────────────────────

If the config field name is different (e.g. cfg.API.AuthToken or cfg.Debug.Token),
check with:
  grep -r "AuthToken\|AUTH_TOKEN" internal/config/ | head -20

Use whatever field name the config struct uses for AUTH_TOKEN.

MANUAL

echo ""
echo "=== After manual changes, run: ==="
echo "  make build"
echo "  grep -rn 'clihttp\.' internal/webdetector/cli*.go internal/detectors/mysql/governor_cli.go | wc -l"
echo "  # Should show 20+ hits"
echo ""
echo "  # Test that CLI still works (loopback bypass active, token sent as bonus):"
echo "  cfm webtop rules list"
echo "  cfm mysqltop top 5"
