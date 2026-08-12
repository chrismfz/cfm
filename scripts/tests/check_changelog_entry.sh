#!/usr/bin/env bash
#
# check_changelog_entry.sh — CI safety net for CHANGELOG.md hygiene.
#
# Two independent checks:
#
#   1. STRUCTURE (always): CHANGELOG.md must contain exactly one
#      "## [Unreleased]" heading, and it must sit ABOVE the first dated
#      "## YYYY.MM.DD" heading. This is the invariant scripts/stamp-changelog.sh
#      relies on — if [Unreleased] is renamed, removed, or duplicated,
#      `make release` would SILENTLY stop stamping (the stamper no-ops when it
#      cannot find the block), so we guard it here rather than discover it on
#      release day.
#
#   2. ENTRY (pull requests only): if a PR changes runtime code but touches
#      neither CHANGELOG.md nor carries an explicit opt-out, fail — so a
#      user-facing change cannot merge with an empty changelog. Docs/test/CI-only
#      PRs are exempt (CLAUDE.md §9: "Docs-only / config-comment PRs may skip").
#      Escape hatches for the rare code change with no operator-facing effect:
#      "[skip changelog]" in the PR title or body, or a "no-changelog" label.
#
# The entry leg runs only when BASE_SHA is set (the CI job passes the PR base
# commit). Locally, or on push / workflow_dispatch, only the structure check
# runs — so this script is safe to run by hand for a quick structural sanity
# check.
#
# Env (all optional; the entry leg activates only with BASE_SHA):
#   BASE_SHA   PR base commit  — enables the entry check
#   HEAD_SHA   PR head commit  (default: HEAD)
#   PR_TITLE   PR title        (escape-hatch scan)
#   PR_BODY    PR body         (escape-hatch scan)
#   PR_LABELS  space/comma-separated label names (escape-hatch scan)
#   CHANGELOG_FILE  override the changelog path (default: CHANGELOG.md)
set -euo pipefail

FILE="${CHANGELOG_FILE:-CHANGELOG.md}"
[ -f "$FILE" ] || { echo "check_changelog_entry: no such file: $FILE" >&2; exit 1; }

# --- 1. Structure -----------------------------------------------------------
unrel_count="$(grep -c '^## \[Unreleased\]$' "$FILE" || true)"
if [ "$unrel_count" -ne 1 ]; then
  echo "❌ CHANGELOG.md must have exactly one '## [Unreleased]' heading (found $unrel_count)." >&2
  echo "   scripts/stamp-changelog.sh keys on it; 'make release' stops stamping without it." >&2
  exit 1
fi

unrel_line="$(grep -n '^## \[Unreleased\]$' "$FILE" | head -n1 | cut -d: -f1)"
dated_line="$( { grep -nE '^## [0-9]{4}\.[0-9]{2}\.[0-9]{2}$' "$FILE" || true; } | head -n1 | cut -d: -f1)"
if [ -n "$dated_line" ] && [ "$unrel_line" -gt "$dated_line" ]; then
  echo "❌ '## [Unreleased]' (line $unrel_line) must sit above the first dated section (line $dated_line)." >&2
  exit 1
fi
echo "✅ structure: single '## [Unreleased]' heading, correctly placed."

# --- 2. Entry (pull requests only) ------------------------------------------
if [ -z "${BASE_SHA:-}" ]; then
  echo "ℹ️  no BASE_SHA — structure check only (per-PR entry check runs in CI)."
  exit 0
fi
HEAD_SHA="${HEAD_SHA:-HEAD}"

# Three-dot: what THIS branch changed since it forked from base (needs the
# merge-base, hence the CI job checks out with fetch-depth: 0).
changed="$(git diff --name-only "${BASE_SHA}...${HEAD_SHA}")"
if [ -z "$changed" ]; then
  echo "ℹ️  no changed files detected — nothing to check."
  exit 0
fi

if printf '%s\n' "$changed" | grep -qx 'CHANGELOG.md'; then
  echo "✅ entry: CHANGELOG.md updated in this PR."
  exit 0
fi

# Escape hatches (deliberate opt-out for a code change with no operator-facing effect).
case "${PR_TITLE:-} ${PR_BODY:-}" in
  *"[skip changelog]"*)
    echo "✅ entry: '[skip changelog]' opt-out present — skipping."
    exit 0 ;;
esac
if printf '%s' "${PR_LABELS:-}" | tr ' ,' '\n\n' | grep -qx 'no-changelog'; then
  echo "✅ entry: 'no-changelog' label present — skipping."
  exit 0
fi

# Runtime code the operator would want documented. Kept deliberately narrow so
# docs/tests/CI-only PRs never trip it (CLAUDE.md §9).
code="$(printf '%s\n' "$changed" | grep -E '^(internal/|cmd/|configs/|plugins/|packaging/|Makefile|go\.mod$|go\.sum$)' || true)"
if [ -z "$code" ]; then
  echo "✅ entry: no runtime-code paths changed (docs/tests/CI only) — CHANGELOG optional."
  exit 0
fi

echo "❌ This PR changes runtime code but adds no CHANGELOG.md entry." >&2
echo "   Add a bullet under '## [Unreleased]' (Added / Changed / Fixed / Security / Removed)," >&2
echo "   or opt out with '[skip changelog]' in the PR title/body, or a 'no-changelog' label." >&2
echo "   Changed runtime-code paths:" >&2
printf '%s\n' "$code" | sed 's/^/     /' >&2
exit 1
