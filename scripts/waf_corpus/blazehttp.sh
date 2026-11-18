#!/usr/bin/env bash
# scripts/waf_corpus/blazehttp.sh — run BlazeHTTP's labelled corpus through
# the in-path WAF and print detection / false-positive numbers per rule.
#
#   scripts/waf_corpus/blazehttp.sh [run.lua options]
#   make waf-corpus ARGS="--out /tmp/after.tsv --baseline /tmp/before.tsv"
#
# BlazeHTTP (github.com/chaitin/blazehttp, GPL-3.0) ships ~33 k benign and
# ~650 attack raw-HTTP samples. It is fetched at a pinned commit into a cache
# outside this repository and only read from there: never vendor its samples
# or code into CFM (Apache-2.0). Bump BLAZEHTTP_REV deliberately; a different
# corpus makes earlier --out files incomparable.
#
# Env: BLAZEHTTP_DIR  an existing checkout to use instead of fetching
#      CFM_CORPUS_CACHE  cache root (default ${XDG_CACHE_HOME:-~/.cache}/cfm)
set -euo pipefail

BLAZEHTTP_REPO="https://github.com/chaitin/blazehttp.git"
BLAZEHTTP_REV="afc88a94d03db1cd52156c34c3c9c58053c9f658" # master, 2024-07-01

root="$(cd "$(dirname "$0")/../.." && pwd)"
command -v luajit >/dev/null 2>&1 || { echo "luajit is required" >&2; exit 1; }

dir="${BLAZEHTTP_DIR:-}"
if [ -z "$dir" ]; then
  command -v git >/dev/null 2>&1 || { echo "git is required to fetch BlazeHTTP" >&2; exit 1; }
  cache="${CFM_CORPUS_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/cfm}"
  dir="$cache/blazehttp-$BLAZEHTTP_REV"
  if [ ! -d "$dir/testcases" ]; then
    echo "fetching BlazeHTTP $BLAZEHTTP_REV into $dir" >&2
    tmp="$dir.tmp.$$"
    rm -rf "$tmp"
    mkdir -p "$tmp"
    git -C "$tmp" init -q
    git -C "$tmp" fetch -q --depth 1 "$BLAZEHTTP_REPO" "$BLAZEHTTP_REV"
    git -C "$tmp" -c advice.detachedHead=false checkout -q FETCH_HEAD
    got="$(git -C "$tmp" rev-parse HEAD)"
    if [ "$got" != "$BLAZEHTTP_REV" ]; then
      echo "fetched $got, expected $BLAZEHTTP_REV" >&2
      rm -rf "$tmp"
      exit 1
    fi
    rm -rf "$dir"
    mv "$tmp" "$dir"
  fi
fi
[ -d "$dir/testcases" ] || { echo "no testcases/ under $dir" >&2; exit 1; }

cd "$root"
exec luajit scripts/waf_corpus/run.lua "$@" "$dir/testcases"
