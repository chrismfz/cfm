#!/usr/bin/env python3
"""Offline (no-network) tests + validator for the challenge/WAF bypass list.

Two jobs, both runnable in CI without touching the internet:

  1. Unit-test the generator's safety logic (scripts/build_bypass_list.py):
     prefix bounding, metadata sanitisation, the shrink/size guard, and that
     the atomic render can't be tricked into injecting an nginx directive.
  2. Re-validate the COMMITTED configs/challenge_waf_bypass.conf against the
     generator's OWN normalize_prefix — so a hand-edited or stale file that
     smuggled in an over-broad/private/malformed prefix fails the build even
     if nobody ever re-runs the generator.

Reusing build_bypass_list.normalize_prefix for (2) keeps the generator and the
validator on a single rule set (no drift — CLAUDE.md §5).
"""

from __future__ import annotations

import os
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "scripts"))

import build_bypass_list as blp  # noqa: E402

CONF = os.path.join(REPO, "configs", "challenge_waf_bypass.conf")

_failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        _failures.append(msg)
        print(f"  FAIL: {msg}")


# ── 1a. normalize_prefix: bounding + public-only ─────────────────────────────
def test_normalize_prefix() -> None:
    np = blp.normalize_prefix
    reject = [
        "0.0.0.0/0", "::/0",                       # global kill-switch
        "10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24", "127.0.0.1", "127.0.0.0/8",
        "169.254.0.0/16", "224.0.0.0/4", "100.64.0.0/10",   # special-purpose
        "203.0.113.0/24",                          # RFC5737 documentation (is_private)
        "8.0.0.0/8", "8.8.0.0/15",                 # broader than /16 floor
        "2001:4860::/29", "2600::/16",             # broader than /32 floor
        "not-an-ip", "", "   ", "999.1.1.1/33",
    ]
    for r in reject:
        check(np(r) is None, f"normalize_prefix should reject {r!r} (got {np(r)!r})")
    keep = {
        "136.122.0.0/16": "136.122.0.0/16",        # exactly at v4 floor
        "66.249.66.0/24": "66.249.66.0/24",        # real googlebot range
        "8.8.8.8": "8.8.8.8/32",                    # bare host -> /32
        "2a03:e40::/32": "2a03:e40::/32",           # exactly at v6 floor
        "2606:4700::/32": "2606:4700::/32",
        "93.184.216.0/24  # trailing comment": "93.184.216.0/24",  # comment stripped, public
    }
    for src, exp in keep.items():
        check(np(src) == exp, f"normalize_prefix({src!r}) = {np(src)!r}, expected {exp!r}")


# ── 1b. check_thresholds: shrink / size guard ────────────────────────────────
def test_thresholds() -> None:
    ct = blp.check_thresholds
    check(ct(2742, 2742) is None, "equal counts must pass")
    check(ct(2600, 2742) is None, "small shrink must pass")
    check(ct(2742, 0) is None, "no existing file must pass")
    check(ct(1000, 2742) is not None, ">50% shrink must abort")
    check(ct(blp.MIN_PREFIXES_TOTAL - 1, 0) is not None, "< MIN must abort")
    check(ct(blp.MAX_PREFIXES_TOTAL + 1, 0) is not None, "> MAX must abort")


# ── 1c. oneline: config-injection defense on metadata ────────────────────────
def test_oneline() -> None:
    ol = blp.oneline
    inj = "2026-01-01T00:00:00Z\n0.0.0.0/0 1;\n#"
    out = ol(inj)
    check("\n" not in out and "\r" not in out, "oneline must strip CR/LF")
    got_tab = ol("a\tb")
    check(got_tab == "a b", f"oneline must replace tab with space (got {got_tab!r})")


# ── 1d. render_output: end-to-end, incl. injection via feed metadata ─────────
def test_render_no_injection() -> None:
    union = {"93.184.216.0/24", "66.249.66.0/24"}
    res = blp.SourceResult(
        name="evil", kind="json", origin="https://feed.example/x.json",
        prefixes=set(union),
        # attacker-controlled creationTime trying to break out of the comment:
        meta={"creationTime": "x\n0.0.0.0/0 1;\n# "},
    )
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "challenge_waf_bypass.conf")
        blp.render_output([res], out, union)
        with open(out) as fh:
            lines = [ln.rstrip("\n") for ln in fh]
    data_lines = [ln for ln in lines if ln and not ln.startswith("#")]
    check("0.0.0.0/0 1;" not in data_lines,
          "metadata newline must NOT inject a standalone `0.0.0.0/0 1;` directive")
    check(set(data_lines) == {p + " 1;" for p in union},
          f"unexpected data lines: {data_lines}")
    check(data_lines and data_lines[-1].endswith(" 1;"),
          "output must end with a data line")


# ── 2. validate the COMMITTED file with the generator's own rules ────────────
def test_committed_file() -> None:
    check(os.path.exists(CONF), f"missing {CONF}")
    if not os.path.exists(CONF):
        return
    np = blp.normalize_prefix
    total = 0
    with open(CONF) as fh:
        for ln, line in enumerate(fh, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            check(s.endswith(" 1;"), f"{CONF}:{ln}: not a `<cidr> 1;` line: {s!r}")
            if not s.endswith(" 1;"):
                continue
            cidr = s[:-3].strip()
            total += 1
            norm = np(cidr)
            check(norm is not None,
                  f"{CONF}:{ln}: prefix {cidr!r} is rejected by the generator's bounds "
                  f"(over-broad / private / malformed)")
            check(norm == cidr,
                  f"{CONF}:{ln}: prefix {cidr!r} is not canonical (expected {norm!r})")
    check(total >= blp.MIN_PREFIXES_TOTAL,
          f"{CONF}: only {total} prefixes (< MIN_PREFIXES_TOTAL={blp.MIN_PREFIXES_TOTAL})")
    check(total <= blp.MAX_PREFIXES_TOTAL,
          f"{CONF}: {total} prefixes (> MAX_PREFIXES_TOTAL={blp.MAX_PREFIXES_TOTAL})")
    print(f"  committed file: {total} prefixes, all bounded & canonical")


def main() -> int:
    for fn in (test_normalize_prefix, test_thresholds, test_oneline,
               test_render_no_injection, test_committed_file):
        fn()
    if _failures:
        print(f"\nbypass_list_test: {len(_failures)} FAILURE(S)")
        return 1
    print("bypass_list_test: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
