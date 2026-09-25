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


# ── 1e. walk_for_prefixes: every feed shape we consume ───────────────────────
def test_walk_for_prefixes() -> None:
    def walk(doc):
        return blp.collect_prefixes(blp.walk_for_prefixes(doc.get("prefixes", doc)))
    # Google / Bing: list of {ipv4Prefix|ipv6Prefix: "..."} objects.
    google = {"creationTime": "x", "prefixes": [{"ipv4Prefix": "66.249.64.0/27"},
                                                {"ipv6Prefix": "2001:4860:4801:10::/64"}]}
    check(walk(google) == {"66.249.64.0/27", "2001:4860:4801:10::/64"},
          f"google shape: got {sorted(walk(google))}")
    # Skroutz: bare string lists under ipv4 / ipv6 (was silently 0 prefixes).
    skroutz = {"ipv4": ["185.6.76.0/22", "3.73.204.153/32"], "ipv6": ["2a03:e40::/32"],
               "last_modified": "2025-12-10T08:31:15Z"}
    check(walk(skroutz) == {"185.6.76.0/22", "3.73.204.153/32", "2a03:e40::/32"},
          f"skroutz shape: got {sorted(walk(skroutz))}")
    # The same bounds still apply to list-held strings.
    bad = {"ipv4": ["0.0.0.0/0", "10.0.0.0/8", "1.0.0.0/8", "not-an-ip"], "ipv6": ["::/0"]}
    check(walk(bad) == set(), f"list-held over-broad/private must be dropped: got {sorted(walk(bad))}")
    # A string outside any known key is still ignored (no free-text scraping).
    check(walk({"note": "8.8.8.0/24", "hosts": ["8.8.4.0/24"]}) == set(),
          "strings under unknown keys must be ignored")


# ── 1f. fetch retry + --strict (a feed outage must not drop its ranges) ─────
def test_retry_and_strict() -> None:
    import io
    import urllib.error

    class _Resp(io.BytesIO):
        headers = type("H", (), {"get_content_charset": staticmethod(lambda: "utf-8")})()
        def __enter__(self): return self
        def __exit__(self, *a): return False

    calls = {"n": 0}
    def flaky(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.URLError(ConnectionResetError(104, "reset"))
        return _Resp(b"8.8.8.0/24\n")

    real_urlopen, real_backoff = blp.urllib.request.urlopen, blp.FETCH_BACKOFF_S
    blp.urllib.request.urlopen, blp.FETCH_BACKOFF_S = flaky, 0
    try:
        check(blp.fetch_text("https://feed.invalid/x") == "8.8.8.0/24\n" and calls["n"] == 2,
              f"a transient reset must be retried (calls={calls['n']})")

        def gone(req, timeout=None):
            calls["n"] += 1
            raise urllib.error.HTTPError(req.full_url, 404, "gone", {}, None)
        calls["n"] = 0
        blp.urllib.request.urlopen = gone
        try:
            blp.fetch_text("https://feed.invalid/x")
            check(False, "a 404 must raise")
        except urllib.error.HTTPError:
            check(calls["n"] == 1, f"a 4xx must not be retried (calls={calls['n']})")
        # 429 / 408 are transient: retried.
        for code in (429, 408):
            calls["n"] = 0
            def limited(req, timeout=None, code=code):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise urllib.error.HTTPError(req.full_url, code, "slow down", {}, None)
                return _Resp(b"8.8.8.0/24\n")
            blp.urllib.request.urlopen = limited
            check(blp.fetch_text("https://feed.invalid/x") == "8.8.8.0/24\n" and calls["n"] == 2,
                  f"HTTP {code} must be retried (calls={calls['n']})")
        # A body cut short mid-transfer (IncompleteRead) is retried.
        import http.client
        calls["n"] = 0
        def truncated(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise http.client.IncompleteRead(b"8.8.8.0/2", 100)
            return _Resp(b"8.8.8.0/24\n")
        blp.urllib.request.urlopen = truncated
        check(blp.fetch_text("https://feed.invalid/x") == "8.8.8.0/24\n" and calls["n"] == 2,
              f"IncompleteRead must be retried (calls={calls['n']})")
    finally:
        blp.urllib.request.urlopen, blp.FETCH_BACKOFF_S = real_urlopen, real_backoff

    # --strict: one failing source => nothing written, exit 3, existing file intact.
    good = [f"{a}.{b}.0.0/24" for a in (8, 9) for b in range(80)]  # 160 public /24s
    def fake_load(spec):
        if spec == "bad":
            raise OSError("reset")
        return [blp.SourceResult(name=spec, kind="txt", origin="x", prefixes=set(good))]
    real_load, real_sources, real_argv = blp.load_source, blp.SOURCES, sys.argv
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "bypass.conf")
        with open(out, "w") as fh:
            fh.write("# last-good\n")
        blp.load_source, blp.SOURCES = fake_load, ["ok", "bad"]
        try:
            sys.argv = ["build_bypass_list.py", "--strict", out]
            rc = blp.main()
            with open(out) as fh:
                kept = fh.read() == "# last-good\n"
            check(rc == 3 and kept, f"--strict with a failed source: rc={rc}, file kept={kept}")
            sys.argv = ["build_bypass_list.py", out]
            rc = blp.main()
            check(rc == 1 and blp.count_existing_prefixes(out) == len(good),
                  f"non-strict with a failed source writes the rest (rc={rc})")
        finally:
            blp.load_source, blp.SOURCES, sys.argv = real_load, real_sources, real_argv

    # --strict: a source that answers with NO prefixes (a 200 maintenance page,
    # a changed JSON shape) drops its ranges just like an exception does.
    def empty_load(spec):
        return [blp.SourceResult(name=spec, kind="txt", origin="x",
                                 prefixes=set() if spec == "empty" else set(good))]
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "bypass.conf")
        with open(out, "w") as fh:
            fh.write("# last-good\n")
        blp.load_source, blp.SOURCES = empty_load, ["ok", "empty"]
        try:
            sys.argv = ["build_bypass_list.py", "--strict", out]
            rc = blp.main()
            with open(out) as fh:
                kept = fh.read() == "# last-good\n"
            check(rc == 3 and kept, f"--strict with an empty source: rc={rc}, file kept={kept}")
        finally:
            blp.load_source, blp.SOURCES, sys.argv = real_load, real_sources, real_argv


# ── 1f2. --strict per-source shrink (a truncated feed parses as a shorter list) ─
def test_source_shrink() -> None:
    good = [f"8.{a}.{b}.0/24" for a in range(2) for b in range(100)]   # 200 /24s
    real_load, real_sources, real_argv = blp.load_source, blp.SOURCES, sys.argv
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "bypass.conf")
        blp.render_output([blp.SourceResult(name="feed", kind="txt", origin="x", prefixes=set(good)),
                           blp.SourceResult(name="small", kind="txt", origin="x", prefixes={"9.9.9.0/24"} | {f"9.9.{i}.0/24" for i in range(1, 4)})],
                          out, set(good) | {"9.9.9.0/24"})
        check(blp.existing_source_counts(out) == {"feed": 200, "small": 4},
              f"header counts must round-trip: {blp.existing_source_counts(out)}")
        with open(out) as fh:
            before = fh.read()

        def cut(spec):   # 'feed' returns 60 of its 200 prefixes
            return [blp.SourceResult(name=spec, kind="txt", origin="x",
                                     prefixes=set(good[:60]) if spec == "feed" else {"9.9.9.0/24"})]
        blp.load_source, blp.SOURCES = cut, ["feed", "small"]
        try:
            sys.argv = ["build_bypass_list.py", "--strict", out]
            rc = blp.main()
            with open(out) as fh:
                kept = fh.read() == before
            check(rc == 3 and kept, f"--strict with a source cut to under half: rc={rc}, kept={kept}")
            # 'small' went 4 -> 1, but tiny feeds are below MIN_SOURCE_COUNT_FOR_SHRINK.
            check(blp.shrunk_sources(cut("small"), {"small": 4}) == [],
                  "a tiny feed's swing must not count as a shrink")
        finally:
            blp.load_source, blp.SOURCES, sys.argv = real_load, real_sources, real_argv


# ── 1g. address-space growth guard (a poisoned feed of public /16s) ─────────
def test_space_growth() -> None:
    base = [f"8.{b}.0.0/24" for b in range(200)]           # 51 200 addresses
    g = blp.check_space_growth
    check(g(base, base) is None, "same list must pass")
    check(g(base + ["9.9.9.0/24"], base) is None, "small growth must pass")
    # Allowed growth = existing space without its largest prefix, plus the slack.
    allow4 = (51_200 - 256) + blp.SPACE_GROWTH_SLACK_V4
    fill = allow4 // 256                                     # whole /24s that still fit
    check(g(base + [f"9.{b}.0.0/24" for b in range(fill)], base) is None,
          "growth up to the allowance must pass")
    check(g(base + [f"9.{b}.0.0/24" for b in range(fill + 1)], base) is not None,
          "one /24 past the allowance must be refused")
    check(g(base + ["9.1.0.0/16"], base) is not None,
          "a new /16 (more than the whole baseline) must be refused")
    # The slack is what lets a tiny list grow at all.
    tiny = ["8.8.8.0/24"]
    check(g(tiny + ["9.9.0.0/20"], tiny) is None, "a /20 of growth fits the slack on a tiny list")
    check(g(tiny + ["9.9.0.0/19"], tiny) is not None, "a /19 does not")
    # One dominant prefix must not inflate the allowance (Skroutz's /32 is ~all
    # of the IPv6 space): adding another prefix that size is refused.
    v6 = ["2a03:e40::/32"] + [f"2001:db8:{i:x}::/48" for i in range(4)]
    check(g(base + v6, base + v6) is None, "unchanged IPv6 must pass")
    check(g(base + v6 + ["2a04::/32"], base + v6) is not None,
          "a second /32 next to a dominant /32 must be refused")
    check(g(base + v6 + ["2001:db8:ff::/48"], base + v6) is None,
          "one more /48 is within the allowance")
    check(g(base + [f"{a}.{b}.0.0/16" for a in (11, 12) for b in range(10)], []) is None,
          "no existing file: nothing to compare")
    poisoned = base + [f"{a}.{b}.0.0/16" for a in (11, 12) for b in range(10)]

    # main() applies it: a poisoned run is refused (exit 2) and the file kept,
    # and --allow-growth (a reviewed manual run) lets it through.
    def poisoned_load(spec):
        return [blp.SourceResult(name=spec, kind="txt", origin="x", prefixes=set(poisoned))]
    real_load, real_sources, real_argv = blp.load_source, blp.SOURCES, sys.argv
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "bypass.conf")
        blp.render_output([blp.SourceResult(name="seed", kind="txt", origin="x", prefixes=set(base))],
                          out, set(base))
        with open(out) as fh:
            before = fh.read()
        blp.load_source, blp.SOURCES = poisoned_load, ["feed"]
        try:
            sys.argv = ["build_bypass_list.py", "--strict", out]
            rc = blp.main()
            with open(out) as fh:
                kept = fh.read() == before
            check(rc == 2 and kept, f"poisoned run through main(): rc={rc}, file kept={kept}")
            sys.argv = ["build_bypass_list.py", "--strict", "--allow-growth", out]
            rc = blp.main()
            check(rc == 0 and blp.count_existing_prefixes(out) == len(poisoned),
                  f"--allow-growth writes the larger list (rc={rc})")
        finally:
            blp.load_source, blp.SOURCES, sys.argv = real_load, real_sources, real_argv
    # The committed file must round-trip through the reader the guard uses.
    check(len(blp.existing_prefixes(CONF)) == blp.count_existing_prefixes(CONF),
          "existing_prefixes and count_existing_prefixes disagree on the committed file")


def main() -> int:
    for fn in (test_normalize_prefix, test_thresholds, test_oneline,
               test_render_no_injection, test_walk_for_prefixes, test_retry_and_strict,
               test_source_shrink, test_space_growth, test_committed_file):
        fn()
    if _failures:
        print(f"\nbypass_list_test: {len(_failures)} FAILURE(S)")
        return 1
    print("bypass_list_test: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
