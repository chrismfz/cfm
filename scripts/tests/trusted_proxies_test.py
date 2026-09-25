#!/usr/bin/env python3
"""Offline (no-network) tests + validator for the edge's trusted_proxies.conf.

  1. Unit-test the generator's safety logic (scripts/build_trusted_proxies.py):
     prefix bounds, the API-shape check, the count and address-space guards,
     and main()'s keep-the-existing-file paths (fetch stubbed).
  2. Re-validate the COMMITTED configs/trusted_proxies.conf with the
     generator's own normalize_prefix: a hand edit that adds an overbroad or
     private range (anyone in it could name the client IP) fails CI.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "scripts"))
sys.dont_write_bytecode = True

import build_trusted_proxies as tp  # noqa: E402

CONF = os.path.join(REPO, "configs", "trusted_proxies.conf")

_failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        _failures.append(msg)
        print(f"  FAIL: {msg}")


V4 = ["173.245.48.0/20", "103.21.244.0/22", "104.16.0.0/13", "172.64.0.0/13", "131.0.72.0/22"]
V6 = ["2400:cb00::/32", "2606:4700::/32", "2a06:98c0::/29"]


# Cloudflare's real IPv4 list (2026-09), and its 5 biggest ranges.
REAL4 = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
         "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
         "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"]
BIG4 = ["104.16.0.0/13", "172.64.0.0/13", "104.24.0.0/14", "162.158.0.0/15", "198.41.128.0/17"]


def api(v4=None, v6=None, **over):
    doc = {"success": True, "result": {"ipv4_cidrs": list(V4 if v4 is None else v4),
                                       "ipv6_cidrs": list(V6 if v6 is None else v6),
                                       "etag": "abc"}}
    doc.update(over)
    return doc


def test_normalize_prefix() -> None:
    np = tp.normalize_prefix
    for bad in ["0.0.0.0/0", "::/0", "10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8",
                "169.254.0.0/16", "224.0.0.0/4", "100.64.0.0/10", "203.0.113.0/24",
                "8.0.0.0/8", "104.0.0.0/11", "2400::/16", "2a06:9800::/27",
                "100.64.0.0/12", "100.100.0.0/16",   # CGNAT (Tailscale): not is_private
                "::ffff:104.16.0.0/109", "2002:6810::/32", "2001:0:6810::/48",  # v4-mapped, 6to4, Teredo
                "173.245.48.1/20",           # host bits set: not what the API sends
                "1.2.3.4",                   # no prefix length
                "1.2.3.0/24; include /etc/passwd", "1.2.3.0/24\n", "", None, 42, ["1.2.3.0/24"]]:
        check(np(bad) is None, f"normalize_prefix should reject {bad!r} (got {np(bad)!r})")
    for good in V4 + V6 + ["104.0.0.0/12", "2a06:9800::/28"]:
        check(np(good) == good, f"normalize_prefix should keep {good!r}")


def test_parse_api() -> None:
    v4, v6, etag = tp.parse_api(api())
    check(sorted(v4) == sorted(V4) and sorted(v6) == sorted(V6) and etag == "abc", "parse_api reads a good answer")
    bad_docs = {
        "not a dict": [],
        "success false": api(success=False),
        "no result": {"success": True},
        "v4 not a list": {"success": True, "result": {"ipv4_cidrs": "1.2.3.0/24", "ipv6_cidrs": V6}},
        "one private entry": api(v4=V4 + ["10.0.0.0/8"]),
        "one broad entry": api(v6=V6 + ["::/0"]),
        "v6 in the v4 list": api(v4=V4 + ["2400:cb00::/32"]),
        "a non-string entry": api(v4=V4 + [None]),
    }
    for name, doc in bad_docs.items():
        try:
            tp.parse_api(doc)
            check(False, f"parse_api should refuse: {name}")
        except ValueError:
            pass


def test_guards() -> None:
    check(tp.check_counts(V4, V6) is None, "check_counts accepts a normal list")
    check(tp.check_counts(V4[:4], V6) is not None, "check_counts refuses too few IPv4")
    check(tp.check_counts(V4, V6[:2]) is not None, "check_counts refuses too few IPv6")
    base = V4 + V6
    check(tp.check_space(base, []) is None, "no existing file: nothing to compare")
    check(tp.check_space(base, base) is None, "same ranges pass")
    check(tp.check_space(base + ["188.114.96.0/20"], base) is None, "a small addition passes")
    check(tp.check_space(base + ["8.0.0.0/12", "9.0.0.0/12"], base) is not None, "IPv4 space doubling is refused")
    check(tp.check_space(base + ["2c0f:f000::/28"], base) is not None, "IPv6 space doubling is refused")
    check(tp.check_space([p for p in base if p not in ("104.16.0.0/13", "172.64.0.0/13")], base) is not None,
          "IPv4 space halving (partial answer) is refused")
    # A partial answer keeping only the big ranges: space barely moves, count halves.
    real4, big4 = REAL4, BIG4
    check(tp.check_space(big4 + V6, real4 + V6) is None, "(the space guard alone can't see it)")
    check(tp.check_shrink(big4, V6, real4 + V6) is not None, "a count that halves (only the big ranges kept) is refused")
    check(tp.check_shrink(real4[:-1], V6, real4 + V6) is None, "one range dropped passes")
    check(tp.check_shrink(real4, V6[:1], real4 + V6) is not None, "an IPv6 count that halves is refused")


def run_main(output: str, doc=None, exc: Exception | None = None, force: bool = False) -> tuple[int, str]:
    real_fetch, real_argv = tp.blp.fetch_json, sys.argv

    def fake_fetch(url: str):
        check(url == tp.SOURCE_URL, f"fetches {tp.SOURCE_URL}")
        if exc is not None:
            raise exc
        return doc

    tp.blp.fetch_json = fake_fetch
    sys.argv = ["build_trusted_proxies.py", output] + (["--force"] if force else [])
    out = io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(out):
            rc = tp.main()
    finally:
        tp.blp.fetch_json, sys.argv = real_fetch, real_argv
    return rc, out.getvalue()


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_main() -> None:
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "trusted_proxies.conf")
        rc, _ = run_main(out, api())
        check(rc == 0 and sorted(tp.existing_prefixes(out)) == sorted(V4 + V6), "main writes a fresh file")
        check(oct(os.stat(out).st_mode & 0o777) == "0o644", "the file is 0644")
        first = read(out)

        rc, log = run_main(out, api())
        check(rc == 0 and read(out) == first and "unchanged" in log, "unchanged ranges leave the file (and its date) alone")
        doc = api(); doc["result"]["etag"] = "def"
        rc, _ = run_main(out, doc)
        check(rc == 0 and read(out) == first, "an etag-only change leaves the file alone (no release commit)")

        with open(out, "w", encoding="utf-8") as fh:
            fh.write("# Example only\n" + "".join(f"set_real_ip_from {p};\n" for p in V4 + V6))
        rc, _ = run_main(out, api())
        check(rc == 0 and tp.is_generated(out), "a hand-written file with the same ranges is rewritten once")
        first = read(out)

        for name, kw, want in [
            ("fetch error", {"exc": OSError("down")}, 1),
            ("not JSON", {"exc": __import__("json").JSONDecodeError("Expecting value", "<html>", 0)}, 1),
            ("bad answer", {"doc": api(success=False)}, 2),
            ("too few", {"doc": api(v6=V6[:1])}, 2),
            ("space jump", {"doc": api(v4=V4 + ["8.0.0.0/12", "9.0.0.0/12"])}, 2),
        ]:
            rc, _ = run_main(out, **kw)
            check(rc == want and read(out) == first, f"{name}: exit {want}, existing file kept (got {rc})")
        check(not [f for f in os.listdir(d) if f.endswith(".tmp")], "no temp file left")

        # End to end: a partial answer keeping only the 5 big IPv4 ranges of the
        # real 15 is refused by main(), not just by check_shrink().
        real = os.path.join(d, "real.conf")
        rc, _ = run_main(real, api(v4=REAL4))
        kept = read(real)
        rc, _ = run_main(real, api(v4=BIG4))
        check(rc == 2 and read(real) == kept, f"main refuses a partial answer (count halved), file kept (got {rc})")

        with open(out, "a", encoding="utf-8") as fh:
            fh.write("set_real_ip_from unix:;\nset_real_ip_from not-a-net;\n")
        rc, _ = run_main(out, api())
        check(rc == 0 and "set_real_ip_from unix:;" not in read(out), "unparseable lines in the existing file don't crash it; the rewrite drops them")

        rc, log = run_main(out, api(v4=V4 + ["8.0.0.0/12", "9.0.0.0/12"]), force=True)
        check(rc == 0 and "+ 8.0.0.0/12" in log and "8.0.0.0/12" in tp.existing_prefixes(out),
              "--force writes a reviewed big change and prints the diff")


def validate_committed() -> None:
    try:
        text = read(CONF)
    except OSError as exc:
        check(False, f"cannot read {CONF}: {exc}")
        return
    check(tp.is_generated(CONF), f"{CONF} must be the generator's output (run scripts/build_trusted_proxies.py)")
    v4, v6 = [], []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        body = s[len(tp.DIRECTIVE) + 1:-1] if s.startswith(tp.DIRECTIVE + " ") and s.endswith(";") else None
        p = tp.normalize_prefix(body) if body is not None else None
        if p is None or p != body:
            check(False, f"{CONF}:{n}: not a bounded 'set_real_ip_from <public cidr>;' line: {s!r}")
            continue
        (v4 if ":" not in p else v6).append(p)
    check(tp.check_counts(v4, v6) is None, f"{CONF}: {tp.check_counts(v4, v6)}")
    check(len(set(v4 + v6)) == len(v4 + v6), f"{CONF}: duplicate ranges")


def main() -> int:
    for t in (test_normalize_prefix, test_parse_api, test_guards, test_main, validate_committed):
        t()
    if _failures:
        print(f"trusted_proxies: {len(_failures)} failure(s)")
        return 1
    print("trusted_proxies: generator logic + committed configs/trusted_proxies.conf OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
