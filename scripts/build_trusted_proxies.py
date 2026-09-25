#!/usr/bin/env python3
"""
Build the edge's trusted_proxies.conf (nginx/Angie realip) from Cloudflare's
published ranges.

Just run it:   python3 scripts/build_trusted_proxies.py   # writes configs/trusted_proxies.conf
Or override:   python3 scripts/build_trusted_proxies.py /custom/path.conf

Every range here is trusted to name the client: the edge takes the client IP
from CF-Connecting-IP when the peer is in it (real_ip_header CF-Connecting-IP).
A poisoned or overbroad range would let anyone in it pick the IP the WAF,
challenge and blocks see, so the input is bounded like the bypass list's
(public CIDRs only, no range broader than /12 v4 // /28 v6, count bounds, a
shrink and an address-space growth guard), the write is atomic, and a refused
run keeps the existing file. `scripts/tests/check_bypass_list.sh` re-validates
the committed file in CI.

Cloudflare only: QUIC.cloud and other CDNs send the client IP in a header a
client can also set (QUIC.cloud passes a client-supplied CF-Connecting-IP
through), and one real_ip_header serves them all, so adding them needs a
per-proxy design, not a feed here.

Exit: 0 written (or unchanged), 1 fetch failed, 2 refused (bounds/guards).
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Iterable

sys.dont_write_bytecode = True  # no scripts/__pycache__ in the packages
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# One fetcher (retries, timeouts) and one address-space measure for both
# generated lists: no second copy to drift (CLAUDE.md §5).
import build_bypass_list as blp  # noqa: E402

SOURCE_URL = "https://api.cloudflare.com/client/v4/ips"

DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "configs", "trusted_proxies.conf",
)

# Cloudflare's broadest ranges today are an IPv4 /13 and an IPv6 /29; one step
# of headroom each, nothing wider.
MIN_IPV4_PREFIXLEN = 12
MIN_IPV6_PREFIXLEN = 28
MIN_IPV4_COUNT = 5        # 15 today
MIN_IPV6_COUNT = 3        # 7 today
MAX_PER_FAMILY = 100
# Per family: refuse if the covered space more than doubles, or halves (a
# truncated or partial answer). A real change of that size is a reviewed manual
# run with --force.
MAX_SPACE_GROWTH_FACTOR = 2.0
MIN_SPACE_SHRINK_FACTOR = 0.5

DIRECTIVE = "set_real_ip_from"


def normalize_prefix(value: Any) -> str | None:
    """A bounded, public CIDR in canonical form, or None. The one validator
    for the generator and the CI check of the committed file."""
    if not isinstance(value, str):
        return None
    raw = value
    if not raw or raw != raw.strip() or "/" not in raw:
        return None
    try:
        net = ipaddress.ip_network(raw, strict=True)
    except ValueError:
        return None
    if (net.is_unspecified or net.is_loopback or net.is_link_local
            or net.is_multicast or net.is_reserved or net.is_private):
        return None
    min_len = MIN_IPV4_PREFIXLEN if net.version == 4 else MIN_IPV6_PREFIXLEN
    if net.prefixlen < min_len:
        return None
    return str(net)


def parse_api(doc: Any) -> tuple[list[str], list[str], str]:
    """(ipv4, ipv6, etag) from the API answer. Raises ValueError on any shape
    or entry that isn't exactly what Cloudflare documents: one bad entry
    refuses the run rather than being dropped (a partial list is worse)."""
    if not isinstance(doc, dict) or doc.get("success") is not True:
        raise ValueError("API answer is not a success document")
    res = doc.get("result")
    if not isinstance(res, dict):
        raise ValueError("API answer has no result object")
    out: dict[int, list[str]] = {}
    for fam, key in ((4, "ipv4_cidrs"), (6, "ipv6_cidrs")):
        vals = res.get(key)
        if not isinstance(vals, list):
            raise ValueError(f"{key} is not a list")
        got = []
        for v in vals:
            p = normalize_prefix(v)
            if p is None or ipaddress.ip_network(p).version != fam:
                raise ValueError(f"{key}: unusable entry {blp.oneline(v, 60)!r}")
            got.append(p)
        out[fam] = sorted(set(got), key=blp.sort_key)
    etag = res.get("etag")
    return out[4], out[6], etag if isinstance(etag, str) else ""


def check_counts(v4: list[str], v6: list[str]) -> str | None:
    if not MIN_IPV4_COUNT <= len(v4) <= MAX_PER_FAMILY:
        return f"{len(v4)} IPv4 ranges (want {MIN_IPV4_COUNT}..{MAX_PER_FAMILY})"
    if not MIN_IPV6_COUNT <= len(v6) <= MAX_PER_FAMILY:
        return f"{len(v6)} IPv6 ranges (want {MIN_IPV6_COUNT}..{MAX_PER_FAMILY})"
    return None


def check_space(new: Iterable[str], existing: Iterable[str]) -> str | None:
    """Refuse a per-family jump or collapse of the covered address space.
    No existing ranges = nothing to compare."""
    existing = list(existing)
    if not existing:
        return None
    n4, n6 = blp.address_space(new)
    e4, e6 = blp.address_space(existing)
    for fam, n, e, unit in ((4, n4, e4, "addresses"), (6, n6, e6, "/64s")):
        if e and n > e * MAX_SPACE_GROWTH_FACTOR:
            return f"IPv{fam} space grew from {e} to {n} {unit} (poisoned answer?)"
        if e and n < e * MIN_SPACE_SHRINK_FACTOR:
            return f"IPv{fam} space shrank from {e} to {n} {unit} (partial answer?)"
    return None


def existing_prefixes(path: str) -> list[str]:
    """The CIDR of each `set_real_ip_from <cidr>;` line of an existing file."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        s = line.strip()
        if s.startswith(DIRECTIVE + " ") and s.endswith(";"):
            out.append(s[len(DIRECTIVE):-1].strip())
    return out


GENERATED_MARK = "# Auto-generated by scripts/build_trusted_proxies.py"


def is_generated(path: str) -> bool:
    try:
        with open(path, encoding="utf-8") as fh:
            return any(line.startswith(GENERATED_MARK) for line in fh)
    except OSError:
        return False


def render(v4: list[str], v6: list[str], etag: str) -> str:
    lines = [
        "# Cloudflare ranges trusted to name the client (realip, CF-Connecting-IP).",
        f"{GENERATED_MARK} from {SOURCE_URL}",
        "# (`make release` refreshes it). Don't edit by hand: the next release",
        "# overwrites it. On a node, the package upgrade deploys it next to the",
        "# edge's main config.",
        f"# Generated at: {datetime.now(timezone.utc).isoformat()}",
    ]
    if etag:
        lines.append(f"# etag: {blp.oneline(etag, 80)}")
    lines.append("")
    lines += [f"{DIRECTIVE} {p};" for p in v4]
    lines.append("")
    lines += [f"{DIRECTIVE} {p};" for p in v6]
    return "\n".join(lines) + "\n"


def write_atomic(output: str, data: str) -> None:
    directory = os.path.dirname(os.path.abspath(output)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".trusted_proxies.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, output)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main() -> int:
    p = argparse.ArgumentParser(description="Build trusted_proxies.conf from Cloudflare's ranges")
    p.add_argument("output", nargs="?", default=DEFAULT_OUTPUT, help="Output file path")
    p.add_argument("--force", action="store_true",
                   help="skip the address-space guard (a reviewed manual run after a real Cloudflare change)")
    args = p.parse_args()

    try:
        v4, v6, etag = parse_api(blp.fetch_json(SOURCE_URL))
    except ValueError as exc:
        blp.eprint(f"ERROR: refusing Cloudflare's answer ({exc}); keeping existing file at {args.output}")
        return 2
    except Exception as exc:  # network, HTTP, JSON
        blp.eprint(f"ERROR: fetching {SOURCE_URL}: {exc}; keeping existing file at {args.output}")
        return 1

    existing = existing_prefixes(args.output)
    reason = check_counts(v4, v6)
    if reason is None and not args.force:
        reason = check_space(v4 + v6, existing)
    if reason is not None:
        blp.eprint(f"ERROR: refusing to write ({reason}); keeping existing file at {args.output}")
        return 2

    new = set(v4 + v6)
    old = set(existing)
    if new == old and is_generated(args.output):
        # Unchanged ranges: leave the file (and its date) alone, so a release
        # commits nothing.
        print(f"{args.output}: Cloudflare ranges unchanged ({len(v4)} IPv4, {len(v6)} IPv6)")
        return 0
    for pfx in sorted(new - old, key=blp.sort_key):
        print(f"  + {pfx}")
    for pfx in sorted(old - new, key=blp.sort_key):
        print(f"  - {pfx}")
    write_atomic(args.output, render(v4, v6, etag))
    print(f"Wrote {args.output}: {len(v4)} IPv4 + {len(v6)} IPv6 Cloudflare ranges")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
