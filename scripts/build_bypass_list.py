#!/usr/bin/env python3
"""
Build an nginx/OpenResty geo include file for static challenge/WAF bypasses.

Supported sources:
- Official Google crawler JSON feeds
- Plain-text IP/CIDR lists (one item per line)
- RIPEstat announced-prefixes lookups for ASNs
- Arbitrary JSON feeds containing prefixes in common shapes

Output format:
    203.0.113.10/32 1;
    2001:db8::/32 1;
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

TIMEOUT = 30
UA = "cfm-bypass-builder/2.0"

GOOGLE_FEEDS = {
    "common-crawlers": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "special-crawlers": "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
    "user-triggered-fetchers": "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json",
    "user-triggered-fetchers-google": "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json",
    "user-triggered-agents": "https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json",
}


@dataclass
class SourceResult:
    name: str
    kind: str
    origin: str
    prefixes: set[str] = field(default_factory=set)
    meta: dict[str, Any] = field(default_factory=dict)


class FetchError(RuntimeError):
    pass


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def fetch_bytes(url: str, timeout: int) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "application/json, text/plain;q=0.9, */*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_text(url: str, timeout: int) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "text/plain, application/json;q=0.9, */*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def fetch_json(url: str, timeout: int) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "application/json, */*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return json.loads(resp.read().decode(charset))


def normalize_prefix(value: str) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None

    # Strip inline comments for txt sources.
    for sep in ("#", ";"):
        if sep in raw:
            raw = raw.split(sep, 1)[0].strip()
    if not raw:
        return None

    try:
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            return str(net)
        ip = ipaddress.ip_address(raw)
        if ip.version == 4:
            return f"{ip}/32"
        return f"{ip}/128"
    except ValueError:
        return None


KNOWN_PREFIX_KEYS = {
    "ipv4prefix",
    "ipv6prefix",
    "prefix",
    "cidr",
    "network",
    "netblock",
    "range",
}


def walk_for_prefixes(obj: Any) -> Iterable[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if kl in KNOWN_PREFIX_KEYS and isinstance(v, str):
                yield v
            else:
                yield from walk_for_prefixes(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_for_prefixes(item)


def collect_prefixes(values: Iterable[str]) -> set[str]:
    out: set[str] = set()
    for value in values:
        norm = normalize_prefix(value)
        if norm:
            out.add(norm)
    return out


def load_google_sources(enabled: list[str], timeout: int) -> list[SourceResult]:
    results: list[SourceResult] = []
    for name in enabled:
        url = GOOGLE_FEEDS[name]
        doc = fetch_json(url, timeout)
        prefixes = collect_prefixes(walk_for_prefixes(doc.get("prefixes", [])))
        results.append(
            SourceResult(
                name=name,
                kind="google-json",
                origin=url,
                prefixes=prefixes,
                meta={"creationTime": doc.get("creationTime", "unknown")},
            )
        )
    return results


def load_txt_source(url: str, timeout: int, index: int) -> SourceResult:
    text = fetch_text(url, timeout)
    prefixes = collect_prefixes(text.splitlines())
    return SourceResult(
        name=f"txt-{index}",
        kind="txt",
        origin=url,
        prefixes=prefixes,
    )


def load_json_source(url: str, timeout: int, index: int) -> SourceResult:
    doc = fetch_json(url, timeout)
    prefixes = collect_prefixes(walk_for_prefixes(doc))
    return SourceResult(
        name=f"json-{index}",
        kind="json",
        origin=url,
        prefixes=prefixes,
    )


def ripe_announced_prefixes_url(asn: str, sourceapp: str | None, ignore_limit: bool) -> str:
    resource = asn.upper()
    if not resource.startswith("AS"):
        resource = f"AS{resource}"
    params = {"resource": resource}
    if sourceapp:
        params["sourceapp"] = sourceapp
    if ignore_limit:
        params["data_overload_limit"] = "ignore"
    return "https://stat.ripe.net/data/announced-prefixes/data.json?" + urllib.parse.urlencode(params)


def load_asn_source(asn: str, timeout: int, index: int, sourceapp: str | None, ignore_limit: bool) -> SourceResult:
    url = ripe_announced_prefixes_url(asn, sourceapp, ignore_limit)
    doc = fetch_json(url, timeout)
    data = doc.get("data", {})
    prefixes_raw: list[str] = []
    for item in data.get("prefixes", []):
        if isinstance(item, dict):
            pfx = item.get("prefix")
            if isinstance(pfx, str):
                prefixes_raw.append(pfx)
        elif isinstance(item, str):
            prefixes_raw.append(item)
    prefixes = collect_prefixes(prefixes_raw)
    return SourceResult(
        name=f"asn-{index}-{asn.upper().removeprefix('AS')}",
        kind="ripe-announced-prefixes",
        origin=url,
        prefixes=prefixes,
        meta={
            "queried_asn": asn.upper() if asn.upper().startswith("AS") else f"AS{asn}",
            "query_time_utc": datetime.now(timezone.utc).isoformat(),
        },
    )


def render_output(results: list[SourceResult], output: str, union_only: bool) -> None:
    union: set[str] = set()
    for res in results:
        union.update(res.prefixes)

    lines: list[str] = []
    lines.append("# Auto-generated nginx/OpenResty geo include for $cfm_bypass_ip")
    lines.append(f"# Generated at: {datetime.now(timezone.utc).isoformat()}")
    lines.append("# Format: <cidr> 1;")
    lines.append("#")
    lines.append("# Example:")
    lines.append("#   geo $cfm_bypass_ip {")
    lines.append("#       default 0;")
    lines.append(f"#       include {output};")
    lines.append("#   }")
    lines.append("#")
    for res in results:
        lines.append(f"# source: {res.name}")
        lines.append(f"#   kind: {res.kind}")
        lines.append(f"#   origin: {res.origin}")
        lines.append(f"#   prefixes: {len(res.prefixes)}")
        for k, v in sorted(res.meta.items()):
            lines.append(f"#   {k}: {v}")
    lines.append("")

    if union_only:
        for prefix in sorted(union, key=sort_key):
            lines.append(f"{prefix} 1;")
    else:
        for res in results:
            lines.append(f"# --- {res.name} ---")
            for prefix in sorted(res.prefixes, key=sort_key):
                lines.append(f"{prefix} 1;")
            lines.append("")
        lines.append("# --- union (deduplicated, commented reference) ---")
        for prefix in sorted(union, key=sort_key):
            lines.append(f"# {prefix}")

    with open(output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")

    print(f"Wrote {output} with {len(union)} unique prefixes from {len(results)} source(s)")


def sort_key(prefix: str) -> tuple[int, int, int, str]:
    net = ipaddress.ip_network(prefix, strict=False)
    return (net.version, int(net.network_address), net.prefixlen, prefix)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build challenge_waf_bypass.conf from JSON/TXT/ASN sources")
    p.add_argument("output", nargs="?", default="challenge_waf_bypass.conf", help="Output file path")
    p.add_argument("--timeout", type=int, default=TIMEOUT, help="HTTP timeout in seconds")
    p.add_argument("--union-only", action="store_true", help="Write only the deduplicated union, no per-source sections")

    p.add_argument("--google-all", action="store_true", help="Include all official Google crawler JSON feeds")
    p.add_argument(
        "--google-feed",
        action="append",
        choices=sorted(GOOGLE_FEEDS.keys()),
        default=[],
        help="Include a specific Google feed; can be repeated",
    )

    p.add_argument("--txt-url", action="append", default=[], help="Plain-text URL with one IP/CIDR per line; can be repeated")
    p.add_argument("--json-url", action="append", default=[], help="Extra JSON URL to recursively scan for prefix-like keys; can be repeated")
    p.add_argument("--asn", action="append", default=[], help="ASN to expand via RIPEstat announced-prefixes, e.g. AS15169 or 15169; can be repeated")
    p.add_argument("--ripe-sourceapp", default="cfm-bypass-builder", help="RIPEstat sourceapp identifier")
    p.add_argument("--no-ripe-ignore-overload", action="store_true", help="Do not send data_overload_limit=ignore to RIPEstat")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    requested_results: list[SourceResult] = []

    google_enabled = list(dict.fromkeys(args.google_feed))
    if args.google_all:
        google_enabled = list(GOOGLE_FEEDS.keys())
    elif not google_enabled and not args.txt_url and not args.json_url and not args.asn:
        # Good default: preserve prior behavior.
        google_enabled = list(GOOGLE_FEEDS.keys())

    try:
        if google_enabled:
            requested_results.extend(load_google_sources(google_enabled, args.timeout))

        for i, url in enumerate(args.txt_url, start=1):
            requested_results.append(load_txt_source(url, args.timeout, i))

        for i, url in enumerate(args.json_url, start=1):
            requested_results.append(load_json_source(url, args.timeout, i))

        for i, asn in enumerate(args.asn, start=1):
            requested_results.append(
                load_asn_source(
                    asn=asn,
                    timeout=args.timeout,
                    index=i,
                    sourceapp=args.ripe_sourceapp,
                    ignore_limit=not args.no_ripe_ignore_overload,
                )
            )
    except Exception as exc:
        eprint(f"ERROR: {exc}")
        return 1

    if not requested_results:
        eprint("ERROR: no sources selected")
        return 1

    empty = [r.name for r in requested_results if not r.prefixes]
    if empty:
        eprint("WARNING: these sources produced zero prefixes:", ", ".join(empty))

    render_output(requested_results, args.output, args.union_only)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
