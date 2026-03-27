#!/usr/bin/env python3
"""
Build an nginx/OpenResty geo include file for static challenge/WAF bypasses.

Just run it:   python3 build_bypass_list.py
Or override:   python3 build_bypass_list.py /custom/path.conf

All sources are defined in SOURCES below — edit the list to add/remove.
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
UA = "cfm-bypass-builder/3.0"
DEFAULT_OUTPUT = "challenge_waf_bypass.conf"

# ═══════════════════════════════════════════════════════════════════════════════
# SOURCES — edit this list to add/remove bypass sources.
#
# Types:
#   google-all          All official Google crawler JSON feeds
#   google:<feed>       One Google feed (common-crawlers, special-crawlers,
#                       user-triggered-fetchers, user-triggered-fetchers-google,
#                       user-triggered-agents)
#   bing-all            All official Bing crawler JSON feeds
#   txt:<url>           Plain-text file with one IP/CIDR per line
#   json:<url>          JSON feed scanned recursively for prefix-like keys
#   asn:<number>        ASN expanded via RIPEstat announced-prefixes
# ═══════════════════════════════════════════════════════════════════════════════

SOURCES = [
    "google-all",
    "bing-all",
    "txt:https://tools.koalityengine.com/ip.txt",
    "asn:AS202042",
    "json:https://duckduckgo.com/duckduckbot.json",
    "json:https://openai.com/gptbot.json",
    "json:https://openai.com/searchbot.json",
    "txt:https://www.quic.cloud/ips?ln",
]

# ═══════════════════════════════════════════════════════════════════════════════

GOOGLE_FEEDS = {
    "common-crawlers": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "special-crawlers": "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
    "user-triggered-fetchers": "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json",
    "user-triggered-fetchers-google": "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json",
    "user-triggered-agents": "https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json",
}

BING_FEEDS = {
    "bingbot": "https://www.bing.com/toolbox/bingbot.json",
}


@dataclass
class SourceResult:
    name: str
    kind: str
    origin: str
    prefixes: set[str] = field(default_factory=set)
    meta: dict[str, Any] = field(default_factory=dict)


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/plain, */*;q=0.8"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def fetch_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json, */*;q=0.8"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return json.loads(resp.read().decode(charset))


def normalize_prefix(value: str) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    for sep in ("#", ";"):
        if sep in raw:
            raw = raw.split(sep, 1)[0].strip()
    if not raw:
        return None
    try:
        if "/" in raw:
            return str(ipaddress.ip_network(raw, strict=False))
        ip = ipaddress.ip_address(raw)
        return f"{ip}/32" if ip.version == 4 else f"{ip}/128"
    except ValueError:
        return None


KNOWN_PREFIX_KEYS = {"ipv4prefix", "ipv6prefix", "prefix", "cidr", "network", "netblock", "range"}


def walk_for_prefixes(obj: Any) -> Iterable[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in KNOWN_PREFIX_KEYS and isinstance(v, str):
                yield v
            else:
                yield from walk_for_prefixes(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_for_prefixes(item)


def collect_prefixes(values: Iterable[str]) -> set[str]:
    out: set[str] = set()
    for v in values:
        norm = normalize_prefix(v)
        if norm:
            out.add(norm)
    return out


def sort_key(prefix: str) -> tuple[int, int, int, str]:
    net = ipaddress.ip_network(prefix, strict=False)
    return (net.version, int(net.network_address), net.prefixlen, prefix)


# ── Source loaders ───────────────────────────────────────────────────────────

def load_json_feed(name: str, kind: str, url: str) -> SourceResult:
    doc = fetch_json(url)
    prefixes = collect_prefixes(walk_for_prefixes(doc.get("prefixes", doc)))
    return SourceResult(name=name, kind=kind, origin=url, prefixes=prefixes,
                        meta={"creationTime": doc.get("creationTime", "unknown")})


def load_txt(name: str, url: str) -> SourceResult:
    text = fetch_text(url)
    return SourceResult(name=name, kind="txt", origin=url,
                        prefixes=collect_prefixes(text.splitlines()))


def load_asn(name: str, asn: str) -> SourceResult:
    resource = asn.upper() if asn.upper().startswith("AS") else f"AS{asn}"
    params = {"resource": resource, "data_overload_limit": "ignore", "sourceapp": "cfm-bypass-builder"}
    url = "https://stat.ripe.net/data/announced-prefixes/data.json?" + urllib.parse.urlencode(params)
    doc = fetch_json(url)
    raw: list[str] = []
    for item in doc.get("data", {}).get("prefixes", []):
        if isinstance(item, dict) and isinstance(item.get("prefix"), str):
            raw.append(item["prefix"])
        elif isinstance(item, str):
            raw.append(item)
    return SourceResult(name=name, kind="ripe-asn", origin=url, prefixes=collect_prefixes(raw),
                        meta={"asn": resource, "query_time": datetime.now(timezone.utc).isoformat()})


# ── Dispatcher ───────────────────────────────────────────────────────────────

def load_source(spec: str) -> list[SourceResult]:
    """Parse a SOURCES entry and return one or more SourceResults."""
    if spec == "google-all":
        return [load_json_feed(f"google-{n}", "google-json", u) for n, u in GOOGLE_FEEDS.items()]
    if spec.startswith("google:"):
        feed = spec[7:]
        if feed not in GOOGLE_FEEDS:
            raise ValueError(f"unknown google feed: {feed}")
        return [load_json_feed(f"google-{feed}", "google-json", GOOGLE_FEEDS[feed])]
    if spec == "bing-all":
        return [load_json_feed(f"bing-{n}", "bing-json", u) for n, u in BING_FEEDS.items()]
    if spec.startswith("bing:"):
        feed = spec[5:]
        if feed not in BING_FEEDS:
            raise ValueError(f"unknown bing feed: {feed}")
        return [load_json_feed(f"bing-{feed}", "bing-json", BING_FEEDS[feed])]
    if spec.startswith("txt:"):
        url = spec[4:]
        name = url.rsplit("/", 1)[-1].split("?")[0].split(".")[0] or "txt"
        return [load_txt(f"txt-{name}", url)]
    if spec.startswith("json:"):
        url = spec[5:]
        name = url.rsplit("/", 1)[-1].split("?")[0].split(".")[0] or "json"
        return [load_json_feed(f"json-{name}", "json", url)]
    if spec.startswith("asn:"):
        asn = spec[4:].strip()
        canonical = asn.upper().removeprefix("AS")
        return [load_asn(f"asn-{canonical}", asn)]
    raise ValueError(f"unknown source spec: {spec}")


# ── Output ───────────────────────────────────────────────────────────────────

def render_output(results: list[SourceResult], output: str) -> None:
    union: set[str] = set()
    for res in results:
        union.update(res.prefixes)

    lines: list[str] = [
        "# Auto-generated nginx/OpenResty geo include for $cfm_bypass_ip",
        f"# Generated at: {datetime.now(timezone.utc).isoformat()}",
        "# Format: <cidr> 1;",
        "#",
        "#   geo $cfm_bypass_ip {",
        "#       default 0;",
        f"#       include {output};",
        "#   }",
        "#",
    ]
    for res in results:
        lines.append(f"# source: {res.name}  ({res.kind}, {len(res.prefixes)} prefixes)")
        lines.append(f"#   {res.origin}")
        for k, v in sorted(res.meta.items()):
            lines.append(f"#   {k}: {v}")
    lines.append("")

    for prefix in sorted(union, key=sort_key):
        lines.append(f"{prefix} 1;")

    with open(output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip() + "\n")

    print(f"Wrote {output} with {len(union)} unique prefixes from {len(results)} source(s)")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser(description="Build challenge_waf_bypass.conf")
    p.add_argument("output", nargs="?", default=DEFAULT_OUTPUT, help="Output file path")
    args = p.parse_args()

    results: list[SourceResult] = []
    errors: list[str] = []

    for spec in SOURCES:
        try:
            results.extend(load_source(spec))
        except Exception as exc:
            errors.append(f"{spec}: {exc}")
            eprint(f"ERROR [{spec}]: {exc}")

    if not results:
        eprint("ERROR: no sources produced results")
        return 1

    empty = [r.name for r in results if not r.prefixes]
    if empty:
        eprint("WARNING: zero prefixes from:", ", ".join(empty))
    if errors:
        eprint(f"WARNING: {len(errors)} source(s) failed, continuing with {len(results)} that succeeded")

    render_output(results, args.output)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
