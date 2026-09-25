#!/usr/bin/env python3
"""
Build an nginx/OpenResty geo include file for static challenge/WAF bypasses.

Just run it:   python3 scripts/build_bypass_list.py       # writes configs/challenge_waf_bypass.conf
Or override:   python3 scripts/build_bypass_list.py /custom/path.conf

All sources are defined in SOURCES below — edit the list to add/remove.

Safety: every prefix here disables WAF + challenge for that IP space, so feed
input is bounded (public CIDRs only, no ranges broader than /16 v4 // /32 v6),
metadata is sanitised against config-injection, the write is atomic, and a run
that would shrink the list too far is refused (the existing file is kept).
`scripts/tests/check_bypass_list.sh` re-validates the committed file in CI.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

TIMEOUT = 30
UA = "cfm-bypass-builder/3.0"

# Authoritative output: the packaged reference config the installers copy from
# (/usr/share/cfm/configs/). Resolve it relative to THIS script so a manual
# `python3 scripts/build_bypass_list.py` (from any cwd) rewrites the right file
# instead of dropping a stray copy in the current directory.
DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "configs", "challenge_waf_bypass.conf",
)

# ── Safety bounds (audit: challenge_waf_bypass.conf generator hardening) ──────
# Every prefix in the output makes cfm.lua early-return straight to origin,
# disabling WAF + challenge for that IP space. A single overbroad or poisoned
# feed prefix would silently turn protection off for a huge range, so we bound
# what any feed can contribute. The prefix-length floors keep every prefix
# currently shipped (broadest are IPv4 /16 and IPv6 /32) while rejecting
# anything wider.
MIN_IPV4_PREFIXLEN = 16          # reject IPv4 broader than /16 (e.g. /8, 0.0.0.0/0)
MIN_IPV6_PREFIXLEN = 32          # reject IPv6 broader than /32 (e.g. ::/0)
MAX_PREFIXES_PER_SOURCE = 10000  # a single feed emitting more than this is suspect
MAX_PREFIXES_TOTAL = 50000       # runaway-output backstop
MIN_PREFIXES_TOTAL = 100         # sanity floor: a healthy run yields thousands
MAX_SHRINK_FRACTION = 0.5        # abort if the new list is < 50% of the existing one
# Abort if the covered ADDRESS SPACE grows by more than the existing space
# minus its single largest prefix (times factor - 1), plus a small slack.
# The count caps can't see a poisoned feed that serves a few hundred public
# /16s: +300 prefixes, but ~100x the space bypassing WAF + challenge. The
# largest prefix is left out because one prefix dominates each family
# (136.122.0.0/16 is over half the ~120k IPv4 addresses; Skroutz's
# 2a03:e40::/32 is ~99.99998% of the IPv6 /64s): counting it would let a
# poisoned feed add another prefix that size unnoticed. Overlaps are merged
# first (address_space). A genuinely larger list (a new source) is a reviewed
# manual run with --allow-growth.
MAX_SPACE_GROWTH_FACTOR = 2.0
SPACE_GROWTH_SLACK_V4 = 1 << 12          # addresses (a /20)
SPACE_GROWTH_SLACK_V6 = 1 << 16          # /64s (a /48)
# --strict also refuses a source that shrank below half its previous count (a
# body truncated without a Content-Length still parses as a shorter list).
MAX_SOURCE_SHRINK_FRACTION = 0.5
MIN_SOURCE_COUNT_FOR_SHRINK = 10         # tiny feeds legitimately swing by a few

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
    "json:https://developer.skroutz.gr/ip_ranges.json",
    "json:https://search.developer.apple.com/applebot.json",  # Applebot (Siri / Spotlight crawler)
    # NEVER add a service whose target URL anyone can choose: a bypass skips
    # the WAF too (cfm.lua Step 0), so it becomes a free WAF-bypass proxy.
    # Rejected for that reason: ChatGPT-User (fetches any URL a user types),
    # Stripe webhooks, UptimeRobot / Pingdom (anyone can register a webhook or
    # monitor aimed at https://victim/?id=<payload>). Such callers need a
    # path-scoped exclude, not an IP bypass.

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


FETCH_ATTEMPTS = 3               # a transient reset must not drop a whole source
FETCH_BACKOFF_S = 2.0            # 2s, then 4s between attempts
RETRY_HTTP_4XX = {408, 425, 429}  # timeout / too early / rate-limited: transient, retry


def _fetch(url: str, accept: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(charset, errors="replace")
        except urllib.error.HTTPError as exc:
            # Any other 4xx is an answer (moved, gone, forbidden), not a transient fault.
            transient = exc.code >= 500 or exc.code in RETRY_HTTP_4XX
            if not transient or attempt == FETCH_ATTEMPTS:
                raise
            exc.close()  # release the connection before sleeping
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            # HTTPException covers IncompleteRead: a body cut short mid-transfer.
            if attempt == FETCH_ATTEMPTS:
                raise
        time.sleep(FETCH_BACKOFF_S * attempt)
    raise AssertionError("unreachable")


def fetch_text(url: str) -> str:
    return _fetch(url, "text/plain, */*;q=0.8")


def fetch_json(url: str) -> Any:
    return json.loads(_fetch(url, "application/json, */*;q=0.8"))


def normalize_prefix(value: str) -> str | None:
    """Canonicalize a feed value to a bounded, public CIDR, or None if unusable.

    Validation is intentionally strict (see the safety-bounds block): a feed can
    only ever ADD a range to the WAF/challenge bypass, so we reject anything that
    is not a well-formed, public, sufficiently-specific prefix — no 0.0.0.0/0, no
    RFC1918/loopback/link-local/multicast/reserved, nothing broader than the
    MIN_*_PREFIXLEN floors. This is the single validator both the generator and
    the CI check use, so their rules can't drift.
    """
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
            net = ipaddress.ip_network(raw, strict=False)
        else:
            ip = ipaddress.ip_address(raw)
            net = ipaddress.ip_network(f"{ip}/{32 if ip.version == 4 else 128}")
    except ValueError:
        return None
    # Drop special-purpose / non-public ranges — none are legitimate bot space,
    # and any of them in the bypass list would be a hole (0.0.0.0/0 a global
    # kill-switch, RFC1918/loopback a per-host bypass for internal traffic).
    if (net.is_unspecified or net.is_loopback or net.is_link_local
            or net.is_multicast or net.is_reserved or net.is_private):
        return None
    # Drop over-broad prefixes: a wide block from any feed would bypass
    # protection for far more space than a bot legitimately occupies.
    min_len = MIN_IPV4_PREFIXLEN if net.version == 4 else MIN_IPV6_PREFIXLEN
    if net.prefixlen < min_len:
        return None
    return str(net)


KNOWN_PREFIX_KEYS = {"ipv4prefix", "ipv6prefix", "prefix", "cidr", "network", "netblock", "range"}

# Keys whose value is a bare LIST of prefix strings, e.g. Skroutz's
# {"ipv4": ["185.6.76.0/22", ...], "ipv6": [...]}. The walker used to recurse
# into such a list and drop every string (it only kept strings held by a
# KNOWN_PREFIX_KEYS key), so that feed silently contributed 0 prefixes.
KNOWN_PREFIX_LIST_KEYS = {"ipv4", "ipv6"}


def walk_for_prefixes(obj: Any) -> Iterable[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k).lower()
            if key in KNOWN_PREFIX_KEYS and isinstance(v, str):
                yield v
            elif key in KNOWN_PREFIX_LIST_KEYS and isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        yield item
                    else:
                        yield from walk_for_prefixes(item)
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
                        meta={"creationTime": doc.get("creationTime", doc.get("last_modified", "unknown"))})


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

def oneline(value: Any, maxlen: int = 200) -> str:
    """Flatten a value to a single safe comment token: replace CR/LF and other
    control characters with a space and clamp the length. Feed-controlled
    metadata (e.g. a JSON ``creationTime``) is written into ``#`` comment lines,
    so an embedded newline could otherwise break out of the comment and inject a
    standalone nginx ``geo`` directive (e.g. ``0.0.0.0/0 1;``) into the file."""
    s = str(value)
    s = "".join(ch if (ch.isprintable() and ch not in "\r\n") else " " for ch in s)
    return s[:maxlen]


def _space(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    """IPv4 addresses, or IPv6 /64s, covered by one network."""
    if net.version == 4:
        return net.num_addresses
    return 1 << (64 - net.prefixlen) if net.prefixlen <= 64 else 1


def address_space(prefixes: Iterable[str], drop_largest: bool = False) -> tuple[int, int]:
    """(IPv4 addresses, IPv6 /64s) covered by the prefixes; with drop_largest,
    without the single largest prefix of each family. Overlaps are merged
    first (collapse_addresses): a feed that lists a range AND its
    more-specifics (AS202042 announces 2a03:e40::/32 and a /48 inside it)
    adds no space, and must not be counted as growth."""
    nets: dict[int, list] = {4: [], 6: []}
    for p in prefixes:
        net = ipaddress.ip_network(p, strict=False)
        nets[net.version].append(net)
    out = []
    for fam in (4, 6):
        sizes = [_space(n) for n in ipaddress.collapse_addresses(nets[fam])]
        total = sum(sizes)
        if drop_largest and sizes:
            total -= max(sizes)
        out.append(total)
    return out[0], out[1]


def existing_prefixes(path: str) -> list[str]:
    """The ``<cidr>`` of each ``<cidr> 1;`` data line in an existing output file."""
    try:
        with open(path, encoding="utf-8") as fh:
            return [s[:-2].strip() for line in fh
                    if (s := line.strip()) and not s.startswith("#") and s.endswith(" 1;")]
    except OSError:
        return []


def check_space_growth(new: Iterable[str], existing: Iterable[str]) -> str | None:
    """Return an abort reason if the covered address space grew suspiciously:
    by more than (factor - 1) x the existing space without its largest prefix,
    plus the slack. No existing file = nothing to compare."""
    existing = list(existing)
    if not existing:
        return None
    n4, n6 = address_space(new)
    e4, e6 = address_space(existing)
    b4, b6 = address_space(existing, drop_largest=True)
    allow4 = b4 * (MAX_SPACE_GROWTH_FACTOR - 1) + SPACE_GROWTH_SLACK_V4
    allow6 = b6 * (MAX_SPACE_GROWTH_FACTOR - 1) + SPACE_GROWTH_SLACK_V6
    if n4 - e4 > allow4:
        return f"IPv4 space grew by {n4 - e4} addresses (from {e4}; allowed {int(allow4)}; poisoned feed?)"
    if n6 - e6 > allow6:
        return f"IPv6 space grew by {n6 - e6} /64s (from {e6}; allowed {int(allow6)}; poisoned feed?)"
    return None


def existing_source_counts(path: str) -> dict[str, int]:
    """Per-source prefix counts from the ``# source: <name>  (<kind>, <n> prefixes)``
    header lines of an existing output file."""
    counts: dict[str, int] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if not line.startswith("# source: "):
                    continue
                name, _, rest = line[len("# source: "):].partition("  (")
                num = rest.rsplit(", ", 1)[-1].split(" ", 1)[0]
                if num.isdigit():
                    counts[name.strip()] = int(num)
    except OSError:
        pass
    return counts


def shrunk_sources(results: list[SourceResult], previous: dict[str, int]) -> list[str]:
    """Sources that answered with less than half their previous count."""
    out = []
    for res in results:
        before = previous.get(res.name, 0)
        if before >= MIN_SOURCE_COUNT_FOR_SHRINK and len(res.prefixes) < before * MAX_SOURCE_SHRINK_FRACTION:
            out.append(f"{res.name} {before}->{len(res.prefixes)}")
    return out


def check_thresholds(new_count: int, existing_count: int) -> str | None:
    """Return an abort reason if the new list is unsafe to write, else None.

    Guards against a partial-feed run silently gutting the list (which for a
    fail-closed geo include means fewer bypasses = more challenges, an
    availability regression) and against a runaway/oversized result."""
    if new_count < MIN_PREFIXES_TOTAL:
        return f"only {new_count} prefixes (< MIN_PREFIXES_TOTAL={MIN_PREFIXES_TOTAL})"
    if new_count > MAX_PREFIXES_TOTAL:
        return f"{new_count} prefixes (> MAX_PREFIXES_TOTAL={MAX_PREFIXES_TOTAL})"
    if existing_count > 0 and new_count < existing_count * (1.0 - MAX_SHRINK_FRACTION):
        return (f"{new_count} prefixes is a >{int(MAX_SHRINK_FRACTION * 100)}% shrink "
                f"vs the existing {existing_count} (partial-feed failure?)")
    return None


def render_output(results: list[SourceResult], output: str, union: set[str]) -> None:
    lines: list[str] = [
        "# Auto-generated nginx/OpenResty geo include for $cfm_bypass_ip",
        f"# Generated at: {datetime.now(timezone.utc).isoformat()}",
        "# Format: <cidr> 1;",
        "#",
        "#   geo $cfm_bypass_ip {",
        "#       default 0;",
        f"#       include {oneline(os.path.basename(output))};",
        "#   }",
        "#",
    ]
    for res in results:
        lines.append(f"# source: {oneline(res.name)}  ({oneline(res.kind)}, {len(res.prefixes)} prefixes)")
        lines.append(f"#   {oneline(res.origin)}")
        for k, v in sorted(res.meta.items()):
            lines.append(f"#   {oneline(k)}: {oneline(v)}")
    lines.append("")

    for prefix in sorted(union, key=sort_key):
        lines.append(f"{prefix} 1;")

    data = "\n".join(lines).rstrip() + "\n"

    # Atomic write: a crash / concurrent nginx reload mid-write must never see a
    # truncated geo file. Write a sibling temp file, fsync, then rename in place.
    directory = os.path.dirname(os.path.abspath(output)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".challenge_waf_bypass.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        # mkstemp creates 0600; restore the umask-default 0644 so an in-place
        # regenerate against a live path stays world-readable for nginx.
        os.chmod(tmp, 0o644)
        os.replace(tmp, output)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    print(f"Wrote {output} with {len(union)} unique prefixes from {len(results)} source(s)")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser(description="Build challenge_waf_bypass.conf")
    p.add_argument("output", nargs="?", default=DEFAULT_OUTPUT, help="Output file path")
    p.add_argument("--strict", action="store_true",
                   help="write nothing (exit 3, existing file kept) if ANY source failed, "
                        "returned no prefixes, or (for a source of 10+ prefixes) shrank to "
                        "under half its previous count; used by `make release` so a feed "
                        "outage can't drop that feed's ranges")
    p.add_argument("--allow-growth", action="store_true",
                   help="skip the address-space growth guard (a reviewed manual run that adds a source)")
    args = p.parse_args()

    results: list[SourceResult] = []
    errors: list[str] = []

    for spec in SOURCES:
        try:
            for res in load_source(spec):
                if len(res.prefixes) > MAX_PREFIXES_PER_SOURCE:
                    # A source suddenly emitting a huge set is a red flag (feed
                    # compromise / format change). Refuse the whole run rather
                    # than trust it; the existing file is kept untouched.
                    eprint(f"ERROR: source {res.name} produced {len(res.prefixes)} prefixes "
                           f"(> MAX_PREFIXES_PER_SOURCE={MAX_PREFIXES_PER_SOURCE}); aborting, keeping existing file")
                    return 2
                results.append(res)
        except Exception as exc:
            errors.append(f"{spec}: {exc}")
            eprint(f"ERROR [{spec}]: {exc}")

    if not results:
        eprint("ERROR: no sources produced results; keeping existing file")
        return 1

    empty = [r.name for r in results if not r.prefixes]
    if empty:
        eprint("WARNING: zero prefixes from:", ", ".join(empty))
    # An empty answer (HTTP 200 with a maintenance page or a changed JSON shape)
    # drops that feed's ranges just like an exception does.
    shrunk = shrunk_sources(results, existing_source_counts(args.output)) if args.strict else []
    if shrunk:
        eprint("WARNING: shrank to under half their previous count:", ", ".join(shrunk))
    if (errors or empty or shrunk) and args.strict:
        eprint(f"ERROR: {len(errors)} source(s) failed, {len(empty)} returned no prefixes, "
               f"{len(shrunk)} shrank by over half; --strict is set; keeping existing file at {args.output}")
        return 3
    if errors:
        eprint(f"WARNING: {len(errors)} source(s) failed, continuing with {len(results)} that succeeded")

    union: set[str] = set()
    for res in results:
        union.update(res.prefixes)

    # Fail-safe: never replace a good list with a suspiciously small/large one.
    existing = existing_prefixes(args.output)
    reason = check_thresholds(len(union), len(existing))
    if reason is None and not args.allow_growth:
        reason = check_space_growth(union, existing)
    if reason is not None:
        eprint(f"ERROR: refusing to write ({reason}); keeping existing file at {args.output}")
        return 2

    render_output(results, args.output, union)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
