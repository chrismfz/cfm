#!/usr/bin/env python3
"""check_edge_peer_header.py: every edge proxy_pass sends X-CFM-Peer.

WHY: an origin that keys security on the TCP peer (NGM's panel login limiter,
mail guard and auth-log bans) reads X-CFM-Peer from a loopback peer, because
CF-Connecting-IP / X-Real-IP carry the visitor the edge resolved, which a
Cloudflare Worker writes itself. nginx forwards a client's headers by
default, so a proxy_pass whose effective proxy_set_header list lacks
`X-CFM-Peer $realip_remote_addr` would hand the origin a CLIENT's own
X-CFM-Peer.

The effective list follows nginx's inheritance: a block that sets any
proxy_set_header uses only its own list; one that sets none inherits its
parent's. So for each proxy_pass, the innermost enclosing block (the
proxy_pass's own included) that sets any proxy_set_header must set
X-CFM-Peer, with exactly $realip_remote_addr.

Not checked, by decision: cfm-panel-listeners.conf(.in), the panel-port
listeners (2082-2096). They front cPanel / DirectAdmin's own daemons, which
read no X-CFM-Peer, through cfm_panel_tunnel.lua's raw byte tunnel; NGM's
panel listens itself (9601) and its nginx's X-CFM-Peer map is reached only
through the web DNAT (80/443). Panel DNAT in front of an NGM nginx port would
need this check (or a cleared header) there too.

The parser understands quotes, # comments and *_by_lua_block bodies (Lua
strings, long brackets and -- comments), and fails rather than guess: an
unbalanced brace, or a proxy_pass count that differs from a plain text count.
"""
import re
import sys

PEER_VALUE = "$realip_remote_addr"


class ParseError(Exception):
    pass


def skip_lua_block(s, i, line):
    """s[i] is just past the '{' of a *_by_lua_block; return the index just
    past its matching '}' and the line number there."""
    depth = 1
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\n":
            line += 1
            i += 1
        elif s.startswith("--", i):
            m = re.match(r"--\[(=*)\[", s[i:])
            if m:
                close = "]" + m.group(1) + "]"
                j = s.find(close, i + len(m.group(0)))
                if j < 0:
                    raise ParseError(f"line {line}: unterminated Lua long comment")
                line += s.count("\n", i, j)
                i = j + len(close)
            else:
                j = s.find("\n", i)
                i = n if j < 0 else j
        elif c in "\"'":
            j = i + 1
            while j < n and s[j] != c:
                if s[j] == "\\":
                    j += 1
                elif s[j] == "\n":
                    raise ParseError(f"line {line}: newline in a Lua string")
                j += 1
            if j >= n:
                raise ParseError(f"line {line}: unterminated Lua string")
            i = j + 1
        elif c == "[" and re.match(r"\[(=*)\[", s[i:]):
            m = re.match(r"\[(=*)\[", s[i:])
            close = "]" + m.group(1) + "]"
            j = s.find(close, i + len(m.group(0)))
            if j < 0:
                raise ParseError(f"line {line}: unterminated Lua long string")
            line += s.count("\n", i, j)
            i = j + len(close)
        elif c == "{":
            depth += 1
            i += 1
        elif c == "}":
            depth -= 1
            i += 1
            if depth == 0:
                return i, line
        else:
            i += 1
    raise ParseError("unterminated *_by_lua_block")


def parse(s):
    """Yield (kind, data): ('open', (words, line)), ('close', line),
    ('stmt', (words, line))."""
    i, n, line = 0, len(s), 1
    words, cur, start = [], [], None
    while i < n:
        c = s[i]
        if c == "\n":
            line += 1
        if c in "\"'":
            j = i + 1
            while j < n and s[j] != c:
                if s[j] == "\\":
                    j += 1
                j += 1
            if j >= n:
                raise ParseError(f"line {line}: unterminated quote")
            line += s.count("\n", i, j)
            cur.append(s[i + 1:j])
            start = start or line
            i = j + 1
            continue
        if c == "#":
            j = s.find("\n", i)
            i = n if j < 0 else j
            continue
        if c.isspace() or c in ";{}":
            if cur:
                words.append("".join(cur))
                cur = []
            if c == ";":
                if words:
                    yield "stmt", (words, start)
                words, start = [], None
            elif c == "{":
                yield "open", (words, start or line)
                if words and words[0].endswith("_by_lua_block"):
                    i, line = skip_lua_block(s, i + 1, line)
                    yield "close", line
                    words, start = [], None
                    continue
                words, start = [], None
            elif c == "}":
                if words:
                    raise ParseError(f"line {line}: statement without ';' before '}}'")
                yield "close", line
            i += 1
            continue
        cur.append(c)
        start = start or line
        i += 1
    if cur or words:
        raise ParseError("trailing statement without ';'")


def check(path):
    s = open(path, encoding="utf-8").read()
    errors = []
    # frames: dicts {sets_any, sets_peer, line}
    stack = [{"sets_any": False, "sets_peer": False, "line": 0}]
    passes = []  # (line, [frames innermost..outermost])
    for kind, data in parse(s):
        if kind == "open":
            stack.append({"sets_any": False, "sets_peer": False, "line": data[1]})
        elif kind == "close":
            if len(stack) == 1:
                raise ParseError(f"line {data}: '}}' closes nothing")
            stack.pop()
        else:
            words, line = data
            if words[0] == "proxy_set_header":
                stack[-1]["sets_any"] = True
                if len(words) >= 2 and words[1].lower() == "x-cfm-peer":
                    if words[2:] == [PEER_VALUE]:
                        stack[-1]["sets_peer"] = True
                    else:
                        errors.append(f"{line}: X-CFM-Peer set to {' '.join(words[2:])!r}, not {PEER_VALUE}")
            elif words[0] == "proxy_pass":
                passes.append((line, list(reversed(stack))))
    if len(stack) != 1:
        raise ParseError(f"{len(stack) - 1} block(s) never closed")
    for line, frames in passes:
        for f in frames:
            if f["sets_any"]:
                if not f["sets_peer"]:
                    errors.append(f"{line}: proxy_pass whose proxy_set_header list (block at line {f['line']}) lacks X-CFM-Peer {PEER_VALUE}")
                break
        else:
            errors.append(f"{line}: proxy_pass with no proxy_set_header list at all (a client's X-CFM-Peer passes through)")
    # A plain text count, outside comment lines, must agree with the parser.
    plain = sum(1 for ln in s.splitlines() if re.search(r"(^|[\s;{])proxy_pass\s", ln) and not ln.lstrip().startswith("#"))
    if plain != len(passes):
        errors.append(f"the parser found {len(passes)} proxy_pass, a text count {plain}: the check is not reading what is there")
    return passes, errors


def main(argv):
    confs = argv[1:] or ["configs/openresty.conf", "configs/angie.conf", "configs/cfm-edge.conf"]
    fail = False
    for c in confs:
        try:
            passes, errors = check(c)
        except (OSError, ParseError) as e:
            print(f"❌ {c}: {e}", file=sys.stderr)
            fail = True
            continue
        if not passes:
            print(f"❌ {c}: no proxy_pass found — the check read nothing", file=sys.stderr)
            fail = True
        elif errors:
            for e in errors:
                print(f"❌ {c}:{e}", file=sys.stderr)
            fail = True
        else:
            print(f"✅ {c}: all {len(passes)} proxy_pass send X-CFM-Peer {PEER_VALUE}")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
