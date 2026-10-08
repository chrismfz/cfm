#!/usr/bin/env python3
"""Differential check of cfm_waf_detectors.php_request_fields against real PHP.

The WAF's field-keyed rules (10017, 10018/10019/10020) read a request the way
PHP registers it. This script builds crafted query strings and POST bodies
(urlencoded and multipart, with the spellings where parsers disagree: boundary
lines, header continuations, the 5120-byte line cut, quoting, escapes, NULs,
duplicate parameters), sends each to `php -S` (the cli-server SAPI runs the
same rfc1867.c / php_variables.c as php-fpm), and records what PHP put in
$_GET + $_POST. The Lua reader must produce every name PHP registered, with
PHP's value as its last value.

    php_request_fields_oracle.py check [N]     # N random cases (default 3000) + the fixed ones
    php_request_fields_oracle.py record        # rewrite the CI fixture (fixed + seeded random cases)

`record` writes scripts/tests/fixtures/php_request_fields.lua, which
cfm_waf_php_request_fields_test.lua replays in CI without PHP. Needs php (8.x)
and luajit on PATH; run from the repository root.
"""
import json, os, random, socket, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURE = os.path.join(ROOT, "scripts/tests/fixtures/php_request_fields.lua")
ROUTER = "<?php header('Content-Type: application/json');" \
         "echo json_encode(['get'=>$_GET,'post'=>$_POST], JSON_INVALID_UTF8_SUBSTITUTE|JSON_PARTIAL_OUTPUT_ON_ERROR);"


def start_php():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "r.php"), "w") as f:
        f.write(ROUTER)
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    p = subprocess.Popen(["php", "-d", "max_input_vars=100000", "-d", "post_max_size=8M",
                          "-S", f"127.0.0.1:{port}", os.path.join(d, "r.php")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port)).close(); break
        except OSError:
            time.sleep(0.1)
    return p, port


def php(port, case):
    body = case["body"].encode("latin-1")
    q = ("?" + case["query"]) if case["query"] else ""
    head = f"{case['method']} /r{q} HTTP/1.1\r\nHost: t\r\nContent-Type: {case['ct']}\r\n" \
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(head.encode("latin-1") + body)
    out = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        out += d
    s.close()
    res = json.loads(out.split(b"\r\n\r\n", 1)[1].decode("utf-8"))
    merged = {}
    for src in ("get", "post"):
        v = res[src]
        if isinstance(v, dict):
            for k, val in v.items():
                merged[k] = val if isinstance(val, str) else None  # None: an array
    return merged


# ── case generation ─────────────────────────────────────────────────────────
NAMES = ["action", "string_ids", "trp-edit-translation", "user_login", "pagename", "a", "a.b", "a b",
         "a[b", "a[b]", "a[b[c", "\taction", " action", "act\x00ion", "wc[reset[password", "x"]
VALUES = ["v", "trp_get_translations_regular", "lostpassword", "[680]", "", "a\r", "x--b", "\r\n", "1\x002"]


def gen_urlencoded(r):
    parts = []
    for _ in range(r.randint(0, 6)):
        k = r.choice(NAMES)
        k = "".join(c if r.random() < 0.8 else "%%%02X" % ord(c) for c in k).replace(" ", r.choice([" ", "+", "%20"]))
        k = k.replace("\x00", "%00").replace("\t", "%09").replace("[", r.choice(["[", "%5B"]))
        v = r.choice(VALUES).replace("\r", "%0D").replace("\n", "%0A").replace("\x00", "%00")
        sep = r.choice(["=", "=", "=", "", "=="])
        parts.append(k + sep + (v if sep else ""))
    joiner = r.choice(["&", "&", "&&"])
    return joiner.join(parts)


def gen_multipart(r, bnd):
    nl = lambda: r.choice(["\r\n", "\r\n", "\n"])
    out = []
    if r.random() < 0.2:
        out.append(r.choice(["preamble", "x--" + bnd, "--" + bnd + "X", "--" + bnd + " "]) + nl())
    for _ in range(r.randint(1, 4)):
        out.append(r.choice(["--" + bnd] * 6 + ["--" + bnd + "X", "--" + bnd + "--", "--" + bnd + "\x00z"]) + nl())
        for _ in range(r.randint(0, 3)):
            kind = r.random()
            if kind < 0.55:
                name = r.choice(NAMES)
                q = r.choice(['"', '"', "'", ""])
                if r.random() < 0.15:
                    name = name.replace("a", "a\\\"", 1) if q else name
                key = r.choice(["name", "name", "NAME", "name ", " name", "filename"])
                eq = r.choice(["=", "=", "==", " ="])
                params = [r.choice(["form-data", "form-data", "", "x=\"\\\\\"", "x='a;b'"])]
                params.append(f"{key}{eq}{q}{name}{q}")
                if r.random() < 0.25:
                    params.append(f"name={q}{r.choice(NAMES)}{q}")
                if r.random() < 0.1:
                    params.append('filename="f.txt"')
                sep = r.choice(["; ", ";", ";;", "; \t", ";\r\n "])
                hname = r.choice(["Content-Disposition", "content-disposition", "Content-Disposition ", "X-CD"])
                colon = r.choice([": ", ":", ":\t"])
                line = hname + colon + sep.join(params)
                if r.random() < 0.1:  # split the name across a continuation line
                    cut = r.randint(1, len(line) - 1)
                    line = line[:cut] + nl() + r.choice(["", " ", "\t"]) + line[cut:]
                out.append(line + nl())
            elif kind < 0.7:
                pad = r.choice([5117, 5120, 5122, 10240])
                out.append("X: " + "p" * (pad - 3) + 'Content-Disposition: form-data; name="' + r.choice(NAMES) + '"' + nl())
            elif kind < 0.85:
                out.append(r.choice(["Content-Type: text/plain", "X-A: b", "nocolon", " cont"]) + nl())
            else:
                out.append("X: a\x00" + 'Content-Disposition: form-data; name="nul"' + nl())
        if r.random() < 0.9:
            out.append(nl())
        out.append(r.choice(VALUES) + r.choice(["", "", "\r", "x\n--" + bnd + "X"]) + nl())
    if r.random() < 0.8:
        out.append("--" + bnd + "--" + nl())
    return "".join(out)


def gen_case(r):
    method = r.choice(["POST"] * 9 + ["PUT"])
    query = gen_urlencoded(r).replace(" ", "%20") if r.random() < 0.4 else ""  # a raw space ends the request line
    if r.random() < 0.3:
        ct = r.choice(["application/x-www-form-urlencoded", "application/x-www-form-urlencoded; charset=UTF-8",
                       "application/x-www-form-urlencoded; x=multipart/form-data", "Application/X-WWW-Form-Urlencoded,x",
                       "application/x-www-form-urlencodedx", "text/plain"])
        return {"method": method, "query": query, "ct": ct, "body": gen_urlencoded(r)}
    bnd = r.choice(["b", "----WebKitFormBoundaryX", "a b", "x;y"])
    btoken = r.choice(['boundary=' + bnd, 'boundary="' + bnd + '"', 'BOUNDARY=' + bnd,
                       'boundary=' + bnd + '; boundary=zz', 'boundary="' + bnd + '"; x=1', 'x=boundary; boundary=' + bnd])
    ct = r.choice(["multipart/form-data; ", "multipart/form-data;", "Multipart/Form-Data; ",
                   "multipart/form-data, ", "text/plain; x=multipart/form-data; "]) + btoken
    return {"method": method, "query": query, "ct": ct, "body": gen_multipart(r, bnd)}


FIXED = [
    {"method": "POST", "query": "", "ct": "multipart/form-data; boundary=----b",
     "body": "------bX\r\n\r\n------b\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\ntrp\r\n------b--\r\n"},
    {"method": "POST", "query": "", "ct": "multipart/form-data; boundary=----b",
     "body": "------b\r\nContent-Disposition: form-data; name=\"trp-edit-\r\ntranslation\"\r\n\r\nv\r\n------b--\r\n"},
    {"method": "POST", "query": "", "ct": "multipart/form-data; boundary=----b",
     "body": "------b\r\nContent-Disposition: form-data; name==\"action\"\r\n\r\nv\r\n------b--\r\n"},
    {"method": "POST", "query": "", "ct": "multipart/form-data; boundary=----b",
     "body": "------b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n------b\r\nContent-Disposition: form-data; name=\"wc\"\r\n"},
    {"method": "POST", "query": "", "ct": "multipart/form-data; boundary=b",
     "body": "--b\r\nX: " + "a" * 5117 + "Content-Disposition: form-data; name=\"zz\"\r\n\r\nv\r\n--b--\r\n"},
    {"method": "POST", "query": "", "ct": "multipart/form-data; boundary=b",
     "body": "--b\r\nContent-Disposition: form-data; x=\"\\\\\"; name=\"q\"\r\n\r\nv\r\n--b--\r\n"},
    {"method": "POST", "query": "", "ct": "application/x-www-form-urlencoded",
     "body": "wc%5Breset%5Bpass.word=1&a.b=1&+c=1&%09d=1&e%00f=1&g[h=1&i[j]k=1"},
]


def _lua_lit(s):
    return '"' + "".join(c if (32 <= ord(c) < 127 and c not in '"\\') else "\\%03d" % ord(c) for c in s) + '"'


def lua_quote(s):
    """A Lua string expression for s; a run of 64+ equal bytes (the 5120-byte
    line pads) becomes ("x"):rep(n) so the fixture stays small."""
    import re
    parts, last = [], 0
    for m in re.finditer(r"(.)\1{63,}", s, re.S):
        if m.start() > last:
            parts.append(_lua_lit(s[last:m.start()]))
        parts.append("(%s):rep(%d)" % (_lua_lit(m.group(1)), len(m.group(0))))
        last = m.end()
    if last < len(s) or not parts:
        parts.append(_lua_lit(s[last:]))
    return " .. ".join(parts)


def to_lua(cases):
    out = ["-- GENERATED by scripts/tests/php_request_fields_oracle.py record: PHP " +
           subprocess.run(["php", "-r", "echo PHP_VERSION;"], capture_output=True, text=True).stdout +
           "'s $_GET + $_POST for each request. Do not edit; re-record.", "return {"]
    for c in cases:
        want = ", ".join("[%s] = %s" % (lua_quote(k), "true" if v is None else lua_quote(v)) for k, v in sorted(c["want"].items()))
        out.append("  { method = %s, query = %s, ct = %s, body = %s, want = { %s } }," % (
            lua_quote(c["method"]), lua_quote(c["query"]), lua_quote(c["ct"]), lua_quote(c["body"]), want))
    out.append("}")
    return "\n".join(out) + "\n"


def run_lua(fixture_path):
    r = subprocess.run(["luajit", os.path.join(ROOT, "scripts/tests/cfm_waf_php_request_fields_test.lua"), fixture_path],
                       cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    proc, port = start_php()
    try:
        if mode == "record":
            r = random.Random(19632)
            cases = FIXED + [gen_case(r) for _ in range(400)]
        else:
            n = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
            r = random.Random(int(time.time()))
            cases = FIXED + [gen_case(r) for _ in range(n)]
        for c in cases:
            c["want"] = php(port, c)
    finally:
        proc.terminate()
    if mode == "record":
        with open(FIXTURE, "w", encoding="latin-1") as f:
            f.write(to_lua(cases))
        code, out = run_lua(FIXTURE)
    else:
        fd, path = tempfile.mkstemp(suffix=".lua")
        with os.fdopen(fd, "w", encoding="latin-1") as f:
            f.write(to_lua(cases))
        code, out = run_lua(path)
        os.unlink(path)
    sys.stdout.write(out)
    sys.exit(code)


if __name__ == "__main__":
    main()
