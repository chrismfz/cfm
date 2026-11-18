-- Tests for scripts/waf_corpus/run.lua, the labelled-corpus runner
-- (BlazeHTTP). No network: synthetic samples only. Pins the nginx emulation
-- (what ngx.var.uri would be, which header names nginx drops), the raw
-- request parser, the base64 stand-in, and that a sample goes through the
-- real cfm_waf.check() with the verdicts the WAF's own tests expect.

local M = dofile("scripts/waf_corpus/run.lua")
local waf = require("cfm_waf")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function eq(got, want, msg)
  check(got == want, msg .. " (got " .. tostring(got) .. ", want " .. tostring(want) .. ")")
end

-- ── ngx.var.uri emulation ──────────────────────────────────────────────────
eq(M.nginx_uri("/a/b"), "/a/b", "plain path")
eq(M.nginx_uri("/a%20b/%2e%2e/c"), "/c", "decoded, then dot segments resolved")
eq(M.nginx_uri("//a///b/"), "/a/b/", "slashes merged, trailing slash kept")
eq(M.nginx_uri("/a/./b/../c"), "/a/c", "dot segments")
eq(M.nginx_uri("/a/.."), "/", "dot-dot to the root")
eq(M.nginx_uri("/"), "/", "root")
eq(M.nginx_uri("/../etc/passwd"), nil, "above the root is a 400")
eq(M.nginx_uri("/a%zz"), nil, "bad %-escape is a 400")
eq(M.nginx_uri("/a%2"), nil, "truncated %-escape is a 400")
eq(M.nginx_uri("/a+b"), "/a+b", "+ is not a space in the path")
eq(M.nginx_uri("/index.php%00.jpg"), nil, "an escaped NUL is a 400 (ngx_http_parse_complex_uri)")
eq(M.nginx_uri("/a%2fb/%2e"), "/a/b/", "an escaped / and . take part in normalization")

-- ── base64 stand-in (ngx.decode_base64: nil on bad input) ──────────────────
eq(M.decode_base64("PD9waHA="), "<?php", "base64 with padding")
eq(M.decode_base64("YWJj"), "abc", "base64 without padding")
eq(M.decode_base64("YWJ"), "ab", "unpadded input decodes, as in nginx")
eq(M.decode_base64("YWJjZA"), "abcd", "unpadded, 2 chars over")
eq(M.decode_base64("YWJjZ"), nil, "length 1 mod 4 is refused")
eq(M.decode_base64("YQ==junk"), "a", "bytes after the first = are ignored")
eq(M.decode_base64("YWJjZGVmZ2g="), "abcdefgh", "padded, longer")
eq(M.decode_base64("YW!j"), nil, "invalid character")
eq(M.decode_base64(""), "", "empty")

-- ── raw request parser ─────────────────────────────────────────────────────
local raw = "POST http://h.example/x/y.php?a=1&b=%3C HTTP/1.1\r\n" ..
            "Host: 10.0.0.1\r\n" ..
            "X-Forwarded-For: 1.1.1.1\r\n" ..
            "X-Dup: one\r\nX-Dup: two\r\n" ..
            "Bad_Name: dropped\r\n" ..
            "Content-Type: application/x-www-form-urlencoded\r\n\r\n" ..
            "q=1\r\nz=2"
local r = assert(M.parse(raw))
eq(r.method, "POST", "method")
eq(r.raw_path, "/x/y.php", "absolute-form target reduced to the path")
eq(r.args, "a=1&b=%3C", "query kept raw")
eq(r.raw_uri, "/x/y.php?a=1&b=%3C", "raw uri")
eq(r.headers.host, "10.0.0.1", "header names lowercased")
eq(type(r.headers["x-dup"]), "table", "a repeated header is a list")
eq(r.headers["x-dup"] and r.headers["x-dup"][2], "two", "list keeps order")
eq(r.headers["bad_name"], nil, "underscore header dropped (underscores_in_headers off)")
eq(r.body, "q=1\r\nz=2", "body is everything after the blank line")
local r2 = assert(M.parse("GET /p HTTP/1.1\nHost: x\n\n"))
eq(r2.raw_path, "/p", "LF-only sample parses")
check(M.parse("garbage") == nil, "a non-HTTP sample does not parse")
local r3 = M.parse("GET /q HTTP/1.1\r\nHost: x\r\n")
check(r3 and r3.raw_path == "/q" and r3.headers.host == "x", "CRLF request saved without the final blank line parses")
local r4 = M.parse("GET /q HTTP/1.1\r\nHost: x")
check(r4 and r4.headers.host == "x", "CRLF request with no line ending after the last header parses")
local r5 = assert(M.parse("POST /p HTTP/1.1\nHost: x\n\nbody\r\n"))
eq(r5.body, "body\r\n", "LF head, body kept byte for byte")

-- ── evaluate: the real WAF on a parsed sample ──────────────────────────────
local opts = { max_body = 32768 }
local function run(s, o) return M.evaluate(waf, assert(M.parse(s)), o or opts, 1) end
local UA = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " ..
           "(KHTML, like Gecko) Chrome/120.0 Safari/537.36\r\nAccept: text/html\r\nAccept-Language: en-US,en;q=0.9\r\n"

local sqli = run("GET /item?id=1%27%20union%20select%201,2,3--%20 HTTP/1.1\r\nHost: a.example\r\n" .. UA .. "\r\n")
eq(sqli.outcome, "block", "union select in the query blocks")
eq(sqli.headline, 301, "as rule 301")

local clean = run("GET /blog/hello-world/?utm_source=x HTTP/1.1\r\nHost: a.example\r\n" .. UA .. "\r\n")
eq(clean.outcome, "clean", "an ordinary page view is clean")

local trav = run("GET /../../etc/passwd HTTP/1.1\r\nHost: a.example\r\n" .. UA .. "\r\n")
eq(trav.outcome, "nginx_400", "a path above the root never reaches the WAF")

-- Host is rewritten unless --keep-host: an IP-literal Host must not decide.
local iphost = "GET / HTTP/1.1\r\nHost: 10.10.3.128\r\n" .. UA .. "\r\n"
eq(run(iphost).outcome, "clean", "IP-literal Host rewritten by default")
check(run(iphost, { max_body = 32768, keep_host = true }).ids[1] ~= nil,
      "--keep-host passes the IP-literal Host to the WAF")

-- A body-borne hit is tagged as needing the body.
local body = run("POST /contact HTTP/1.1\r\nHost: a.example\r\n" .. UA ..
                 "Content-Type: application/x-www-form-urlencoded\r\n\r\n" ..
                 "id=1%27%20union%20select%201,2,3--%20")
eq(body.outcome, "block", "union select in a urlencoded body blocks")
check(body.body_dep == true and body.body_ct_ok == true, "body hit tagged: needs the body, CT read on any path")

-- GET bodies are not handed to the WAF (the edge reads POST/PUT/PATCH only).
local getbody = run("GET /x HTTP/1.1\r\nHost: a.example\r\n" .. UA ..
                    "Content-Type: application/x-www-form-urlencoded\r\n\r\n" ..
                    "id=1%27%20union%20select%201,2,3--%20")
eq(getbody.outcome, "clean", "a GET body is not inspected")

-- Content-Length as BlazeHTTP sends it: the body's length, or no header.
local cl0 = assert(M.parse("POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"))
M.evaluate(waf, cl0, opts, 1)
eq(cl0.headers["content-length"], nil, "no body: Content-Length removed")
local clx = assert(M.parse("POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 99\r\n\r\nabc"))
M.evaluate(waf, clx, opts, 1)
eq(clx.headers["content-length"], "3", "a stale Content-Length is set to the body's length")
local clg = assert(M.parse("GET /p HTTP/1.1\r\nHost: x\r\n\r\nabcd"))
M.evaluate(waf, clg, opts, 1)
eq(clg.headers["content-length"], "4", "a GET with a body gets its length too")

-- --keep-host tells the WAF the sample's host (lowercased, no port).
local seen_host
local spy = { check = function(ctx) seen_host = ctx.host; return false end }
M.evaluate(spy, assert(M.parse("GET / HTTP/1.1\r\nHost: WWW.Example.COM:8080\r\n\r\n")),
           { max_body = 32768, keep_host = true }, 1)
eq(seen_host, "www.example.com", "--keep-host: ctx.host is the Host header")
M.evaluate(spy, assert(M.parse("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")), opts, 1)
eq(seen_host, "waf-corpus.example", "default: ctx.host is the neutral host")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("waf_corpus_runner_test: ok")
