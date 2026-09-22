-- Tests for the WordPress core page-template traversal detectors
-- (CVE-2026-87902, GHSA-7hp8-65ch-5whp; WordPress 4.7.0–7.1.1):
--
--   rule 10017  rule_cve_wp_pagename_traversal  (WAF_CVE, block, armed)
--     a `pagename` query var — query string, urlencoded or multipart POST —
--     whose value holds a `..` segment. get_page_template() builds
--     page-{$pagename}.php from it without the `..` check.
--
--   rule 103    rule_traversal_raw_path         (WAF_TRAVERSAL, block)
--     a `..` segment in the RAW request path. ngx.var.uri (ctx.uri, what rule
--     101 scans) is already dot-segment-resolved by nginx; the origin gets the
--     raw path, which WordPress pretty permalinks turn into `pagename`.
--
-- Positives use inert placeholder targets: the detectors key on the `..`
-- segment in the vector, not on what the traversal reaches.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- ── Shipped tiers ────────────────────────────────────────────────────────────
local cfg = waf.get_config()
check(cfg.rule_cve_wp_pagename_traversal == "block",
      "rule_cve_wp_pagename_traversal ships at block (got " .. tostring(cfg.rule_cve_wp_pagename_traversal) .. ")")
check(cfg.rule_traversal_raw_path == "block",
      "rule_traversal_raw_path ships at block (got " .. tostring(cfg.rule_traversal_raw_path) .. ")")

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

-- ctx.uri is what nginx hands the WAF (decoded + dot segments resolved);
-- raw_uri is the untouched $request_uri. For the pagename tests the path is
-- plain, so both are the same.
local function get(path, args, raw_uri)
  return { uri = path, raw_uri = raw_uri or (path .. (args and args ~= "" and ("?" .. args) or "")),
           args = args or "", method = "GET", ip = "203.0.113.81", headers = {}, body = "" }
end
local function post(path, body, ct, args)
  return { uri = path, raw_uri = path, args = args or "", method = "POST", ip = "203.0.113.82",
           headers = { ["Content-Type"] = ct }, body = body }
end

local function fires(c, label, want_reason)
  local hit, reason, _, action = waf.check(c)
  check(hit == true and action == "block", label .. " — blocks (got hit=" .. tostring(hit) .. " action=" .. tostring(action) .. ")")
  check(reason == want_reason, label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

-- ═══ Rule 10017 — the `pagename` query var ═══════════════════════════════════
set_only({ rule_cve_wp_pagename_traversal = "block" })
local ARG  = "WAF_CVE:CVE_2026_87902:WORDPRESS:ARG"
local BODY = "WAF_CVE:CVE_2026_87902:WORDPRESS:BODY"

fires(get("/", "pagename=templates/../../../../placeholder"), "plain ../ segments", ARG)
fires(get("/", "pagename=templates%2F..%2F..%2Fplaceholder"), "percent-encoded separators", ARG)
fires(get("/", "pagename=templates/%2e%2e/%2E%2E/placeholder"), "percent-encoded dots (mixed case)", ARG)
fires(get("/", "pagename=templates/%252e%252e/placeholder"), "double-encoded dots", ARG)
fires(get("/", "pagename=templates%5c..%5cplaceholder"), "backslash separators", ARG)
fires(get("/", "pagename=templates/.."), "trailing .. segment", ARG)
fires(get("/", "page%6eame=templates/../../placeholder"), "percent-encoded key (PHP decodes keys)", ARG)
fires(get("/", "pagename=a%26/../../placeholder"), "%26 inside the value cannot split it", ARG)
fires(get("/", "pagename=about&pagename=templates/../../placeholder"), "later duplicate (PHP keeps the last)", ARG)
fires(get("/index.php", "p=1&pagename=templates/../../placeholder"), "not the first parameter", ARG)

fires(post("/", "pagename=templates%2F..%2F..%2Fplaceholder", "application/x-www-form-urlencoded"),
      "urlencoded POST body ($_POST wins in WP)", BODY)
local MP = "multipart/form-data; boundary=----B"
fires(post("/", "------B\r\nContent-Disposition: form-data; name=\"pagename\"\r\n\r\n" ..
                "templates/../../placeholder\r\n------B--\r\n", MP),
      "multipart field", BODY)
fires(post("/", "------B\r\nContent-Disposition: form-data; name=\"pagename\"\r\n" ..
                "Content-Type: text/plain\r\n\r\ntemplates/../../placeholder\r\n------B--\r\n", MP),
      "multipart field with an extra part header", BODY)

fires(get("/", "pagename%5B%5D=templates/../../placeholder"), "array-suffixed key", ARG)
fires(get("/", "+pagename=templates/../../placeholder"), "key with leading whitespace", ARG)
fires(get("/", ("pad=" .. string.rep("a", 3000)) .. "&pagename=templates/../../placeholder"),
      "pagename past the 2048-byte memoized window (GET, no Content-Type)", ARG)
fires(post("/", ("pad=" .. string.rep("a", 3000)) .. "&pagename=templates/../../placeholder",
           "application/x-www-form-urlencoded"), "pagename past 2 KB of urlencoded body", BODY)
fires(post("/", "------B\r\nContent-Disposition: form-data; name='pagename'\r\n\r\n" ..
                "templates/../../placeholder\r\n------B--\r\n", "multipart/form-data; boundary=----B"),
      "multipart field, single-quoted name", BODY)
fires(post("/", "------B\r\nContent-Disposition: form-data; name=pagename\r\n\r\n" ..
                "templates/../../placeholder\r\n------B--\r\n", "multipart/form-data; boundary=----B"),
      "multipart field, bare name", BODY)

clean(get("/", "pagename=about"), "a page slug")
clean(post("/", "------B\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"pagename\"\r\n\r\n" ..
                "a/../../b\r\n------B--\r\n", "multipart/form-data; boundary=----B"),
      "a FILE part named pagename is not the field")
clean(get("/", "pagename=parent/child/grandchild"), "a hierarchical page path")
clean(get("/", "pagename=release..notes"), "dots inside a segment")
clean(get("/", "pagename=wait.../more"), "ellipsis slug")
clean(get("/", "pagename=..hidden/x"), "a segment that only starts with ..")
clean(get("/", "pagename=a/./b"), "single-dot segment")
clean(get("/", "page=../../placeholder"), "traversal in another WP var")
clean(get("/", "xpagename=a/../../b&pagenamex=a/../../b"), "near-miss parameter names")
clean(get("/", "s=pagename%3D../../x"), "the marker inside another value")
clean(post("/", "pagename=about&comment=../../x", "application/x-www-form-urlencoded"),
      "clean pagename next to traversal in another field")
clean(post("/", "------B\r\nContent-Disposition: form-data; name=\"pagename_old\"\r\n\r\n" ..
                "a/../../b\r\n------B--\r\n", MP), "multipart near-miss field name")
clean(get("/wp-admin/edit.php", "post_type=page&orderby=title"), "ordinary admin listing")
clean(post("/wp-json/x/v1/y", "pagename=templates/../../placeholder", "application/json"),
      "a non-form body never becomes $_POST")

-- ═══ Rule 103 — a `..` segment in the RAW path ═══════════════════════════════
set_only({ rule_traversal_raw_path = "block" })
local RAW = "WAF_TRAVERSAL:RAW_PATH"
-- nginx resolves these before the WAF, so ctx.uri is the collapsed path.
fires(get("/placeholder/", "", "/templates/%2e%2e/%2e%2e/placeholder/"), "encoded dots", RAW)
fires(get("/placeholder/", "", "/a/b/../../placeholder/"), "literal dots (curl --path-as-is)", RAW)
fires(get("/placeholder", "", "/templates/..%2F..%2Fplaceholder"), "encoded slash", RAW)
fires(get("/placeholder", "", "/templates/%252e%252e/placeholder"), "double-encoded dots", RAW)
fires(get("/placeholder", "", "/templates%5c..%5cplaceholder"), "backslash separators", RAW)
fires(get("/", "", "/a/%2E%2E"), "trailing encoded segment", RAW)
fires(get("/placeholder", "", "/" .. string.rep("a", 3000) .. "/%2e%2e/placeholder"),
      "dot segment past 2 KB of path (uri_scan_len budget)", RAW)

clean(get("/about/", "", "/about/"), "an ordinary path")
clean(get("/product/ring...gold/", "", "/product/ring...gold/"), "ellipsis slug")
clean(get("/a/.../b", "", "/a/.../b"), "a three-dot segment")
clean(get("/file..ext", "", "/file..ext"), "dots inside a segment")
clean(get("/a/..hidden/b", "", "/a/..hidden/b"), "a segment that only starts with ..")
clean(get("/a/b", "", "/a/./b"), "single-dot segment")
clean(get("/\206\177/", "", "/%CE%B1%CE%B8%CE%AE%CE%BD%CE%B1/"), "percent-encoded Greek slug")
fires(get("/placeholder", "", "/templates/.%2E/placeholder"), "one literal, one encoded dot", RAW)
clean(get("/", "next=../../x", "/?next=../../x"), "traversal only in the query (rules 101/10017 own it)")
clean({ uri = "/", args = "", method = "GET", ip = "203.0.113.83", headers = {}, body = "" },
      "no raw_uri (the panel gate) — inert")

-- ═══ Attribution with every shipped default ══════════════════════════════════
-- Restore the shipped tiers: the armed CVE owns a pagename traversal (ban +
-- alert) ahead of rule 101 — which also matches it but runs last because its
-- family's autoblock is held — and 101 keeps a request both it and 103 match.
for k, v in pairs(cfg) do
  if k:sub(1, 5) == "rule_" then waf.set_rule(k, v) end
end
local hit, reason = waf.check(get("/", "pagename=templates/../../../../placeholder"))
check(hit == true and reason == ARG,
      "defaults: pagename traversal is attributed to the armed CVE rule (got " .. tostring(reason) .. ")")
hit, reason = waf.check(get("/placeholder/", "", "/templates/%2e%2e/%2e%2e/placeholder/"))
check(hit == true and reason == RAW,
      "defaults: a raw-path-only traversal blocks as rule 103 (got " .. tostring(reason) .. ")")

if fails > 0 then
  io.stderr:write(("cfm_waf CVE-2026-87902 tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf WordPress pagename traversal (rule 10017, CVE-2026-87902) + raw-path traversal (rule 103)")
