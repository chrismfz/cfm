-- Tests for rule 318 (rule_superglobal_override, WAF_SUPERGLOBAL): a request
-- parameter whose KEY is a PHP superglobal / reserved name (?_SERVER[x]=,
-- &GLOBALS[x]=, _GET[x]= in the body) — PHP variable-poisoning against
-- extract()/import_request_variables()/register_globals patterns.
--
-- Clean-room addition from the NinjaFirewall gap analysis (the concept;
-- no GPL code/signatures copied). Ships at `logonly`; tested here at `block`
-- for crisp assertions since detection is mode-independent.

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

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

local function post(body)
  return {
    uri = "/app.php", args = "", method = "POST", ip = "203.0.113.60",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" }, body = body,
  }
end
local function get(qs)
  return { uri = "/app.php", args = qs, method = "GET", ip = "203.0.113.61", headers = {}, body = "" }
end

local function fires(ctx, label, want_reason)
  local hit, reason = waf.check(ctx)
  check(hit == true,           label .. " — hit=true")
  if want_reason then
    check(reason == want_reason, label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
  else
    check(type(reason) == "string" and reason:sub(1, 15) == "WAF_SUPERGLOBAL",
          label .. " — reason starts WAF_SUPERGLOBAL (got " .. tostring(reason) .. ")")
  end
end
local function clean(ctx, label)
  local hit = waf.check(ctx)
  check(hit ~= true, label .. " — must NOT fire")
end

set_only({ rule_superglobal_override = "block" })

-- Positives — param key IS a superglobal (array + scalar, GET + body, encoded).
fires(get("_SERVER[foo]=bar"),        "GET ?_SERVER[foo]=", "WAF_SUPERGLOBAL:_server")
fires(get("a=1&_GET[x]=y"),           "GET &_GET[x]=",      "WAF_SUPERGLOBAL:_get")
fires(get("GLOBALS[x]=1"),            "GET GLOBALS[x]=",    "WAF_SUPERGLOBAL:globals")
fires(get("_post=1"),                 "GET ?_post= (scalar)", "WAF_SUPERGLOBAL:_post")
fires(get("_REQUEST%5Bx%5D=1"),       "GET _REQUEST%5Bx%5D (encoded brackets)", "WAF_SUPERGLOBAL:_request")
fires(post("name=a&_COOKIE[sid]=x"),  "body &_COOKIE[sid]=", "WAF_SUPERGLOBAL:_cookie")
fires(post("_FILES[f]=x"),            "body _FILES[f]=",     "WAF_SUPERGLOBAL:_files")
fires(post("_SESSION[uid]=1"),        "body _SESSION[uid]=", "WAF_SUPERGLOBAL:_session")
fires(post("_ENV[PATH]=x"),           "body _ENV[PATH]=",    "WAF_SUPERGLOBAL:_env")

-- False positives — name only ENDS in / contains a superglobal, or it's a value.
clean(get("db_server=localhost"),     "FP: db_server= (name ends in _server)")
clean(get("mail_server=smtp.x.gr"),   "FP: mail_server=")
clean(get("_server_name=ns1"),        "FP: _server_name= (followed by _, not =/[)")
clean(get("x=_SERVER"),               "FP: superglobal as a VALUE, not a key")
clean(get("globalsettings=1"),        "FP: globalsettings= (globals is a prefix)")
clean(get("serverid=5&cookies=accept"), "FP: serverid / cookies (not _server / _cookie)")
clean(post("subject=Help&message=please check my _SERVER config in php"),
      "FP: '_SERVER' as prose in a value")
clean(get("page=home&lang=el&sort=date"), "FP: ordinary browsing")
-- Common framework params that begin with '_' but are NOT superglobals —
-- locked in so nobody widens the table into them by accident.
clean(post("_method=PUT&_token=abc123"),  "FP: Laravel/Rails _method + _token")
clean(get("action=heartbeat&_wpnonce=ab12cd&_ajax_nonce=ef34"), "FP: WordPress nonces")
clean(get("v=2&_ga=GA1.2.x&_gid=GA1.2.y"), "FP: Google Analytics _ga/_gid")
clean(get("q=test&_=1719500000"),          "FP: jQuery cachebuster _=")

if fails > 0 then
  io.stderr:write(string.format("FAILED %d tests\n", fails))
  os.exit(1)
end
print("ok: cfm_waf superglobal-override tests (rule 318)")
