-- Regression: rule 329 (WAF_RCE:PHP_OBJECT_INJECTION) must NOT fire on Joomla
-- 5.4+ automated core updates. FP 2026-09-21 (ardas.gr): the Joomla.org update
-- server (UA "Joomla.org Automated Updates Server") POSTs
-- `index.php?jautoupdate=1` with `instance=base64(serialize(ZIPExtraction))`;
-- Joomla's index.php hands that request to com_joomlaupdate/extract.php, which
-- reads only password / instance / task. Rule 329 blocked it and the WAF_RCE
-- autoblock fleet-banned the update server. The carve-out keys on the PAYLOAD
-- (only extract.php's params, only the classes extract.php itself allows), so
-- `?jautoupdate=1` appended to an attack buys nothing.
--
-- Real base64 here (not a lookup table): the carve-out must decode the whole
-- `instance` value, so the tests need genuine payloads.

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64enc(s)
  return ((s:gsub(".", function(c)
    local r, b = "", c:byte()
    for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
    if #x < 6 then return "" end
    local c = 0
    for i = 1, 6 do c = c + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0) end
    return B64:sub(c + 1, c + 1)
  end) .. ({ "", "==", "=" })[#s % 3 + 1])
end
-- Like ngx.decode_base64 (nginx's ngx_decode_base64): decoding stops at the
-- first `=`, a char outside the alphabet before it is an error, and so is a
-- remainder of 1 (mod 4).
local function b64dec(s)
  s = s:match("^[^=]*")
  if s:find("[^%w%+/]") or #s % 4 == 1 then return nil end
  return (s:gsub(".", function(x)
    local r, f = "", (B64:find(x, 1, true) - 1)
    for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
    if #x ~= 8 then return "" end
    local c = 0
    for i = 1, 8 do c = c + (x:sub(i, i) == "1" and 2 ^ (8 - i) or 0) end
    return string.char(c)
  end))
end
assert(b64dec(b64enc("O:13:\"ZIPExtraction\"")) == "O:13:\"ZIPExtraction\"", "b64 round-trip")

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = b64dec,
  log           = function(_, _) end,
  ERR = 0, WARN = 1, INFO = 2,
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

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

-- Form-encodes a value the way an HTTP client does (+ / = become %2B %2F %3D).
local function urlenc(s)
  return (s:gsub("[^%w%-%._~]", function(c) return ("%%%02X"):format(c:byte()) end))
end

-- A ZIPExtraction as extract.php serializes it: private props carry the
-- \0Class\0 prefix, fileHeader is a nested stdClass. `extra` splices more
-- serialized members in (to plant a gadget).
local function zip_instance(extra)
  local p = "\0ZIPExtraction\0"
  return 'O:13:"ZIPExtraction":4:{'
    .. 's:23:"' .. p .. 'runState";i:2;'
    .. 's:23:"' .. p .. 'filename";s:47:"/home/ardas/public_html/tmp/Joomla_5.4.1-Stable.zip";'
    .. 's:25:"' .. p .. 'fileHeader";O:8:"stdClass":2:{s:4:"file";s:22:"administrator/index.php";s:12:"uncompressed";i:4096;}'
    .. (extra or "")
    .. 's:27:"' .. p .. 'currentOffset";i:1048576;}'
end

local PASSWORD = "kQ3v9XbT2mLp7RzW4hN8cY6fJ1sD5gAe"   -- 32 alnum, like the site's secret
local FORM = "application/x-www-form-urlencoded"

local function req(o)
  local body = o.body or ""
  local headers = { ["Content-Type"] = o.ct or FORM }
  if o.cl ~= false then headers["Content-Length"] = tostring(o.cl or #body) end
  return { uri = o.uri or "/index.php", args = o.args or "jautoupdate=1", method = "POST",
           ip = "52.14.131.139", body = body, cookie = "",
           headers = headers }
end
local function step_body(instance, rest)
  return "task=stepExtract&password=" .. PASSWORD
    .. "&instance=" .. urlenc(b64enc(instance)) .. (rest or "")
end

local function fires(c, label, want)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

set_only({ rule_php_object_injection = "block" })
local B64HIT, PLAIN = "WAF_RCE:PHP_OBJECT_INJECTION:BASE64", "WAF_RCE:PHP_OBJECT_INJECTION:PLAIN"

-- Sanity: the real payload IS an object blob the detector would block.
fires(req({ uri = "/wp-admin/admin-ajax.php", args = "", body = step_body(zip_instance()) }),
      "control: the ZIPExtraction blob off the update route is blocked", B64HIT)

-- ── The FP: Joomla's automated update stays clean ─────────────────────────────
clean(req({ body = step_body(zip_instance()) }), "stepExtract with a ZIPExtraction instance")
clean(req({ body = "task=startExtract&password=" .. PASSWORD }), "startExtract (no instance yet)")
clean(req({ body = "task=finalizeUpdate&password=" .. PASSWORD .. "&instance="
            .. urlenc(b64enc(zip_instance())) }), "finalizeUpdate")
clean(req({ uri = "/joomla/index.php", body = step_body(zip_instance()) }),
      "Joomla in a subdirectory")
clean(req({ args = "jautoupdate=1&task=stepExtract", body = "password=" .. PASSWORD
            .. "&instance=" .. urlenc(b64enc(zip_instance())) }),
      "task in the query ($_REQUEST merges GET and POST)")
-- The encoded body really carries %2B/%2F (base64's + and / on the wire): the
-- carve-out decodes the whole value, not the prefix up to the first %.
do
  local pad, body = "", nil
  for _ = 1, 8 do
    body = step_body(zip_instance('s:3:"pad";s:' .. #pad .. ':"' .. pad .. '";'))
    if body:find("%%2B") or body:find("%%2F") then break end
    pad = pad .. "\251"
  end
  check(body:find("%%2B") or body:find("%%2F"), "test setup: an instance with %2B/%2F on the wire")
  clean(req({ body = body }), "instance whose wire form carries %2B/%2F")
end

-- ── Still blocked: anything the payload check can't vouch for ────────────────
fires(req({ body = step_body(zip_instance('s:1:"x";O:4:"Evil":1:{s:3:"cmd";s:2:"id";}')) }),
      "gadget NESTED inside a ZIPExtraction", B64HIT)
fires(req({ body = step_body('O:4:"Evil":0:{}') }), "gadget as the top-level instance", B64HIT)
fires(req({ body = step_body(zip_instance(), '&evil=O:4:"Evil":0:{}') }),
      "extra param carrying a plain object", PLAIN)
fires(req({ body = step_body(zip_instance(), "&foo=bar") }),
      "a param extract.php never reads (allowlist, not denylist)", B64HIT)
fires(req({ body = "task=stepExtract&password=" .. urlenc('O:4:"Evil":0:{}') }),
      "object marker in password", PLAIN)
fires(req({ body = step_body(zip_instance()):gsub("stepExtract", "runEvil") }),
      "task outside extract.php's three verbs", B64HIT)
fires(req({ args = "jautoupdate=0", body = step_body(zip_instance()) }),
      "jautoupdate=0 (PHP empty(): Joomla doesn't route it)", B64HIT)
fires(req({ args = "jautoupdate=1&jautoupdate=", body = step_body(zip_instance()) }),
      "duplicate jautoupdate, last one empty (PHP keeps the last)", B64HIT)
fires(req({ args = "", body = "jautoupdate=1&" .. step_body(zip_instance()) }),
      "jautoupdate only in the body (Joomla reads $_GET)", B64HIT)
fires(req({ uri = "/", body = step_body(zip_instance()) }), "route: / instead of index.php", B64HIT)
fires(req({ uri = "/wp-login.php", body = step_body(zip_instance()) }),
      "route: another PHP entry point", B64HIT)
do
  local body = step_body(zip_instance())
  fires(req({ body = body, cl = #body + 4096 }),
        "body only partly seen by the WAF (Content-Length > body)", B64HIT)
  fires(req({ body = body, cl = false }), "no Content-Length (chunked body)", B64HIT)
  fires(req({ body = body, ct = "multipart/form-data; boundary=----X" }),
        "non-form body", B64HIT)
end

-- Helper-level: shapes the detector itself can't see, so waf.check can't show
-- the carve-out refusing them — assert the carve-out directly.
local function vouches(o) return det.is_joomla_autoupdate_request(o.uri, o.args, o.body, o.headers) end
check(vouches(req({ body = step_body(zip_instance()) })) == true, "helper: the real request qualifies")
check(vouches(req({ body = step_body('O:+13:"ZIPExtraction":0:{}') })) == false,
      "helper: an object marker it can't parse strictly (O:+N) disqualifies")
check(vouches(req({ body = step_body(zip_instance('s:1:"x";C:11:"ArrayObject":0:{}')) })) == false,
      "helper: a custom-serialized (C:) foreign class disqualifies")
check(vouches(req({ body = "task=stepExtract&password=" .. PASSWORD .. "&instance=%%%%" })) == false,
      "helper: an instance that doesn't decode disqualifies")
-- nginx's decoder stops at the first `=`; PHP's non-strict base64_decode skips
-- it and keeps going. `b64(clean)` + "=" + `b64(gadget)` must not qualify: we
-- would decode only the clean half, PHP the whole thing.
do
  local head = 'O:13:"ZIPExtraction":1:{s:2:"ab";'         -- 33 bytes: no padding
  assert(#head % 3 == 0, "test setup: head must encode without padding")
  local spliced = b64enc(head) .. "=" .. b64enc('O:4:"Evil":0:{}}')
  check(b64dec(spliced) == head, "test setup: the stub decodes only up to the first =")
  local body = "task=stepExtract&password=" .. PASSWORD .. "&instance=" .. urlenc(spliced)
  check(vouches(req({ body = body })) == false,
        "helper: base64 with a mid-string = (nginx/PHP decode differently) disqualifies")
  fires(req({ body = body }), "spliced b64(clean)=b64(gadget) instance", B64HIT)
  check(vouches(req({ body = "task=stepExtract&password=" .. PASSWORD .. "&instance="
                      .. urlenc(b64enc(zip_instance()) .. " ") })) == false,
        "helper: base64 with stray whitespace (PHP skips it) disqualifies")
end
check(vouches(req({ body = step_body(zip_instance()) .. "&instance%5B%5D=x" })) == false,
      "helper: an array-style key (instance[]) is not `instance`")
-- Keys PHP rewrites before $_POST (truncates at NUL, strips a leading space):
-- not an exact allowlisted name here, so the whole request is disqualified.
check(vouches(req({ body = "task=stepExtract&password=" .. PASSWORD .. "&instance%00x="
                    .. urlenc(b64enc('O:4:"Evil":0:{}')) })) == false,
      "helper: instance%00x (PHP reads it as `instance`) disqualifies")
check(vouches(req({ body = "task=stepExtract&password=" .. PASSWORD .. "&+instance="
                    .. urlenc(b64enc(zip_instance())) })) == false,
      "helper: a leading-space key disqualifies")
check(vouches(req({ body = step_body(zip_instance()) .. "&instance="
                    .. urlenc(b64enc(zip_instance())) })) == false,
      "helper: a repeated parameter disqualifies, even with two clean copies")
check(vouches(req({ args = "jautoupdate=1&task=stepExtract", body = step_body(zip_instance()) })) == false,
      "helper: the same parameter in query AND body disqualifies")
do
  local c = req({ body = step_body(zip_instance()) })
  c.headers["Content-Length"] = { c.headers["Content-Length"], "99999" }
  check(vouches(c) == false, "helper: a repeated Content-Length disqualifies")
end
-- The class name is read by its length prefix, as PHP does.
check(vouches(req({ body = step_body('O:4:"ZIPExtraction":0:{}') })) == false,
      "helper: a length prefix that doesn't span the name disqualifies")
check(vouches(req({ body = step_body('O:99:"ZIPExtraction":0:{}') })) == false,
      "helper: a length prefix that overruns disqualifies")
check(vouches(req({ body = step_body(zip_instance()):gsub("ZIPExtraction", "zipextraction", 1) })) == true,
      "helper: class names compare case-insensitively (PHP class lookup does)")

if fails > 0 then
  io.stderr:write(("cfm_waf object-injection Joomla auto-update tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf object-injection Joomla 5.4+ automated-update carve-out (rule 329)")
