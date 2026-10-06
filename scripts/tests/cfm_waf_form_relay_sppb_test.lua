-- Tests for rule 520 rule_form_relay_sppb_contact (WAF_FORM_RELAY, block):
-- the Joomla SP Page Builder `ajax_contact` mail relay.
--
-- The addon's getAjax() base64-decodes the client-posted hidden `recipient`
-- field and mails it. A bot appends a victim, the address it also types as the
-- form's `email` (seen on titan 2026-10-06, hotellito.gr). The request shapes
-- below are what the addon's jQuery submit sends: option/task/addon at the top
-- level and the form as data[N][name] / data[N][value] pairs.
--
-- ngx.decode_base64 is replaced by a real (strict, nil-on-invalid) decoder so
-- the detector's decode path runs as it does under OpenResty.

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64IDX = {}
for i = 1, #B64 do B64IDX[B64:sub(i, i)] = i - 1 end

local function b64enc(s)
  local out = {}
  for i = 1, #s, 3 do
    local a, b, c = s:byte(i, i + 2)
    local n = a * 65536 + (b or 0) * 256 + (c or 0)
    local c1 = math.floor(n / 262144) % 64
    local c2 = math.floor(n / 4096) % 64
    local c3 = math.floor(n / 64) % 64
    local c4 = n % 64
    out[#out + 1] = B64:sub(c1 + 1, c1 + 1) .. B64:sub(c2 + 1, c2 + 1)
      .. (b and B64:sub(c3 + 1, c3 + 1) or "=") .. (c and B64:sub(c4 + 1, c4 + 1) or "=")
  end
  return table.concat(out)
end

local function b64dec(s)
  if #s % 4 ~= 0 then return nil end
  local out = {}
  for i = 1, #s, 4 do
    local q = s:sub(i, i + 3)
    local pad = select(2, q:gsub("=", ""))
    local body = q:gsub("=", "A")
    local n = 0
    for j = 1, 4 do
      local v = B64IDX[body:sub(j, j)]
      if v == nil then return nil end
      n = n * 64 + v
    end
    local bytes = string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
    out[#out + 1] = bytes:sub(1, 3 - pad)
  end
  return table.concat(out)
end

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = b64dec,
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

check(b64dec(b64enc("litohotel@outlook.com,victim@example.net")) == "litohotel@outlook.com,victim@example.net",
      "test codec round-trips")

local cfg = waf.get_config()
check(cfg.rule_form_relay_sppb_contact == "block",
      "rule_form_relay_sppb_contact ships at block (got " .. tostring(cfg.rule_form_relay_sppb_contact) .. ")")

local snap = waf.get_config()
for k, _ in pairs(snap) do
  if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
end
waf.set_rule("rule_form_relay_sppb_contact", "block")

local function enc(s)
  return (s:gsub("[^%w%-%._~]", function(c) return string.format("%%%02X", c:byte()) end))
end

-- The addon's form as jQuery serializes it (data[N][name]/[value]).
local function form(fields, top)
  local parts = {}
  for k, v in pairs(top or { option = "com_sppagebuilder", task = "ajax", addon = "ajax_contact" }) do
    parts[#parts + 1] = k .. "=" .. enc(v)
  end
  parts[#parts + 1] = "g-recaptcha-response="
  for i, f in ipairs(fields) do
    parts[#parts + 1] = enc("data[" .. (i - 1) .. "][name]") .. "=" .. enc(f[1])
    parts[#parts + 1] = enc("data[" .. (i - 1) .. "][value]") .. "=" .. enc(f[2])
  end
  return table.concat(parts, "&")
end

local function fields(recipient_plain, email)
  return {
    { "name", "Rickymub Rickymub" },
    { "email", email },
    { "subject", "https://casino.example/" },
    { "message", "spam body" },
    { "recipient", b64enc(recipient_plain) },
    { "from_email", "" },
    { "from_name", "" },
    { "addon_id", "1559043218373" },
    { "captcha_type", "default" },
    { "view_type", "page" },
  }
end

local UE = "application/x-www-form-urlencoded; charset=UTF-8"
local function post(body, ct, args)
  return { uri = "/en/contactus", raw_uri = "/en/contactus", args = args or "", method = "POST",
           ip = "203.0.113.90", headers = { ["Content-Type"] = ct or UE }, body = body }
end

local HAS   = "WAF_FORM_RELAY:SPPB_AJAX_CONTACT:RECIPIENT_HAS_SUBMITTER"
local MULTI = "WAF_FORM_RELAY:SPPB_AJAX_CONTACT:MULTI_RECIPIENT"

local function fires(c, label)
  local hit, reason, _, action = waf.check(c)
  check(hit == true and action == "block", label .. " — blocks (got hit=" .. tostring(hit) .. " action=" .. tostring(action) .. ")")
  check(reason == HAS, label .. " — reason " .. HAS .. " (got " .. tostring(reason) .. ")")
end
local function logs_only(c, label)
  local hit, reason, _, action = waf.check(c)
  check(hit == true and action == "logonly", label .. " — logonly (got hit=" .. tostring(hit) .. " action=" .. tostring(action) .. ")")
  check(reason == MULTI, label .. " — reason " .. MULTI .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

-- ── Positives ────────────────────────────────────────────────────────────────
fires(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"))),
      "the titan relay shape (owner, victim; victim = submitted email)")
fires(post(form(fields("litohotel@outlook.com, CDEW@Spam.Example ", " cdew@spam.example"))),
      "case and whitespace differences")
fires(post(form(fields("litohotel@outlook.com;cdew@spam.example", "cdew@spam.example"))),
      "semicolon separator")
fires(post(form(fields("cdew@spam.example,litohotel@outlook.com", "cdew@spam.example"))),
      "victim listed first")
fires(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"),
                { option = "COM_SPPAGEBUILDER", task = "ajax", addon = "Ajax_Contact" })),
      "option/addon case-insensitive")
do
  -- PHP's base64_decode is non-strict: stripped padding and junk bytes still decode.
  local b = b64enc("litohotel@outlook.com,cdew@spam.example"):gsub("=", "")
  local f = fields("x", "cdew@spam.example")
  f[5][2] = b:sub(1, 8) .. " " .. b:sub(9)
  fires(post(form(f)), "unpadded base64 with a space in it")
end
-- Everything in the query string (Joomla reads $_REQUEST), empty body.
fires({ uri = "/index.php", raw_uri = "/index.php", method = "GET", ip = "203.0.113.91", body = "", headers = {},
        args = form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example")) },
      "GET with the form in the query string")
-- Top-level option/addon in the query, form in the body.
fires(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"), {}),
           UE, "option=com_sppagebuilder&task=ajax&addon=ajax_contact"),
      "option/addon in the query, data in the body")
do
  local MP = "multipart/form-data; boundary=----B"
  local function part(n, v) return "------B\r\nContent-Disposition: form-data; name=\"" .. n .. "\"\r\n\r\n" .. v .. "\r\n" end
  local b = part("option", "com_sppagebuilder") .. part("task", "ajax") .. part("addon", "ajax_contact")
    .. part("data[0][name]", "email") .. part("data[0][value]", "cdew@spam.example")
    .. part("data[1][name]", "recipient") .. part("data[1][value]", b64enc("litohotel@outlook.com,cdew@spam.example"))
    .. "------B--\r\n"
  fires(post(b, MP), "multipart body")
end
do
  local pad = string.rep("a", 3000)
  local f = fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example")
  f[4][2] = pad
  fires(post(form(f)), "long message pushes the recipient past the 2 KB memo window")
end

-- Review round 1 (bypasses PHP accepts):
do
  -- PHP ignores what follows the second `]` and cuts a key at NUL.
  local b = form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"))
  b = b:gsub("data%%5B4%%5D%%5Bvalue%%5D=", "data%%5B4%%5D%%5Bvalue%%5Dx=")
  b = b:gsub("data%%5B1%%5D%%5Bname%%5D=", "data%%5B1%%5D%%5Bname%%5D%%00zz=")
  fires(post(b), "junk after the key's last ] and a NUL-cut key")
end
do
  -- A lone trailing sextet: PHP drops it, so must we.
  local f = fields("x", "cdew@spam.example")
  f[5][2] = b64enc("litohotel@outlook.com,cdew@spam.example") .. "A"
  fires(post(form(f)), "base64 with a stray trailing character (length 1 mod 4)")
end
do
  local f = fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example")
  f[4][2] = string.rep("a", 9000)
  fires(post(form(f)), "a 9000-byte message before the recipient (past the generic scan budget)")
end
do
  local MP = "multipart/form-data; boundary=----B"
  local e = b64enc("litohotel@outlook.com,cdew@spam.example")
  local function part(n, v) return "------B\r\nContent-Disposition: form-data; name=\"" .. n .. "\"\r\n\r\n" .. v .. "\r\n" end
  local b = part("addon", "ajax_contact")
    .. part("data[0][name]", "email") .. part("data[0][value]", "cdew@spam.example")
    .. part("data[1][name]", "recipient") .. part("data[1][value]", e:sub(1, 24) .. "\r\n" .. e:sub(25))
    .. "------B--\r\n"
  fires(post(b, MP), "multipart value split over two lines")
end
fires(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"),
                { task = "ajax", addon = "ajax_contact" })),
      "no option (a SEF page URL supplies it)")
do
  -- Last wins per key, as PHP: an earlier clean value is overridden.
  local b = form(fields("litohotel@outlook.com", "cdew@spam.example")) .. "&"
    .. enc("data[4][value]") .. "=" .. enc(b64enc("litohotel@outlook.com,cdew@spam.example"))
  fires(post(b), "a later duplicate key overrides the earlier value")
end
do
  -- Attacker-sized input stays linear: thousands of rows and duplicate keys.
  local parts = { "addon=ajax_contact" }
  local v = enc(b64enc("a@b.example,c@d.example"))
  for i = 1, 3000 do
    parts[#parts + 1] = enc("data[" .. i .. "][name]") .. "=recipient"
    parts[#parts + 1] = enc("data[" .. i .. "][value]") .. "=" .. v
  end
  local t0 = os.clock()
  waf.check(post(table.concat(parts, "&")))
  local dt = os.clock() - t0
  check(dt < 0.5, string.format("3000-row body is bounded (took %.3fs)", dt))
  local mp = { "------B\r\nContent-Disposition: form-data; name=\"addon\"\r\n\r\najax_contact\r\n" }
  for _ = 1, 2300 do mp[#mp + 1] = " name=x" end
  mp[#mp + 1] = "\r\n\r\n------B--\r\n"
  t0 = os.clock()
  waf.check(post(table.concat(mp), "multipart/form-data; boundary=----B"))
  dt = os.clock() - t0
  check(dt < 0.2, string.format("multipart name= flood is linear (took %.3fs)", dt))
end

-- ── Measurement only ─────────────────────────────────────────────────────────
logs_only(post(form(fields("owner@hotel.example,sales@hotel.example", "guest@mail.example"))),
          "an owner-saved recipient list (no submitter in it) is logonly")
-- An owner list tested by a staff member: the submitter shares a recipient's
-- domain, so it is not an outsider (review round 1 false positive).
logs_only(post(form(fields("owner@hotel.example, staff@hotel.example", "staff@hotel.example"))),
          "staff testing an owner list on the same domain")
-- The documented residual: a victim on the owner's own mail domain.
logs_only(post(form(fields("owner@gmail.com,victim@gmail.com", "victim@gmail.com"))),
          "victim on the owner's mail domain is logged, not blocked")
-- Even with the rule at block, the MULTI tag never enforces.
logs_only(post(form(fields("a@one.example,b@two.example,c@three.example", "guest@mail.example"))),
          "three recipients, none the submitter")

-- ── Clean ────────────────────────────────────────────────────────────────────
clean(post(form(fields("litohotel@outlook.com", "guest@mail.example"))), "a normal contact submission")
clean(post(form(fields("litohotel@outlook.com", "litohotel@outlook.com"))),
      "owner testing the form with the address it mails (single recipient)")
clean(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"),
                { option = "com_sppagebuilder", task = "ajax", addon = "form_builder" })),
      "another addon")
clean(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"),
                { option = "com_contact", task = "ajax", addon = "ajax_contact" })),
      "an explicit other component")
do
  local f = fields("x", "cdew@spam.example")
  f[5][2] = "!!!not-base64!!!"
  clean(post(form(f)), "an undecodable recipient")
end
do
  -- `recipient` as a plain top-level field, not a data[] pair, is not what the addon reads.
  local b = form(fields("litohotel@outlook.com", "cdew@spam.example")) .. "&recipient="
    .. enc(b64enc("litohotel@outlook.com,cdew@spam.example"))
  clean(post(b), "a top-level recipient field is not the addon's input")
end
clean(post("option=com_sppagebuilder&task=ajax&addon=ajax_contact", UE), "no form data")
clean(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example")), "application/json"),
      "a JSON body never becomes $_POST")

-- ── Disabled ────────────────────────────────────────────────────────────────
waf.set_rule("rule_form_relay_sppb_contact", "disabled")
clean(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"))), "rule disabled")

if fails > 0 then
  io.stderr:write(string.format("%d failure(s)\n", fails))
  os.exit(1)
end
print("ok: cfm_waf SP Page Builder ajax_contact mail relay (rule 520)")
