-- Tests for rule 520 rule_form_relay_sppb_contact (WAF_FORM_RELAY, logonly):
-- the Joomla SP Page Builder contact-form mail relay, MEASUREMENT ONLY.
--
-- ajax_contact and form_builder <= 3.8.6 post `recipient` and (form_builder)
-- `additional_header` back as base64 data[] fields; form_builder 3.8.7 - 5.x
-- pack them into `form_id` (base64 JSON + an md5 with a salt shared by every
-- install). getAjax() mails recipient + the Cc:/Bcc: header lines after
-- replacing {{field}} with the visitor's input. A relay is the shape of a real
-- submission, so every tag is logonly — even with the rule set to block. The
-- request shapes are what the addons' jQuery submit sends: option/task/addon
-- at the top level and the form as data[N][name] / data[N][value] pairs.
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
check(cfg.rule_form_relay_sppb_contact == "logonly",
      "rule_form_relay_sppb_contact ships at logonly (got " .. tostring(cfg.rule_form_relay_sppb_contact) .. ")")

local snap = waf.get_config()
for k, _ in pairs(snap) do
  if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
end
-- Set to block on purpose: the call site must still only log.
waf.set_rule("rule_form_relay_sppb_contact", "block")

local function enc(s)
  return (s:gsub("[^%w%-%._~]", function(c) return string.format("%%%02X", c:byte()) end))
end

local AC = { option = "com_sppagebuilder", task = "ajax", addon = "ajax_contact" }
local FB = { option = "com_sppagebuilder", task = "ajax", addon = "form_builder" }

-- The addon's form as jQuery serializes it (data[N][name]/[value]).
local function form(fields, top)
  local parts = {}
  for k, v in pairs(top or AC) do
    parts[#parts + 1] = k .. "=" .. enc(v)
  end
  parts[#parts + 1] = "g-recaptcha-response="
  for i, f in ipairs(fields) do
    parts[#parts + 1] = enc("data[" .. (i - 1) .. "][name]") .. "=" .. enc(f[1])
    parts[#parts + 1] = enc("data[" .. (i - 1) .. "][value]") .. "=" .. enc(f[2])
  end
  return table.concat(parts, "&")
end

-- ajax_contact (and form_builder <= 3.8.6 without a header).
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

-- form_builder <= 3.8.6: recipient and header as plain base64 fields.
local function fb_old(recipient_plain, header, email, email_field)
  return {
    { email_field or "email", email },
    { "message", "hello" },
    { "recipient", b64enc(recipient_plain) },
    { "from", b64enc("") },
    { "addon_id", "1601234567890" },
    { "additional_header", b64enc(header) },
    { "email_subject", b64enc("New message from {{name}}") },
    { "email_template", b64enc("<p>{{message}}</p>") },
    { "view_type", "page" },
  }
end

-- form_builder 3.8.7 - 5.x: everything in form_id = base64(JSON) ":" md5.
local function fb_new(recipient_plain, header, email)
  local json = '{"recipient_email":"' .. b64enc(recipient_plain):gsub("/", "\\/")
    .. '","additional_header":"' .. b64enc(header):gsub("/", "\\/") .. '","from":""}'
  return {
    { "email", email },
    { "message", "hello" },
    { "form_id", b64enc(json) .. ":0123456789abcdef0123456789abcdef" },
    { "addon_id", "1601234567890" },
    { "email_subject", b64enc("New message") },
    { "email_template", b64enc("<p>{{message}}</p>") },
  }
end

local UE = "application/x-www-form-urlencoded; charset=UTF-8"
local function post(body, ct, args, host)
  return { uri = "/en/contactus", raw_uri = "/en/contactus", args = args or "", method = "POST",
           ip = "203.0.113.90", headers = { ["Content-Type"] = ct or UE, ["Host"] = host or "www.hotel.example" },
           body = body }
end

local function logs(c, want, label)
  local hit, reason, _, action = waf.check(c)
  check(hit == true and action == "logonly",
        label .. " — logonly (got hit=" .. tostring(hit) .. " action=" .. tostring(action) .. ")")
  check(reason == "WAF_FORM_RELAY:" .. want,
        label .. " — reason WAF_FORM_RELAY:" .. want .. " (got " .. tostring(reason) .. ")")
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end

local AC_TO = "SPPB_AJAX_CONTACT:DELIVERS_TO_VISITOR"

-- ── CC_VISITOR_TEMPLATE: the site's own header copies the visitor ───────────
logs(post(form(fb_old("info@hotellito.example", "Cc: {{email}}", "victim@spam.example"), FB)),
     "SPPB_FORM_BUILDER:CC_VISITOR_TEMPLATE", "the hotellito config (form_builder <= 3.8.6)")
logs(post(form(fb_new("info@hotellito.example", "Reply-To: {{email}}\nBCC: {{email}}", "victim@spam.example"), FB)),
     "SPPB_FORM_BUILDER:CC_VISITOR_TEMPLATE", "form_id payload (3.8.7 - 5.x), upper-case BCC")
logs(post(form(fb_old("info@hotel.example", "Cc: {{email}}", "v@spam.example", "item[email]"), FB)),
     "SPPB_FORM_BUILDER:CC_VISITOR_TEMPLATE", "bracketed field name")

-- ── DELIVERS_TO_VISITOR: an address the visitor typed is mailed ─────────────
logs(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"))), AC_TO,
     "the 2026-10-06 titan request (recipient list holds the submitter)")
logs(post(form(fields("victim@spam.example", "victim@spam.example"))), AC_TO,
     "recipient rewritten to the visitor's address")
logs(post(form(fields("litohotel@outlook.com", "LitoHotel@Outlook.com "))), AC_TO,
     "owner testing with the address it mails (measured, never blocked)")
logs(post(form(fb_old("info@hotel.example", "Cc: victim@spam.example", "victim@spam.example"), FB)),
     "SPPB_FORM_BUILDER:DELIVERS_TO_VISITOR", "literal Cc equal to the typed address")
logs(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"),
               { option = "com_sppagebuilder", task = "ajax", addon = "ajax_<>contact" })), AC_TO,
     "addon=ajax_<>contact (Joomla's CMD filter strips the brackets)")
logs(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"),
               { option = "COM_SPPAGEBUILDER", task = "ajax", addon = "Ajax_Contact" })), AC_TO,
     "option/addon case")

-- ── CC_FOREIGN_LITERAL: a literal copy outside the site and the recipient ───
logs(post(form(fb_old("info@hotel.example", "Bcc: admin@yourcompany.com", "guest@mail.example"), FB)),
     "SPPB_FORM_BUILDER:CC_FOREIGN_LITERAL", "the template placeholder Bcc (earth)")
logs(post(form(fb_new("info@hotel.example", "Cc: victim@spam.example", "guest@mail.example"), FB)),
     "SPPB_FORM_BUILDER:CC_FOREIGN_LITERAL", "a crafted Cc in a forged form_id")
clean(post(form(fb_old("info@hotel.example", "Bcc: office@hotel.example", "guest@mail.example"), FB)),
      "Bcc on the recipient's domain")
clean(post(form(fb_old("owner@gmail.com", "Bcc: sales@hotel.example", "guest@mail.example"), FB)),
      "Bcc on the site's own domain (Host www.hotel.example)")
clean(post(form(fb_old("info@hotel.example", "Bcc: a@mail.hotel.example", "guest@mail.example"), FB)),
      "Bcc on a subdomain of the site")
clean(post(form(fb_old("owner@gmail.com", "Bcc: second@gmail.com", "guest@mail.example"), FB)),
      "Bcc on the recipient's (non-site) domain")
clean(post(form(fb_old("info@hotel.example", "Acc: victim@spam.example", "guest@mail.example"), FB)),
      "a header that only ends in cc is not a copy")
do
  local f = fields("owner@hotel.example", "guest@mail.example")
  f[6][2] = "owner@hotel.example"
  clean(post(form(f)), "the addon's own from_email field is not visitor input")
end
clean(post(form(fb_old("info@hotel.example", " Cc: {{email}}", "v@spam.example"), FB)),
      "a header name with a leading space is not a Cc to PHP")

-- ── MULTI_RECIPIENT / BODY_PAST_WINDOW ───────────────────────────────────────
logs(post(form(fields("owner@hotel.example,sales@hotel.example", "guest@mail.example"))),
     "SPPB_AJAX_CONTACT:MULTI_RECIPIENT", "an owner-saved recipient list")
do
  local c = post(form({ { "name", "x" }, { "message", string.rep("a", 500) } }))
  c.headers["Content-Length"] = tostring(40000)
  logs(c, "SPPB_AJAX_CONTACT:BODY_PAST_WINDOW", "truncated body with no recipient")
  clean(post(form({ { "name", "x" }, { "message", "hi" } })), "no recipient, whole body: nothing")
end

-- ── Parsing robustness (PHP's reading of the request) ───────────────────────
do
  local b = b64enc("litohotel@outlook.com,cdew@spam.example"):gsub("=", "")
  local f = fields("x", "cdew@spam.example")
  f[5][2] = b:sub(1, 8) .. " " .. b:sub(9) .. "A"
  logs(post(form(f)), AC_TO, "non-strict base64: no padding, a space, a stray sextet")
end
logs({ uri = "/index.php", raw_uri = "/index.php", method = "GET", ip = "203.0.113.91", body = "", headers = {},
       args = form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example")) },
     AC_TO, "GET with the form in the query string")
logs(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"), {}),
          UE, "option=com_sppagebuilder&task=ajax&addon=ajax_contact"),
     AC_TO, "option/addon in the query, data in the body")
do
  local MP = "multipart/form-data; boundary=----B"
  local function part(n, v, extra)
    return "------B\r\n" .. (extra or "") .. "Content-Disposition: form-data; name=\"" .. n .. "\"\r\n\r\n" .. v .. "\r\n"
  end
  local e = b64enc("litohotel@outlook.com,cdew@spam.example")
  local b = part("addon", "ajax_contact")
    .. part("data[0][name]", "email") .. part("data[0][value]", "cdew@spam.example")
    .. part("data[1][name]", "recipient")
    .. part("data[1][value]", e:sub(1, 24) .. "\r\n" .. e:sub(25), "X-Junk: a; name=\"zz\"\r\n")
    .. "------B--\r\n"
  logs(post(b, MP), AC_TO, "multipart, value split over two lines, decoy name= in a part header")
end
do
  local f = fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example")
  f[4][2] = string.rep("a", 9000)
  logs(post(form(f)), AC_TO, "a 9000-byte message before the recipient (past the generic scan budget)")
end
do
  local b = form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"))
  b = b:gsub("data%%5B4%%5D%%5Bvalue%%5D=", "data%%5B4%%5D%%5Bvalue%%5Dx=")
  b = b:gsub("data%%5B1%%5D%%5Bname%%5D=", "data%%5B1%%5D%%5Bname%%5D%%00zz=")
  logs(post(b), AC_TO, "junk after the key's last ] and a NUL-cut key")
  clean(post((b:gsub("data%%5B", "DATA%%5B"))), "upper-case DATA keys are not the form PHP reads")
end
do
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
  local list, ems = {}, {}
  for i = 1, 200 do ems[#ems + 1] = { "email" .. i, "a" .. i .. "@d" .. i .. ".example" } end
  for i = 1, 2400 do list[#list + 1] = "f" .. i .. "@filler.example" end
  ems[#ems + 1] = { "recipient", b64enc(table.concat(list, ",")) }
  t0 = os.clock()
  waf.check(post(form(ems)))
  dt = os.clock() - t0
  check(dt < 0.2, string.format("200 typed emails x 2400 recipients is bounded (took %.3fs)", dt))
end

-- ── Clean ────────────────────────────────────────────────────────────────────
clean(post(form(fields("litohotel@outlook.com", "guest@mail.example"))), "a normal ajax_contact submission")
clean(post(form(fb_old("info@hotel.example", "Reply-To: {{email}}", "guest@mail.example"), FB)),
      "a normal form_builder submission (Reply-To is not a copy)")
clean(post(form(fb_new("info@hotel.example", "", "guest@mail.example"), FB)), "a normal 3.8.7+ submission")
clean(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"),
                { option = "com_sppagebuilder", task = "ajax", addon = "optin_form" })), "another addon")
clean(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"),
                { option = "com_contact", task = "ajax", addon = "ajax_contact" })), "an explicit other component")
do
  local f = fields("x", "cdew@spam.example")
  f[5][2] = "!!!"
  clean(post(form(f)), "an undecodable recipient")
end
clean(post(form(fields("litohotel@outlook.com", "cdew@spam.example")) .. "&recipient="
           .. enc(b64enc("litohotel@outlook.com,cdew@spam.example"))),
      "a top-level recipient field is not the addon's input")
clean(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example")), "application/json"),
      "a JSON body never becomes $_POST")

-- ── Disabled ────────────────────────────────────────────────────────────────
waf.set_rule("rule_form_relay_sppb_contact", "disabled")
clean(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"))), "rule disabled")

if fails > 0 then
  io.stderr:write(string.format("%d failure(s)\n", fails))
  os.exit(1)
end
print("ok: cfm_waf SP Page Builder contact-form relay measurement (rule 520)")
