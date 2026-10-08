-- Tests for rule 520 rule_form_relay_sppb_contact (WAF_FORM_RELAY, block):
-- Joomla SP Page Builder (<= 3.8.3) contact-form mail relays.
--
-- ajax_contact base64-decodes the client-posted hidden `recipient` field and
-- mails it; form_builder adds the Cc/Bcc lines of the client-posted base64
-- `additional_header`. Only tampering blocks (a recipient list or a literal
-- Cc/Bcc holding the visitor's own address); the site's own `Cc: {{email}}`
-- setting (titan, hotellito.gr, 2026-09/10) is logged only. The request shapes
-- below are what the addons' jQuery submit sends: option/task/addon at the top
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
      "an injected recipient list (owner, victim; victim = submitted email)")
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

-- Review round 2 (PR review):
do
  -- No row cap to push the real rows past.
  local junk = {}
  for i = 1, 300 do junk[#junk + 1] = enc("data[j" .. i .. "][name]") .. "=x" end
  fires(post(table.concat(junk, "&") .. "&" .. form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"))),
        "300 junk rows before the real form")
end
do
  -- PHP keys are case-sensitive: a differently-cased duplicate is ANOTHER key.
  local b = form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"))
  fires(post(b .. "&ADDON=x"), "an upper-case ADDON duplicate does not mask addon")
  fires(post(b .. "&" .. enc("data[4][VALUE]") .. "=" .. enc(b64enc("x"))),
        "an upper-case VALUE duplicate does not mask the recipient")
  clean(post((b:gsub("data%%5B", "DATA%%5B"))), "upper-case DATA keys are not the form PHP reads")
end
do
  -- Joomla's CMD filter strips junk from option/addon.
  local b = form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"), {})
  fires(post(b .. "&option=com_sppage%27builder&task=ajax&addon=ajax_contact"),
        "junk byte inside option (CMD-filtered)")
  fires(post(b .. "&option=.com_sppagebuilder&addon=ajax_contact%00"),
        "leading dot in option, NUL in addon")
end
do
  -- The multipart name comes from Content-Disposition only.
  local MP = "multipart/form-data; boundary=----B"
  local function part(n, v, extra)
    return "------B\r\n" .. (extra or "") .. "Content-Disposition: form-data; name=\"" .. n .. "\"\r\n\r\n" .. v .. "\r\n"
  end
  local b = part("addon", "ajax_contact")
    .. part("data[0][name]", "email") .. part("data[0][value]", "cdew@spam.example")
    .. part("data[1][name]", "recipient")
    .. part("data[1][value]", b64enc("litohotel@outlook.com,cdew@spam.example"), "X-Junk: a; name=\"zz\"\r\n")
    .. "------B--\r\n"
  fires(post(b, MP), "a decoy name= in another part header")
end
do
  -- Content-Length beyond what the edge handed over, addon present, no recipient.
  local c = post(form({ { "name", "x" }, { "message", string.rep("a", 500) } }))
  c.headers["Content-Length"] = tostring(40000)
  local hit, reason, _, action = waf.check(c)
  check(hit == true and action == "logonly" and reason == "WAF_FORM_RELAY:SPPB_AJAX_CONTACT:BODY_PAST_WINDOW",
        "truncated body with no recipient is logged BODY_PAST_WINDOW (got " .. tostring(reason) .. "/" .. tostring(action) .. ")")
  clean(post(form({ { "name", "x" }, { "message", "hi" } })), "no recipient, whole body: nothing")
end
do
  -- The domain check is linear in the list.
  local list, ems = {}, {}
  for i = 1, 200 do list[#list + 1] = "a" .. i .. "@d" .. i .. ".example"; ems[#ems + 1] = { "email", "a" .. i .. "@d" .. i .. ".example" } end
  for i = 1, 2000 do list[#list + 1] = "f" .. i .. "@filler.example" end
  for i = 1, 200 do list[#list + 1] = "p@d" .. i .. ".example" end
  ems[#ems + 1] = { "recipient", b64enc(table.concat(list, ",")) }
  local t0 = os.clock()
  waf.check(post(form(ems)))
  local dt = os.clock() - t0
  check(dt < 0.2, string.format("200 emails x 2400 recipients is bounded (took %.3fs)", dt))
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
-- Documented residual: a decoy on the victim's domain defeats the domain clause.
logs_only(post(form(fields("owner@hotel.gr,cdew@spam.example,x@spam.example", "cdew@spam.example"))),
          "decoy on the victim's domain is logged, not blocked")
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

-- ── The cheap gate keys on the `addon` KEY, not its value ───────────────────
-- Joomla reads `addon` through STRING (strips tags) for the class and CMD for
-- the file path, so a tag-mangled value still dispatches to ajax_contact.
fires(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"),
                { option = "com_sppagebuilder", task = "ajax", addon = "ajax_<>contact" })),
      "addon=ajax_<>contact (no literal ajax_contact anywhere)")
do
  local b = form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"), {})
  fires(post(b .. "&option=com_sppagebuilder&task=ajax&%61ddon=ajax_%3C%3Econtact"),
        "url-encoded addon key and a mangled value")
end

-- ── form_builder: Cc/Bcc lines of the base64 additional_header ──────────────
-- The addon (<= 3.8.3) splits the decoded header on "\n" and ':', keeps lines
-- whose untrimmed, lowercased key is cc/bcc, and fills {{field}} placeholders
-- with what the visitor typed. Field names are the inner [..] of the row name.
local FB_TOP = { option = "com_sppagebuilder", task = "ajax", addon = "form_builder" }
local function fb_fields(header, typed_email, recipient)
  return {
    { "sppb-form-builder-field[first-name*]", "Rickymub" },
    { "sppb-form-builder-field[email*]", typed_email },
    { "sppb-form-builder-field[message]", "spam body" },
    { "recipient", b64enc(recipient or "litohotel@outlook.com") },
    { "from", b64enc("") },
    { "email_subject", b64enc("{{subject}} | {{email}} | {{site-name}}") },
    { "additional_header", b64enc(header) },
    { "addon_id", "1618817591947" },
    { "view_type", "page" },
  }
end
local FB = "WAF_FORM_RELAY:SPPB_FORM_BUILDER:"
local function fb_is(c, tag, action, label)
  local hit, reason, _, act = waf.check(c)
  check(hit == true and act == action and reason == FB .. tag,
        label .. " — " .. action .. " " .. FB .. tag .. " (got " .. tostring(reason) .. "/" .. tostring(act) .. ")")
end

-- Block: a LITERAL Cc/Bcc equal to the address the visitor typed, outside the
-- recipients' domains (the hidden header was rewritten).
fb_is(post(form(fb_fields("Reply-To: {{email}}\nCc: cdew@spam.example", "cdew@spam.example"), FB_TOP)),
      "CC_HAS_SUBMITTER", "block", "injected literal Cc = typed address")
fb_is(post(form(fb_fields("Reply-To: {{email}}\r\nbCC:  CDEW@spam.example \r\n", " cdew@Spam.Example"), FB_TOP)),
      "CC_HAS_SUBMITTER", "block", "Bcc, mixed case, CRLF lines, padded value")
fb_is(post(form(fb_fields("Cc: {{email}}\nBcc: cdew@spam.example", "cdew@spam.example"), FB_TOP)),
      "CC_HAS_SUBMITTER", "block", "a placeholder line does not mask an injected literal one")
fb_is(post(form(fb_fields("Cc: cdew@spam.example:junk", "cdew@spam.example"), FB_TOP)),
      "CC_HAS_SUBMITTER", "block", "value cut at the next ':' as PHP's explode does")
fb_is({ uri = "/index.php", raw_uri = "/index.php", method = "GET", ip = "203.0.113.92", body = "", headers = {},
        args = form(fb_fields("Cc: cdew@spam.example", "cdew@spam.example"), FB_TOP) },
      "CC_HAS_SUBMITTER", "block", "GET with the form in the query string")
fb_is(post(form(fb_fields("Cc: cdew@spam.example", "cdew@spam.example"),
                { option = "com_sppagebuilder", task = "ajax", addon = "form_<>builder" })),
      "CC_HAS_SUBMITTER", "block", "addon=form_<>builder still dispatches (CMD and STRING both give form_builder)")
-- A tag with a letter in it leaves the letter for CMD (form_bbuilder): the
-- addon file is not found and nothing is mailed, so nothing to flag.
clean(post(form(fb_fields("Cc: cdew@spam.example", "cdew@spam.example"),
                { option = "com_sppagebuilder", task = "ajax", addon = "form_<b>builder" })),
      "addon=form_<b>builder does not dispatch")
do
  -- PHP's base64_decode is non-strict: stripped padding still decodes.
  local f = fb_fields("Cc: cdew@spam.example", "cdew@spam.example")
  f[7][2] = f[7][2]:gsub("=", "")
  fb_is(post(form(f, FB_TOP)), "CC_HAS_SUBMITTER", "block", "unpadded base64 header")
end
-- An address outside the placeholders is written into the header: a trailing
-- placeholder (empty or unknown field) does not hide it (review finding).
do
  local f = fb_fields("Cc: cdew@spam.example{{empty}}", "cdew@spam.example")
  f[#f + 1] = { "sppb-form-builder-field[empty]", "" }
  fb_is(post(form(f, FB_TOP)), "CC_HAS_SUBMITTER", "block", "literal address + an empty field placeholder")
end
do
  local f = fb_fields("Cc: cdew@{{dom}}", "cdew@spam.example")
  f[#f + 1] = { "sppb-form-builder-field[dom]", "spam.example" }
  fb_is(post(form(f, FB_TOP)), "CC_HAS_SUBMITTER", "block", "half literal, half placeholder")
end
do
  -- The posted recipient cannot buy the staff exemption (review finding): only
  -- the Host the form was posted to can.
  local c = post(form(fb_fields("Cc: victim@gmail.com", "victim@gmail.com", "x@gmail.com"), FB_TOP))
  c.host = "www.hotel.example"
  fb_is(c, "CC_HAS_SUBMITTER", "block", "a gmail recipient does not exempt a gmail victim")
  -- The raw Host header is client-set (absolute-URI request line): only the
  -- host the edge routed on (ctx.host) counts (review round 2).
  c = post(form(fb_fields("Cc: victim@gmail.com", "victim@gmail.com"), FB_TOP))
  c.host, c.headers.Host = "hotel.example", "gmail.com"
  fb_is(c, "CC_HAS_SUBMITTER", "block", "a forged Host header buys no exemption")
end
-- A list in the Cc value is split like the ajax_contact recipient.
fb_is(post(form(fb_fields("Cc: cdew@spam.example, decoy@example.org", "cdew@spam.example"), FB_TOP)),
      "CC_HAS_SUBMITTER", "block", "victim inside a Cc list")
do
  -- PHP's last-wins field: the later duplicate fills the placeholder.
  local f = fb_fields("Cc: cdew@{{dom}}", "cdew@spam.example")
  f[#f + 1] = { "sppb-form-builder-field[dom]", "other.example" }
  f[#f + 1] = { "sppb-form-builder-field[dom]", "spam.example" }
  fb_is(post(form(f, FB_TOP)), "CC_HAS_SUBMITTER", "block", "duplicate field: the last in posting order wins")
end

-- The cheap gate must accept every addon-key spelling PHP does (review round 3).
do
  local b = form(fb_fields("Cc: cdew@spam.example", "cdew@spam.example"), {})
  fb_is(post(b .. "&option=com_sppagebuilder&task=ajax&+addon=form_builder"),
        "CC_HAS_SUBMITTER", "block", "+addon= (a leading space PHP drops)")
  fb_is(post(b .. "&option=com_sppagebuilder&task=ajax&addon%00x=form_builder"),
        "CC_HAS_SUBMITTER", "block", "addon%00x= (a key PHP cuts at NUL)")
  local MP = "multipart/form-data; boundary=----B"
  local function part(n, v) return "------B\r\nContent-Disposition: form-data; name='" .. n .. "'\r\n\r\n" .. v .. "\r\n" end
  local m = part("addon", "form_builder") .. part("data[0][name]", "x[email]") .. part("data[0][value]", "cdew@spam.example")
    .. part("data[1][name]", "additional_header") .. part("data[1][value]", b64enc("Cc: cdew@spam.example")) .. "------B--\r\n"
  fb_is(post(m, MP), "CC_HAS_SUBMITTER", "block", "multipart name='addon' (single quotes)")
end

-- Review round 4.
do
  -- A Reply-To in the attacker's own header cannot switch the named email
  -- field off: the email fields are a union.
  fb_is(post(form(fb_fields("Reply-To: {{message}}\nCc: cdew@spam.example", "cdew@spam.example"), FB_TOP)),
        "CC_HAS_SUBMITTER", "block", "Reply-To pointing elsewhere does not hide the email field")
  fb_is(post(form(fb_fields("Reply-To: {{zzz}}\nCc: cdew@spam.example", "cdew@spam.example"), FB_TOP)),
        "CC_HAS_SUBMITTER", "block", "Reply-To naming no field does not hide the email field")
  -- Common spellings of the email field.
  for _, nm in ipairs({ "your_email", "email_address", "Email-Address", "your-email" }) do
    local f = fb_fields("Cc: cdew@spam.example", "nobody")
    f[#f + 1] = { "sppb-form-builder-field[" .. nm .. "]", "cdew@spam.example" }
    fb_is(post(form(f, FB_TOP)), "CC_HAS_SUBMITTER", "block", "email field named " .. nm)
  end
  -- PHP fills placeholders one field at a time, in posting order: a value
  -- carrying {{b}} is filled again by the later field b.
  local f = fb_fields("Cc: cdew@{{a}}", "cdew@spam.example")
  f[#f + 1] = { "sppb-form-builder-field[a]", "{{b}}" }
  f[#f + 1] = { "sppb-form-builder-field[b]", "spam.example" }
  fb_is(post(form(f, FB_TOP)), "CC_HAS_SUBMITTER", "block", "chained placeholders resolve like PHP")
  -- A cut body is logged even when the rows in the window look clean: a later
  -- duplicate (PHP keys are last-wins) may carry the real header.
  local c = post(form(fb_fields("Reply-To: {{email}}", "guest@mail.example"), FB_TOP))
  c.headers["Content-Length"] = tostring(#c.body + 40000)
  fb_is(c, "BODY_PAST_WINDOW", "logonly", "clean rows in the window, the rest unread")
end
do
  -- Linear time on attacker-sized input (each took seconds with the old
  -- patterns and stalled the nginx worker).
  local function quick(c, label)
    local t0 = os.clock()
    waf.check(c)
    local dt = os.clock() - t0
    check(dt < 0.2, string.format("%s is linear (took %.3fs)", label, dt))
  end
  local f = fb_fields("Cc: cdew@spam.example", "cdew@spam.example")
  f[#f + 1] = { string.rep("[", 30000), "x" }
  quick(post(form(f, FB_TOP)), "a 30K '[' row name")
  f = fb_fields("Cc: {{f}}@", "cdew@spam.example")
  f[#f + 1] = { "sppb-form-builder-field[f]", string.rep("a", 24000) }
  quick(post(form(f, FB_TOP)), "a 24K placeholder value ending in '@'")
  quick(post(form(fields(string.rep("a", 23000) .. "@", "cdew@spam.example"))), "a 23K ajax_contact recipient ending in '@'")
  quick(post(form(fb_fields("Cc: " .. string.rep("{", 23000), "x@y.example"), FB_TOP)), "a 23K '{' Cc value")
  quick(post(form(fb_fields("Reply-To: " .. string.rep("{", 23000), "x@y.example"), FB_TOP)), "a 23K '{' Reply-To value")
  quick(post(form(fb_fields("Cc: x" .. string.rep(" ", 23000) .. "x", "x@y.example"), FB_TOP)), "a 23K space run inside a Cc value")
  f = fb_fields("Cc: cdew@spam.example", "cdew@spam.example")
  f[#f + 1] = { "x" .. string.rep(" ", 30000) .. "x", "y" }
  quick(post(form(f, FB_TOP)), "a 30K space run inside a row name")
end

-- Measurement only.
fb_is(post(form(fb_fields("Reply-To: {{email}}\nReply-name: {{first-name}} {{last-name}}\nCc: {{email}}",
                          "victim@spam.example"), FB_TOP)),
      "CC_PLACEHOLDER", "logonly", "the titan setting: Cc: {{email}} (an honest visitor looks the same)")
-- The documented residual: a bot that WRITES a pure placeholder Cc looks like
-- the configured relay, so it is logged, not blocked.
fb_is(post(form(fb_fields("Reply-To: {{email}}\nCc: {{email}}", "cdew@spam.example"), FB_TOP)),
      "CC_PLACEHOLDER", "logonly", "a pure {{email}} Cc (configured or written) is logged only")
do
  -- The header row comes AFTER the visitor's fields, so a padded message can
  -- hide it (review round 3): a urlencoded body past the window is logged.
  local c = post(form({ { "sppb-form-builder-field[message]", string.rep("a", 500) } }, FB_TOP))
  c.headers["Content-Length"] = tostring(40000)
  fb_is(c, "BODY_PAST_WINDOW", "logonly", "urlencoded form_builder body past the window")
  -- A multipart body overflows legitimately (uploads): not logged.
  local MP = "multipart/form-data; boundary=----B"
  local b = "------B\r\nContent-Disposition: form-data; name=\"addon\"\r\n\r\nform_builder\r\n"
    .. "------B\r\nContent-Disposition: form-data; name=\"data[0][name]\"\r\n\r\nx[file]\r\n------B--\r\n"
  c = post(b, MP)
  c.headers["Content-Length"] = tostring(900000)
  clean(c, "multipart form_builder upload past the window is not logged")
end
-- A configured placeholder list is the relay too (review round 3).
fb_is(post(form(fb_fields("Cc: {{email}}, {{email}}", "victim@spam.example"), FB_TOP)),
      "CC_PLACEHOLDER", "logonly", "a placeholder-only Cc list")
-- A saved mix of placeholder and fixed address: an honest visitor is NOT
-- blocked through the placeholder half (review round 3).
fb_is(post(form(fb_fields("Reply-To: {{email}}\nCc: {{email}}, boss@gmail.com", "guest@mail.example"), FB_TOP)),
      "CC_PLACEHOLDER", "logonly", "Cc: {{email}}, boss@gmail.com from an honest visitor")

-- Clean.
clean(post(form(fb_fields("Reply-To: {{email}}\nBcc: admin@yourcompany.com", "guest@mail.example"), FB_TOP)),
      "a saved literal Bcc nobody typed (the normal case, not tagged)")
do
  -- No staff exemption (review round 4): the host it keyed on is the
  -- client's Host header on this edge, so it was a bypass. The accepted cost:
  -- an owner who hardcoded `Cc: boss@site` and tests the form AS boss@site
  -- gets one 403 for that submission (autoblock is held, no ban).
  local c = post(form(fb_fields("Cc: boss@hotel.example", "boss@hotel.example"), FB_TOP))
  c.host = "www.hotel.example"
  fb_is(c, "CC_HAS_SUBMITTER", "block", "owner testing with the address its saved Cc mails (accepted 403)")
end
do
  -- A select named *-email is not the visitor's email either (review round 3):
  -- the Reply-To placeholder names the typed field.
  local f = fb_fields("Reply-To: {{email}}\nBcc: boss@gmail.com", "guest@mail.example")
  f[#f + 1] = { "sppb-form-builder-field[department-email]", "boss@gmail.com" }
  clean(post(form(f, FB_TOP)), "a department-email select equal to the saved Bcc")
end
do
  -- A select whose value is a staff address is not typed input (review round 2).
  local f = fb_fields("Reply-To: {{email}}\nBcc: boss@gmail.com", "guest@mail.example")
  f[#f + 1] = { "sppb-form-builder-field[department]", "boss@gmail.com" }
  clean(post(form(f, FB_TOP)), "a department select equal to the saved Bcc")
end
clean(post(form(fb_fields("Cc: {{nonexistent}}", "cdew@spam.example"), FB_TOP)),
      "a placeholder naming no field is not a relay")
clean(post(form(fb_fields("Cc: none", "cdew@spam.example"), FB_TOP)), "a Cc with no address")
do
  -- The gate wants an addon KEY: `addons[..]` (WHMCS/WooCommerce) is not one.
  local b = "addons%5B1%5D=form_builder&" .. form(fb_fields("Cc: cdew@spam.example", "cdew@spam.example"), {})
  clean(post(b), "addons[] is not the addon key")
end
do
  -- A hidden row is not a form field: it never counts as "typed" (review finding).
  local f = fb_fields("Bcc: boss@partner.example", "guest@mail.example")
  f[#f + 1] = { "reply_to", "boss@partner.example" }
  clean(post(form(f, FB_TOP)), "a hidden non-field row repeating the saved Bcc")
end
-- An unknown placeholder stays as text in PHP: the address is invalid and
-- PHPMailer mails nothing, so there is nothing to flag.
clean(post(form(fb_fields("Cc: cdew@spam.example{{nothing}}", "cdew@spam.example"), FB_TOP)),
      "literal address + an unknown placeholder (undeliverable)")
clean(post("option=com_sppagebuilder&task=ajax&addon=form_builder&x=1", UE),
      "addon without any data[] row (cheap gate)")
clean(post(form(fb_fields("Reply-To: {{email}}\nReply-name: {{first-name}}", "guest@mail.example"), FB_TOP)),
      "form_builder without Cc/Bcc (the fixed setting)")
clean(post(form(fb_fields(" Cc: cdew@spam.example", "cdew@spam.example"), FB_TOP)),
      "a leading space in the key: PHP does not trim it, so no Cc")
clean(post(form(fb_fields("Cc cdew@spam.example", "cdew@spam.example"), FB_TOP)),
      "a Cc line without a colon")
clean(post(form(fb_fields("Cc: cdew@spam.example", "cdew@spam.example"),
                { option = "com_contact", task = "ajax", addon = "form_builder" })),
      "form_builder under an explicit other component")
do
  local f = fb_fields("Cc: cdew@spam.example", "cdew@spam.example")
  f[7][2] = "!!!not-base64!!!"
  clean(post(form(f, FB_TOP)), "an undecodable header")
end

-- Review round 5.
do
  local function timed(c, label)
    local t0 = os.clock()
    local hit, reason, _, act = waf.check(c)
    local dt = os.clock() - t0
    check(dt < 0.2, string.format("%s is bounded (took %.3fs)", label, dt))
    return hit, reason, act
  end
  -- Each field doubles the next one's placeholders: a 3.6 KB POST took 33 s
  -- and 4.3 KB ran the worker out of memory with the 3-pass fill. Bounded now,
  -- and an unresolvable part blocks (it is attacker-only).
  local f = fb_fields("Cc: cdew@{{a1}}", "cdew@spam.example")
  for i = 1, 40 do
    f[#f + 1] = { "sppb-form-builder-field[a" .. i .. "]", "{{a" .. (i + 1) .. "}}{{a" .. (i + 1) .. "}}" }
  end
  local _, reason, act = timed(post(form(f, FB_TOP)), "a doubling placeholder chain")
  check(reason == FB .. "CC_UNRESOLVED" and act == "block",
        "a doubling chain is CC_UNRESOLVED/block (got " .. tostring(reason) .. "/" .. tostring(act) .. ")")
  -- A value repeating its own placeholder: PHP replaces each field ONCE, so
  -- it stays literal text (undeliverable); the 3-pass fill multiplied it.
  f = fb_fields("Cc: cdew@{{a}}", "cdew@spam.example")
  f[#f + 1] = { "sppb-form-builder-field[a]", string.rep("{{a}}", 150) }
  local hit = timed(post(form(f, FB_TOP)), "a self-repeating placeholder")
  check(hit ~= true, "a self-repeating placeholder is undeliverable, not flagged")
  -- A deep honest-shaped chain still resolves like PHP.
  f = fb_fields("Cc: cdew@{{c1}}", "cdew@spam.example")
  for i = 1, 300 do f[#f + 1] = { "sppb-form-builder-field[c" .. i .. "]", "{{c" .. (i + 1) .. "}}" } end
  f[#f + 1] = { "sppb-form-builder-field[c301]", "spam.example" }
  local _, r2, a2 = timed(post(form(f, FB_TOP)), "a 300-field chain")
  check(r2 == FB .. "CC_HAS_SUBMITTER" and a2 == "block", "a 300-field chain resolves (got " .. tostring(r2) .. ")")
  -- A chain that grows past the cap and shrinks back to one address: PHP
  -- mails it, so it must not be skipped as "too long".
  f = fb_fields("Cc: cdew{{a}}@spam.example", "cdew@spam.example")
  f[#f + 1] = { "sppb-form-builder-field[a]", string.rep("{{b}}", 300) }
  f[#f + 1] = { "sppb-form-builder-field[b]", "" }
  fb_is(post(form(f, FB_TOP)), "CC_UNRESOLVED", "block", "grow-then-shrink chain past the cap")
  -- A field named with `}}`: the placeholder `{{a}}b}}` is invisible to the scan.
  f = fb_fields("Cc: cdew@{{a}}b}}", "cdew@spam.example")
  f[#f + 1] = { "sppb-form-builder-field[a}}b]", "spam.example" }
  fb_is(post(form(f, FB_TOP)), "CC_UNRESOLVED", "block", "a field name holding }}")
  -- Many placeholder parts share one step budget.
  local cc = {}
  for i = 1, 1500 do cc[#cc + 1] = "x" .. i .. "@{{d}}" end
  f = fb_fields("Cc: " .. table.concat(cc, ","), "cdew@spam.example")
  f[#f + 1] = { "sppb-form-builder-field[d]", string.rep("{{e}}", 150) }
  f[#f + 1] = { "sppb-form-builder-field[e]", "y" }
  timed(post(form(f, FB_TOP)), "1500 placeholder parts")
end
do
  -- Decoys the edge used to read as the last value (PHP does not): every
  -- candidate is checked now.
  local inj = b64enc("Cc: cdew@spam.example")
  local b = form(fb_fields("Cc: cdew@spam.example", "cdew@spam.example"), FB_TOP)
  fb_is(post(b .. "&%09" .. enc("data[6][value]") .. "=" .. enc(b64enc("Reply-To: {{email}}"))),
        "CC_HAS_SUBMITTER", "block", "a tab-led decoy key (PHP keeps it apart)")
  local MP = "multipart/form-data; boundary=----B"
  local function part(cd, v) return "------B\r\nContent-Disposition: form-data; " .. cd .. "\r\n\r\n" .. v .. "\r\n" end
  local base = part('name="addon"', "form_builder") .. part('name="data[0][name]"', "x[email]")
    .. part('name="data[0][value]"', "cdew@spam.example") .. part('name="data[1][name]"', "additional_header")
    .. part('name="data[1][value]"', inj)
  fb_is(post(base .. part('name="data[1][value]"; filename="a.txt"', b64enc("Reply-To: x")) .. "------B--\r\n", MP),
        "CC_HAS_SUBMITTER", "block", "a later multipart file part (PHP files it under $_FILES)")
  fb_is(post(base .. part('name="data[1][value]"; name="zz"', b64enc("Reply-To: x")) .. "------B--\r\n", MP),
        "CC_HAS_SUBMITTER", "block", "a later part with two name= (PHP keeps the last)")
  -- PHP's boundary: everything after the '=' that follows "boundary".
  fb_is(post(base .. "------B--\r\n", "multipart/form-data; boundary =----B"),
        "CC_HAS_SUBMITTER", "block", "boundary = with a space")
  fb_is(post(base .. "------B--\r\n", "multipart/form-data; BOUNDARY=----B"),
        "CC_HAS_SUBMITTER", "block", "upper-case BOUNDARY")
  -- PHP picks the parser by the media type before ';': a parameter naming
  -- multipart does not make a urlencoded body multipart.
  fb_is(post(b, "application/x-www-form-urlencoded; x=multipart/form-data"),
        "CC_HAS_SUBMITTER", "block", "urlencoded with a multipart-looking parameter")
  fb_is(post(b, "application/x-www-form-urlencoded,text/plain"),
        "CC_HAS_SUBMITTER", "block", "urlencoded media type cut at ','")
  clean(post(b, "text/plain; x=application/x-www-form-urlencoded"), "a text/plain body is not $_POST")
end
do
  -- A duplicate addon/option candidate cannot hide the real one.
  local b = form(fb_fields("Cc: cdew@spam.example", "cdew@spam.example"), {})
  fb_is(post(b .. "&option=com_sppagebuilder&addon=form_builder", UE, "addon=zz&option=com_x"),
        "CC_HAS_SUBMITTER", "block", "query addon/option overridden by the body")
end
do
  -- cfm.lua flags a cut body; no Content-Length needed.
  local c = post(form(fb_fields("Reply-To: {{email}}", "guest@mail.example"), FB_TOP))
  ngx.ctx = { cfm_waf_body_cut = true }
  fb_is(c, "BODY_PAST_WINDOW", "logonly", "the edge's body-cut flag")
  ngx.ctx = nil
  -- A finding in the window outranks the unread rest.
  c = post(form(fb_fields("Reply-To: {{email}}\nCc: {{email}}", "victim@spam.example"), FB_TOP))
  c.headers["Content-Length"] = tostring(#c.body + 40000)
  fb_is(c, "CC_PLACEHOLDER", "logonly", "CC_PLACEHOLDER outranks BODY_PAST_WINDOW")
end
do
  -- `contact_email` is as often a department select: not the visitor's email.
  local f = fb_fields("Reply-To: {{email}}\nBcc: boss@gmail.com", "guest@mail.example")
  f[#f + 1] = { "sppb-form-builder-field[contact_email]", "boss@gmail.com" }
  clean(post(form(f, FB_TOP)), "a contact_email select equal to the saved Bcc")
end

-- Review round 5, second pass.
do
  local function timed(c, label)
    local t0 = os.clock()
    local hit, reason, _, act = waf.check(c)
    local dt = os.clock() - t0
    check(dt < 0.2, string.format("%s is bounded (took %.3fs)", label, dt))
    return hit, reason, act
  end
  -- Many raw names trimming to one name, crossed with many values: names x
  -- values grew quadratically (>1 s, ~70 MB). A row past 16 candidates is
  -- ROWS_AMBIGUOUS (enforced; an honest form sends each key once).
  local ws = { " ", "%09", "%0A", "%0D", "%0B", "%00" }
  for _, nm in ipairs({ "recipient", "additional_header" }) do
    local parts = { "addon=" .. (nm == "recipient" and "ajax_contact" or "form_builder") }
    for a = 1, 6 do for b = 1, 6 do for c = 1, 6 do
      parts[#parts + 1] = "data%5B0%5D%5Bname%5D=" .. nm .. ws[a] .. ws[b] .. ws[c]
    end end end
    for i = 1, 300 do parts[#parts + 1] = "data%5B0%5D%5Bvalue%5D=" .. enc(b64enc("Cc:a@b,c@d\n" .. i)) end
    local _, reason, act = timed(post(table.concat(parts, "&")), nm .. " names x values")
    check(reason and reason:find(":ROWS_AMBIGUOUS$") and act == "block",
          nm .. " names x values is ROWS_AMBIGUOUS/block (got " .. tostring(reason) .. ")")
  end
  -- The fill budget with values spread over many rows (no row cap applies),
  -- and a 1 KB run of `{` in the part: every scan must stay cheap.
  local f = fb_fields("Cc: z@q{{a}}" .. string.rep("{", 1000) .. "}}", "cdew@spam.example")
  for i = 1, 600 do f[#f + 1] = { "x[a]", "v" .. i } end
  timed(post(form(f, FB_TOP)), "600 candidates x a 1 KB '{' run")
  -- A field name ending in `}`: PHP's needle `{{x}}}` is invisible to the scan.
  f = fb_fields("Cc: cdew{{x}}}@spam.example", "cdew@spam.example")
  f[#f + 1] = { "sppb-form-builder-field[x}]", "" }
  fb_is(post(form(f, FB_TOP)), "CC_UNRESOLVED", "block", "a field name ending in }")
  -- A bare key is "" in PHP; a field with no value row fills as "".
  local b = form(fb_fields("Cc: cdew{{x}}@spam.example", "cdew@spam.example"), FB_TOP)
    .. "&" .. enc("data[20][name]") .. "=" .. enc("sppb-form-builder-field[x]") .. "&" .. enc("data[20][value]")
  fb_is(post(b), "CC_HAS_SUBMITTER", "block", "a bare value key fills as empty")
  f = fb_fields("Cc: cdew{{x}}@spam.example", "cdew@spam.example")
  f[#f + 1] = { "sppb-form-builder-field[x]", "" }
  b = form(f, FB_TOP):gsub("&data%%5B9%%5D%%5Bvalue%%5D=", "&zz=")
  fb_is(post(b), "CC_HAS_SUBMITTER", "block", "a field with no value row fills as empty")
  -- Sixteen candidates is still read (a cap, not a hair trigger).
  b = form(fb_fields("Cc: cdew@spam.example", "cdew@spam.example"), FB_TOP)
  for i = 1, 15 do b = b .. "&" .. enc("data[6][name]") .. "=" .. enc("additional_header" .. string.rep(" ", i)) end
  fb_is(post(b), "CC_HAS_SUBMITTER", "block", "16 name candidates on one row")
end

-- ── Disabled ────────────────────────────────────────────────────────────────
waf.set_rule("rule_form_relay_sppb_contact", "disabled")
clean(post(form(fields("litohotel@outlook.com,cdew@spam.example", "cdew@spam.example"))), "rule disabled")
clean(post(form(fb_fields("Cc: cdew@spam.example", "cdew@spam.example"), FB_TOP)), "rule disabled (form_builder)")

if fails > 0 then
  io.stderr:write(string.format("%d failure(s)\n", fails))
  os.exit(1)
end
print("ok: cfm_waf SP Page Builder ajax_contact + form_builder mail relay (rule 520)")
