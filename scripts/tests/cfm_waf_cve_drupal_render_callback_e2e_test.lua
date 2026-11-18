-- Rule 10030 (Drupal render-array callback keys) through cfm.lua. Drupal 8's
-- Drupalgeddon2 is a POST /user/register, which is not on the POST allowlist:
-- a chunked or large body is read in the body burn-in, which turns a body hit
-- into logonly unless the rule is in BURNIN_ENFORCE_IDS.

local H = dofile("scripts/tests/cfm_lua_harness.lua")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function desc(r)
  return ("ok=%s action=%s up=%s exit=%s err=%s"):format(tostring(r.ok), tostring(r.action),
    tostring(r.upstream), tostring(r.exited), tostring(r.err))
end

local CT = "application/x-www-form-urlencoded"
local D8 = "form_id=user_register_form&_drupal_ajax=1&mail%5B%23post_render%5D%5B%5D=exec" ..
           "&mail%5B%23type%5D=markup&mail%5B%23markup%5D=id"

local function post(t)
  local headers = { ["content-type"] = CT, ["user-agent"] = "Mozilla/5.0", host = "120.gr" }
  local vars = { http_content_type = CT, http_content_length = t.cl,
                 cfm_body_buffered = t.buffered and "1" or "" }
  return H.run{ method = "POST", uri = "/user/register",
                args = "element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
                body = t.body or D8, headers = headers, vars = vars }
end

do
  local r = post{ buffered = true }
  check(r.ok and r.exited == 403 and r.action == "block", "Drupalgeddon2, chunked body in burn-in: blocked (" .. desc(r) .. ")")
  check(r.rpcs:find("ip_push", 1, true) ~= nil, "the enforced burn-in hit is pushed (" .. r.rpcs .. ")")
  -- …even when the body also trips another body rule (SQLi in a field)
  r = post{ buffered = true, body = "name=1%27+UNION+SELECT+user_pass+FROM+users--+-&" .. D8 }
  check(r.ok and r.exited == 403 and r.action == "block", "Drupalgeddon2 + SQLi field in burn-in: blocked (" .. desc(r) .. ")")
  -- a plain registration in burn-in: allowed
  r = post{ buffered = true, body = "form_id=user_register_form&mail=a%40b.gr&name=anna" }
  check(r.ok and r.exited == nil, "plain registration in burn-in: allowed (" .. desc(r) .. ")")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_cve_drupal_render_callback_e2e_test: OK")
