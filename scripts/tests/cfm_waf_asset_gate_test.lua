-- Tests for is_php_hostile_asset_upload — the gate that scopes rule 414
-- (php-inside-an-uploaded-zip) to JOOMLA media-asset uploads only. The decision
-- to run rule 414 at `block` rests entirely on this being provably Joomla-only:
-- a match REQUIRES both `option=com_<component>` AND `task=asset.upload*`, each
-- anchored to a query-param boundary. `option=com_` is a Joomla-only routing
-- param, so WordPress (action=), OpenCart (route=), Magento, PrestaShop
-- (controller=) and Drupal cannot match — no cross-platform false positives.
-- args is nginx $args (RAW, not URL-decoded), so anchoring is on raw bytes.

package.path = "configs/lua/?.lua;" .. package.path
local u = require("cfm_waf_util")
local gate = u.is_php_hostile_asset_upload

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- Positive: the confirmed Joomla SP Page Builder vector + siblings.
check(gate("/index.php", "option=com_sppagebuilder&task=asset.uploadcustomicon"), "sppb uploadCustomIcon must match")
check(gate("/index.php", "option=com_sppagebuilder&task=asset.uploadimage"),      "sppb uploadImage must match")
check(gate("/index.php", "option=com_sppagebuilder&task=asset.uploadfont"),       "sppb uploadFont must match")
check(gate("/index.php", "task=asset.upload&option=com_sppagebuilder"),           "reversed param order must match")
check(gate("/index.php?option=com_pagebuilderck&task=asset.upload", ""),          "option/task carried in the uri must match")

-- Negative: OTHER PLATFORMS must never match, even if they carry task=asset.upload.
check(not gate("/wp-admin/admin-ajax.php", "action=asset.upload"),                "WordPress (action=) must NOT match")
check(not gate("/index.php", "route=tool/upload&task=asset.upload"),              "OpenCart (route=) must NOT match")
check(not gate("/admin/index.php", "controller=AdminProducts&task=asset.upload"), "PrestaShop (controller=) must NOT match")
check(not gate("/node/add", "q=media/upload&task=asset.upload"),                  "Drupal (q=/path) must NOT match")
check(not gate("/x", "task=asset.upload"),                                        "task alone (no option=com_) must NOT match")

-- Negative: Joomla NON-asset endpoints must NOT match (installer / content / media).
check(not gate("/administrator/index.php", "option=com_installer&task=install.install"), "Joomla installer must NOT match")
check(not gate("/index.php", "option=com_content&task=article.save"),             "Joomla non-asset task must NOT match")
check(not gate("/index.php", "option=com_media&task=file.upload"),                "Joomla media manager (not asset.upload) must NOT match")

-- Negative: a URL-encoded copy of the Joomla URL sitting inside another param's
-- value must NOT trip (anchoring is on raw bytes; %3f/%26 are not ?/&).
check(not gate("/x", "redirect=%2findex.php%3foption=com_x%26task=asset.upload"),  "encoded substring in a value must NOT match")

if fails > 0 then
  io.stderr:write(("cfm_waf_asset_gate_test.lua: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf asset-upload gate is provably Joomla-scoped (rule 414)")
