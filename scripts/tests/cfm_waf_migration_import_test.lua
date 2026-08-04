-- Tests for the FP-case-6 migration-import demotion (docs/waf.md):
-- an allowlisted WP admin-ajax migration import (CFG.migration_import_actions,
-- default "WMW_import") demotes the PHP-bearing upload scanners
-- (401/402/403, 431-436) to logonly — never skips them — because migration/
-- backup chunk uploads legitimately carry raw PHP source.
--
-- The exemption is keyed on the EFFECTIVE action the way PHP builds
-- $_REQUEST (query parse_str semantics + multipart body fields + cookies),
-- fail-closed: every spoof avenue an attacker could use to reach a different
-- wp_ajax handler while wearing the allowlisted query action must deny the
-- demotion and keep the configured block.

_G.ngx = {
  now            = function() return 1000 end,
  decode_base64  = function(_) return nil end,
  log            = function(_, _) end,
  ERR            = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function disable_all_rules()
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then
      waf.set_rule(k, "disabled")
    end
  end
end

-- ── multipart builders ───────────────────────────────────────────────────────

local B  = "----WebKitFormBoundaryTest1234"
local CT = "multipart/form-data; boundary=" .. B

local function part_field(name, value)
  return "--" .. B .. "\r\n"
      .. 'Content-Disposition: form-data; name="' .. name .. '"\r\n\r\n'
      .. value .. "\r\n"
end

local function part_field_unquoted(name, value)
  return "--" .. B .. "\r\n"
      .. "Content-Disposition: form-data; name=" .. name .. "\r\n\r\n"
      .. value .. "\r\n"
end

local function part_file(filename, content)
  return "--" .. B .. "\r\n"
      .. 'Content-Disposition: form-data; name="chunk"; filename="' .. filename .. '"\r\n'
      .. "Content-Type: application/octet-stream\r\n\r\n"
      .. content .. "\r\n"
end

local function multipart(...)
  return table.concat({ ... }) .. "--" .. B .. "--\r\n"
end

-- A migration chunk: raw PHP source travelling as file content (the FP shape).
local PHP_CHUNK = part_file("chunk.bin", "<?php echo 'migrated plugin source'; $x = 1;")

local function ctx(overrides)
  local c = {
    uri     = "/wp-admin/admin-ajax.php",
    args    = "action=WMW_import",
    method  = "POST",
    ip      = "2.85.210.197",
    headers = { ["content-type"] = CT },
    body    = multipart(PHP_CHUNK),
    cookie  = "",
  }
  for k, v in pairs(overrides or {}) do c[k] = v end
  return c
end

local function action_of(c)
  local _hit, _reason, _ttl, action = waf.check(c)
  return action
end

disable_all_rules()
waf.set_rule("rule_upload_content", "block")

-- ── The FP shape is demoted, not skipped ─────────────────────────────────────
do
  local hit, reason, _ttl, action = waf.check(ctx())
  check(hit == true, "allowlisted import must still HIT (demote, not skip)")
  check(reason and reason:find("UPLOAD_PHP_TAG", 1, true), "reason must stay UPLOAD_PHP_TAG")
  check(action == "logonly", "allowlisted import must demote block -> logonly")
end

-- Subdirectory WP installs keep the exemption (suffix match on the path).
check(action_of(ctx({ uri = "/blog/wp-admin/admin-ajax.php" })) == "logonly",
  "subdir install admin-ajax must also demote")

-- Body may repeat the allowlisted action; that is consistent, still demoted.
check(action_of(ctx({ body = multipart(part_field("action", "WMW_import"), PHP_CHUNK) })) == "logonly",
  "matching body action must keep the demotion")

-- A part whose name merely CONTAINS `action` is a different PHP field:
-- it cannot override dispatch, so it must not cost the exemption.
check(action_of(ctx({ body = multipart(part_field("actions", "evil"), PHP_CHUNK) })) == "logonly",
  "part named `actions` must not deny the demotion")

-- ── Every dispatch-spoof avenue stays at block ───────────────────────────────

check(action_of(ctx({ args = "" })) == "block",
  "no query action -> no exemption")

check(action_of(ctx({ args = "action=evil_upload" })) == "block",
  "non-allowlisted action -> block")

check(action_of(ctx({ args = "action=wmw_import" })) == "block",
  "action names are case-sensitive (WP hooks are) -> block")

-- PHP parse_str: last duplicate wins — and dispatches evil.
check(action_of(ctx({ args = "action=WMW_import&action=evil" })) == "block",
  "duplicate query action (last=evil) -> block")

-- PHP decodes param NAMES: %61ction is `action` to parse_str, and being
-- later it wins the dispatch.
check(action_of(ctx({ args = "action=WMW_import&%61ction=evil" })) == "block",
  "percent-encoded duplicate action name -> block")

-- Body action overrides query in $_REQUEST (request_order=GP).
check(action_of(ctx({ body = multipart(part_field("action", "evil"), PHP_CHUNK) })) == "block",
  "conflicting multipart body action -> block")

-- PHP's rfc1867 parser also accepts an unquoted name token.
check(action_of(ctx({ body = multipart(part_field_unquoted("action", "evil"), PHP_CHUNK) })) == "block",
  "conflicting UNQUOTED body action -> block")

-- request_order=GPC hosts let a cookie named `action` override GET.
check(action_of(ctx({ cookie = "wp_sess=abc; action=evil" })) == "block",
  "cookie named `action` -> block")

-- Wrong endpoint: the allowlisted action means nothing off admin-ajax.
check(action_of(ctx({ uri = "/index.php" })) == "block",
  "non-admin-ajax URI -> block")

-- ── Demotion covers the whole legit-PHP-upload scanner set (401 too) ─────────
do
  disable_all_rules()
  waf.set_rule("rule_upload_filename", "block")
  local shell_name = multipart(part_file("shell.php", "junk-not-php"))
  check(action_of(ctx({ body = shell_name })) == "logonly",
    "rule 401 must demote for the allowlisted import")
  check(action_of(ctx({ body = shell_name, args = "action=evil" })) == "block",
    "rule 401 must stay block without the allowlist match")
end

if fails > 0 then
  io.stderr:write(("cfm_waf_migration_import_test.lua: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf migration-import demotion tests (FP case 6: 401/402 -> logonly, spoofs stay block)")
