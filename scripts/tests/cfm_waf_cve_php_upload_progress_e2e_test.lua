-- Rules 10023 / 10024 (CVE-2026-109619, PHP2Shell) through cfm.lua. On
-- 2026-10-21 the tool's POST / passed this edge: a chunked or large body on
-- `location /` is in the body burn-in, which turns a body hit into logonly.
--   * 10024 (the PHP_SESSION_UPLOAD_PROGRESS field) is enforced there too
--     (BURNIN_ENFORCE_IDS), also when the body trips another burn-in rule;
--   * a browser's own same-site upload-progress form stays allowed;
--   * 10023 (the tool's head) blocks before any body is read.

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

local CT = "multipart/form-data; boundary=XB"
local PROGRESS = '--XB\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n' ..
                 '--XB\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n\r\nzz\r\n--XB--\r\n'

local function post(t)
  local headers = { ["content-type"] = CT, ["user-agent"] = t.ua or "Mozilla/5.0", host = "120.gr" }
  for k, v in pairs(t.headers or {}) do headers[k] = v end
  local vars = { http_content_type = CT, http_content_length = t.cl,
                 cfm_body_buffered = t.buffered and "1" or "" }
  return H.run{ method = "POST", uri = t.uri or "/", args = "", body = t.body or PROGRESS,
                headers = headers, vars = vars }
end

-- 10024 in the body burn-in (chunked POST / on `location /`): blocked.
do
  local r = post{ buffered = true }
  check(r.ok and r.exited == 403 and r.action == "block", "progress field, chunked POST / in burn-in: blocked (" .. desc(r) .. ")")
  check(r.rpcs:find("ip_push", 1, true) ~= nil, "the enforced burn-in hit is pushed (" .. r.rpcs .. ")")
  -- …even when the body also trips another body rule (SQLi in a field).
  local mixed = '--XB\r\nContent-Disposition: form-data; name="q"\r\n\r\n1\' UNION SELECT user_pass FROM wp_users-- -\r\n' .. PROGRESS
  r = post{ buffered = true, body = mixed }
  check(r.ok and r.exited == 403 and r.action == "block", "progress field + SQLi field in burn-in: blocked (" .. desc(r) .. ")")
  -- measured, to an allowlisted .php (read in full): blocked
  r = post{ uri = "/wp-login.php", cl = tostring(#PROGRESS) }
  check(r.ok and r.exited == 403, "progress field to /wp-login.php: blocked (" .. desc(r) .. ")")
  -- a forged same-site Referer alone: blocked
  r = post{ buffered = true, headers = { referer = "https://120.gr/" } }
  check(r.ok and r.exited == 403, "forged same-site Referer, no Fetch Metadata: blocked (" .. desc(r) .. ")")
end

-- A browser's own same-site upload-progress form: allowed (logonly).
do
  local r = post{ buffered = true, headers = { referer = "https://120.gr/upload", origin = "https://120.gr",
                                              ["sec-fetch-site"] = "same-origin" } }
  check(r.ok and r.exited == nil, "same-site browser upload with progress field: allowed (" .. desc(r) .. ")")
end

-- 10023: the tool's User-Agent, on a GET (its check probe) and on its POST.
do
  local r = H.run{ method = "GET", uri = "/", args = "", body = "",
                   headers = { ["user-agent"] = "php2shell-scanner", host = "11ads.gr" }, vars = {} }
  check(r.ok and r.exited == 403, "GET with the tool UA: blocked (" .. desc(r) .. ")")
  r = post{ buffered = true, ua = "php2shell-scanner",
            headers = { referer = "https://120.gr/", ["sec-fetch-site"] = "same-origin" } }
  check(r.ok and r.exited == 403, "tool UA POST with forged browser headers: blocked (" .. desc(r) .. ")")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_cve_php_upload_progress_e2e_test: OK")
