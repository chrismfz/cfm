-- Rules 10021 / 10022 (CVE-2026-109618, PHP multipart OOM) through cfm.lua:
--   * 10021 is enforced in the body burn-in too: its exploit is exactly a
--     large or chunked body on `location /` (POST / to WordPress), which the
--     burn-in otherwise turns into a logonly hit — even when the body also
--     trips another (burn-in) block rule;
--   * 10022 (no Content-Length) fires only for a body the edge never read:
--     one read in full first (allowlisted path, `location /`) goes upstream
--     with a real Content-Length, so it is not the exploit there.

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
local function has_log(r, word)
  for _, l in ipairs(r.logs) do if l:find(word, 1, true) then return true end end
  return false
end

local CT = "multipart/form-data; boundary=XB"
local function empty_files(n, lead)
  local t = { lead or "" }
  for _ = 1, n do t[#t + 1] = '--XB\r\nContent-Disposition: form-data; name="f[]"; filename=""\r\n\r\n\r\n' end
  t[#t + 1] = "--XB--\r\n"
  return table.concat(t)
end
local OOM = empty_files(140)
local CLEAN = '--XB\r\nContent-Disposition: form-data; name="comment"\r\n\r\nhello\r\n--XB--\r\n'

local function post(t)
  -- The current confs declare $cfm_body_buffered everywhere: "1" on
  -- `location /`, "" on the streaming locations.
  local vars = { http_content_type = CT, http_content_length = t.cl,
                 cfm_body_buffered = t.buffered and "1" or "" }
  return H.run{ method = "POST", uri = t.uri or "/", args = "", body = t.body or OOM,
                headers = { ["content-type"] = CT, ["user-agent"] = "Mozilla/5.0" }, vars = vars,
                read_body_error = t.read_body_error }
end

-- 10021, enforced.
do
  local r = post{ cl = tostring(#OOM), uri = "/wp-admin/async-upload.php" }
  check(r.ok and r.exited == 403, "measured OOM body to a .php path: blocked (" .. desc(r) .. ")")
  -- chunked on `location /`: burn-in, but 10021 is enforced there.
  r = post{ buffered = true }
  check(r.ok and r.exited == 403 and r.action == "block", "chunked OOM body on `location /`: blocked in burn-in (" .. desc(r) .. ")")
  check(r.rpcs:find("ip_push", 1, true) ~= nil, "the enforced burn-in hit is pushed (" .. r.rpcs .. ")")
  -- …even when the body also trips another block rule first (SQLi field).
  local mixed = empty_files(140, "--XB\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n1' UNION SELECT user_pass FROM wp_users-- -\r\n")
  r = post{ buffered = true, body = mixed }
  check(r.ok and r.exited == 403 and r.action == "block", "OOM body + SQLi field in burn-in: still blocked (" .. desc(r) .. ")")
  -- A cleared client whose request also trips a low-risk challenge-tier rule
  -- (XSS in the query, rule 302): the challenge used to skip the burn-in body
  -- pass and turn into logonly for the clearance holder, so the body went
  -- upstream. 10021 must still block it.
  r = H.run{ method = "POST", uri = "/", args = "q=<script>alert(1)</script>", body = OOM, clearance = true,
             cookie = "cfm_clearance=good",
             headers = { ["content-type"] = CT, ["user-agent"] = "Mozilla/5.0", cookie = "cfm_clearance=good" },
             vars = { http_content_type = CT, cfm_body_buffered = "1", cookie_cfm_clearance = "good" } }
  check(r.ok and r.exited == 403 and r.action == "block",
        "cleared client + challenge-tier query + OOM body in burn-in: blocked (" .. desc(r) .. ")")
  -- A clean multipart body in burn-in stays allowed.
  r = post{ buffered = true, body = CLEAN }
  check(r.ok and r.exited == nil and r.action == "allow", "clean chunked multipart on `location /`: allowed (" .. desc(r) .. ")")
end

-- 10022.
do
  -- Length-less, read in full by cfm.lua (allowlisted .php): not flagged.
  local r = post{ uri = "/wp-login.php", body = CLEAN }
  check(r.ok and r.exited == nil and r.reads == 1, "chunked multipart to an allowlisted .php: read, allowed (" .. desc(r) .. ")")
  -- Length-less on `location /`: buffered by nginx, not flagged.
  r = post{ buffered = true, body = CLEAN }
  check(r.ok and r.exited == nil, "chunked multipart on `location /`: allowed (" .. desc(r) .. ")")
  -- Length-less and never read (HTTP/3 read failure): blocked by 10022.
  r = post{ uri = "/wp-login.php", body = CLEAN,
            read_body_error = "http3 requests are not supported without content-length header" }
  check(r.ok and r.exited == 403, "unread length-less multipart: blocked by 10022 (" .. desc(r) .. ")")
  -- A streaming path off the body allowlist: never read, blocked.
  r = post{ uri = "/sysadmin/", body = CLEAN }
  check(r.ok and r.exited == 403 and r.reads == 0, "length-less multipart on an unread streaming path: blocked (" .. desc(r) .. ")")
  -- An edge conf older than $cfm_body_buffered: unknown, so never 10022.
  r = H.run{ method = "POST", uri = "/sysadmin/", body = CLEAN,
             headers = { ["content-type"] = CT, ["user-agent"] = "Mozilla/5.0" },
             vars = { http_content_type = CT } }
  check(r.ok and r.exited == nil, "old conf (no $cfm_body_buffered): no 10022 (" .. desc(r) .. ")")
  -- With a Content-Length: never 10022.
  r = post{ uri = "/sysadmin/", body = CLEAN, cl = tostring(#CLEAN) }
  check(r.ok and r.exited == nil, "measured multipart on the same path: allowed (" .. desc(r) .. ")")
end

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("cfm_waf_cve_php_multipart_oom_e2e_test: OK")
