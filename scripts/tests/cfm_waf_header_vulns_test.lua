-- Rule 603 (WAF_HEADER_VULN) header-presence checks.
--
-- FP 2026-09-29 (earth, cloud.nexon.gr): a Nextcloud desktop client
-- (mirall/34.0.4) deleting files over WebDAV sends an RFC 4918 `If:` header.
-- Rule 603 flagged its mere presence as CVE-2017-7269 (HEADER_IF_WEBDAV) and
-- challenged the IP; a sync client cannot solve a challenge, so sync broke and
-- every site served the owner a challenge for the decision TTL. Over 150 h
-- that client's deletes were the fleet's only 603 hits. CVE-2017-7269 is an
-- IIS 6.0 overflow and no node runs IIS, so the `If:` / `Lock-Token:` checks
-- were removed (docs/waf.md FP case 12). httpoxy and CVE-2025-24813 stay.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR = 0, WARN = 1, INFO = 2,
}

package.path = "configs/lua/?.lua;" .. package.path
local waf = require("cfm_waf")
local det = require("cfm_waf_detectors")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local snap = waf.get_config()
for k, _ in pairs(snap) do
  if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
end
waf.set_rule("rule_header_vulns", "challenge_v2")

local MIRALL = "Mozilla/5.0 (Windows) mirall/34.0.4 (build 20260916) (Nextcloud, windows-10.0.19044 ClientArchitecture: x86_64 OsArchitecture: x86_64)"

local function req(method, uri, headers)
  headers = headers or {}
  headers["User-Agent"] = headers["User-Agent"] or MIRALL
  return { uri = uri, args = "", method = method, ip = "94.68.42.127",
           headers = headers, body = "", cookie = "" }
end
local function clean(c, label)
  local hit, reason = waf.check(c)
  check(hit ~= true, label .. " — must NOT fire (got " .. tostring(reason) .. ")")
end
local function fires(c, label, want)
  local hit, reason = waf.check(c)
  check(hit == true, label .. " — must fire (got hit=" .. tostring(hit) .. ")")
  if want then check(reason == want, label .. " — reason " .. want .. " (got " .. tostring(reason) .. ")") end
end

local DAV = "/remote.php/dav/files/chris/"

-- ── The FP: ordinary WebDAV conditional / lock headers stay clean ────────────
clean(req("DELETE", DAV .. "protasi_stadio_A_kollises.docx",
          { ["If"] = '(["a1b2c3d4e5f6"])' }),
      "Nextcloud DELETE with an ETag If: (the live hit)")
clean(req("DELETE", DAV .. "%CE%A0%CE%B5%CF%84%CF%81%CE%BF%CF%8D%CE%BB%CE%B1%202.docx",
          { ["if"] = '(["0a9b8c7d"])' }),
      "lowercase if: header, Greek file name")
clean(req("PUT", DAV .. "report.xlsx",
          { ["If"] = "(<opaquelocktoken:e71d4fae-5dec-22d6-fea5-00a0c91e6be4>)" }),
      "PUT under a lock (untagged list)")
clean(req("MOVE", DAV .. "a.docx",
          { ["If"] = "<https://cloud.example.gr" .. DAV .. "a.docx> (<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>)",
            ["Destination"] = "https://cloud.example.gr" .. DAV .. "b.docx" }),
      "MOVE with a tagged-list If:")
clean(req("UNLOCK", DAV .. "a.docx",
          { ["Lock-Token"] = "<opaquelocktoken:a515cfa4-5da4-22e1-f5b5-00a0451e6bf7>",
            ["User-Agent"] = "Microsoft Office Word 2014" }),
      "Office UNLOCK with Lock-Token:")
clean(req("UNLOCK", DAV .. "a.docx", { ["lock-token"] = "<urn:uuid:x>" }),
      "lowercase lock-token: header")
-- The retired CVE-2017-7269 shape is deliberately not detected any more: it
-- only overflows IIS 6.0, which no node runs.
clean(req("PROPFIND", "/", { ["If"] = "<http://localhost/aaaaaaa" .. ("\230\189\168"):rep(40) .. "> (Not <locktoken:write1>)",
                             ["User-Agent"] = "-" }),
      "IIS 6.0 CVE-2017-7269 If: shape (no target on the fleet)")
check(det.detect_header_vulns({ ["If"] = "(x)", ["Lock-Token"] = "<x>" }, "/", "delete") == nil,
      "detector: If: / Lock-Token: alone return nil")

-- ── What rule 603 still covers ───────────────────────────────────────────────
fires(req("GET", "/index.php", { ["Proxy"] = "http://203.0.113.9:8080" }),
      "httpoxy Proxy: header", "WAF_HEADER_VULN:HEADER_HTTPOXY")
fires(req("GET", "/cgi-bin/x.php", { ["proxy"] = "http://203.0.113.9:8080" }),
      "httpoxy lowercase proxy: header", "WAF_HEADER_VULN:HEADER_HTTPOXY")
fires(req("PUT", "/examples/session", { ["Content-Range"] = "bytes 0-5/100" }),
      "CVE-2025-24813 Tomcat partial PUT", "WAF_HEADER_VULN:CVE_2025_24813")
fires(req("PUT", "/app/session", { ["If"] = "(x)", ["content-range"] = "bytes 0-5/100" }),
      "CVE-2025-24813 still fires alongside an If: header", "WAF_HEADER_VULN:CVE_2025_24813")
clean(req("PUT", "/app/session", {}), "PUT /session without Content-Range")
clean(req("PUT", DAV .. "session", { ["If"] = "(x)" }), "WebDAV PUT to a file named session, no Content-Range")

if fails > 0 then
  io.stderr:write(("cfm_waf header-vulns tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf rule 603 header vulns (WebDAV If:/Lock-Token: FP)")
