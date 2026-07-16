-- Tests for the CRLF detector's multipart/form-data carve-out
-- (rule 605 WAF_CRLF, production tier: logonly).
--
-- A multipart/form-data body legitimately carries a per-part `Content-Type:`
-- (and sometimes `Content-Length:`) MIME header on its own `\r\n`-terminated
-- line for every file/typed part. The raw `[\r\n]…content-type:` branch matched
-- those, so EVERY legit upload (roundcube webmail, wp-admin async-upload,
-- OpenCart filemanager, TYPO3, Elementor) tripped CRLF_CONTENT_TYPE — a
-- structural false positive. Fix: when the request body is multipart/form-data,
-- scope the content-type/content-length raw match to the ARGS surface (those
-- header names can appear legitimately in a multipart body but never in the
-- query string). Set-Cookie / Location / URL-encoded branches stay full-surface.
--
-- Tested at "block" for a crisp hit=true/false assertion (rule-605/606 test
-- convention); the production tier is unchanged (logonly).

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

local function set_only(map)
  local snap = waf.get_config()
  for k, _ in pairs(snap) do
    if k:sub(1, 5) == "rule_" then waf.set_rule(k, "disabled") end
  end
  for k, m in pairs(map) do waf.set_rule(k, m) end
end

-- A realistic multipart file-upload part, as browsers/CMS clients emit it: the
-- part declares its own Content-Type on a `\r\n`-terminated line.
local MULTIPART_UPLOAD =
  "------WebKitFormBoundaryAbc123\r\n" ..
  'Content-Disposition: form-data; name="async-upload"; filename="photo.jpg"\r\n' ..
  "Content-Type: image/jpeg\r\n" ..
  "\r\n" ..
  "\xff\xd8\xff\xe0JFIFbinarydata\r\n" ..
  "------WebKitFormBoundaryAbc123--\r\n"

local function post_multipart(uri, args, body)
  return {
    uri = uri, args = args or "", method = "POST", ip = "198.51.100.10",
    headers = { ["Content-Type"] = "multipart/form-data; boundary=----WebKitFormBoundaryAbc123" },
    body = body,
  }
end
local function post_urlenc(body)
  return {
    uri = "/submit.php", args = "", method = "POST", ip = "198.51.100.11",
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" }, body = body,
  }
end

local function fires(ctx, label, want_reason)
  local hit, reason = waf.check(ctx)
  check(hit == true, label .. " — hit=true (got " .. tostring(hit) .. ")")
  check(reason == want_reason, label .. " — reason=" .. want_reason .. " (got " .. tostring(reason) .. ")")
end
local function clean(ctx, label)
  local hit = waf.check(ctx)
  check(hit ~= true, label .. " — must NOT fire (got hit=" .. tostring(hit) .. ")")
end

set_only({ rule_crlf_injection = "block" })

-- ── FP fix: legit multipart uploads no longer trip CRLF_CONTENT_TYPE ─────────
clean(post_multipart("/wp-admin/async-upload.php", "", MULTIPART_UPLOAD),
      "wp-admin async-upload (Elementor/WP media)")
clean(post_multipart("/admin/index.php",
      "route=common/filemanager/upload&user_token=abc123&directory=", MULTIPART_UPLOAD),
      "OpenCart filemanager upload")
clean(post_multipart("/cpsess123/3rdparty/roundcube/",
      "_task=mail&_remote=1&_from=compose&_action=upload", MULTIPART_UPLOAD),
      "roundcube webmail compose attachment")

-- Content-Length as a part header must also be tolerated inside multipart.
clean(post_multipart("/wp-admin/async-upload.php", "",
      "------b\r\nContent-Disposition: form-data; name=f; filename=a.png\r\n" ..
      "Content-Length: 5\r\n\r\nPNG..\r\n------b--\r\n"),
      "multipart part with Content-Length header")

-- The URL-encoded branch also decodes the full surface; the multipart part's
-- `\r\nContent-Type:` survives url-decoding, so an upload that merely CONTAINS a
-- literal `%0a` (in a field/filename/arg) must NOT re-trip the FP as
-- CRLF_URL_ENCODED — the content-type match there is args-scoped too.
clean(post_multipart("/wp-admin/async-upload.php", "",
      "------b\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n" ..
      "line one%0aline two\r\n" ..                    -- literal %0a in a field value
      "------b\r\nContent-Disposition: form-data; name=f; filename=a.png\r\n" ..
      "Content-Type: image/png\r\n\r\nPNG..\r\n------b--\r\n"),
      "multipart body containing literal %0a (URL-encoded branch)")
clean(post_multipart("/wp-admin/async-upload.php", "note=a%0ab", MULTIPART_UPLOAD),
      "multipart with %0a in the query string")

-- Duplicated Content-Type header (ngx delivers a table) must not crash the
-- detector, and the multipart value must still be recognised.
clean({
  uri = "/wp-admin/async-upload.php", args = "", method = "POST", ip = "198.51.100.12",
  headers = { ["Content-Type"] = { "multipart/form-data; boundary=----b", "text/plain" } },
  body = MULTIPART_UPLOAD,
}, "duplicated Content-Type header (table value) — no crash, multipart honoured")

-- ── Still catches real attacks even under a multipart Content-Type ───────────
-- An injected Set-Cookie / Location in the body is never part of multipart
-- framing, so it must still fire regardless of the request Content-Type.
fires(post_multipart("/x.php", "", "field=foo\r\nSet-Cookie: sid=evil\r\n"),
      "Set-Cookie injection under multipart CT", "WAF_CRLF:CRLF_SET_COOKIE")
fires(post_multipart("/x.php", "", "field=foo\r\nLocation: http://evil/\r\n"),
      "Location injection under multipart CT", "WAF_CRLF:CRLF_LOCATION")
-- A Content-Type injection in the QUERY STRING is still caught for multipart
-- requests (the carve-out scopes to args, it does not disable the check).
fires(post_multipart("/x.php", "r=/a\r\nContent-Type: text/html", MULTIPART_UPLOAD),
      "Content-Type injection in args under multipart CT", "WAF_CRLF:CRLF_CONTENT_TYPE")
-- URL-encoded Content-Type injection in the QUERY STRING under multipart still
-- fires (args-scoped decode still runs).
fires(post_multipart("/x.php", "r=x%0aContent-Type:%20text/html", MULTIPART_UPLOAD),
      "URL-encoded Content-Type in args under multipart CT", "WAF_CRLF:CRLF_URL_ENCODED")

-- ── Regressions: non-multipart requests keep full-surface Content-Type match ─
fires(post_urlenc("x=foo\r\nContent-Type: text/html"),
      "urlencoded body Content-Type still fires", "WAF_CRLF:CRLF_CONTENT_TYPE")
fires(post_urlenc("x=foo\r\nContent-Length: 0"),
      "urlencoded body Content-Length still fires", "WAF_CRLF:CRLF_CONTENT_LENGTH")
fires(post_urlenc("x=foo%0aContent-Type:%20text/html"),
      "urlencoded body URL-encoded Content-Type still fires", "WAF_CRLF:CRLF_URL_ENCODED")

if fails > 0 then
  io.stderr:write(("cfm_waf CRLF multipart carve-out tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf CRLF multipart carve-out (rule 605 upload FP)")
