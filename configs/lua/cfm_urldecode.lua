-- cfm_urldecode: the one %XX decoder of the edge Lua. cfm_waf_util's
-- url_decode_once (the WAF's normalized scan surface, the PHP field reader,
-- the filename*= check) and cfm_cache's cookie_key (Site Cache session-cookie
-- matching) both use it, so the two cannot drift apart. No dependencies: the
-- Site Cache must not hang off a WAF module.
--
-- percent(s): every %XX (either hex case) becomes its byte; anything else,
-- a malformed escape included, stays as written. `+` is NOT a space here
-- (callers that read a form or a cookie name add that themselves). A gsub
-- with a table replacement: no Lua call per escape. HEX_BYTE holds every pair
-- %x%x can match, so nothing falls through to the literal match;
-- scripts/tests/cfm_waf_hex_decode_test.lua pins it to
-- string.char(tonumber(h, 16)) over every byte pair.

local M = {}

local HEX_BYTE = {}
do
  local hx = "0123456789abcdef"
  for i = 0, 255 do
    local a, b = math.floor(i / 16) + 1, i % 16 + 1
    for _, x in ipairs({ hx:sub(a, a), hx:sub(a, a):upper() }) do
      for _, y in ipairs({ hx:sub(b, b), hx:sub(b, b):upper() }) do
        HEX_BYTE[x .. y] = string.char(i)
      end
    end
  end
end

function M.percent(s)
  return (s:gsub("%%(%x%x)", HEX_BYTE))
end

return M
