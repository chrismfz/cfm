-- cfm.lua's challenge_resume redirects (a challenged POST, stashed for replay)
-- must go to /__cfm_challenge, never "/?next=". A sibling tab can clear the
-- browser before the redirect is followed, and "/" then passes to the site's
-- homepage and drops the stashed POST (ligaapola.gr, 2026-09-30). The challenge
-- server sends a cleared client straight to next, i.e. to the cfm_rt resume.

local f = assert(io.open("configs/lua/cfm.lua", "r"))
local src = f:read("*a"); f:close()

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

check(src:find('ngx.redirect("/?next="', 1, true) == nil,
      'cfm.lua still redirects a challenged request to "/?next="')
local n = 0
for _ in src:gmatch('ngx%.redirect%("/__cfm_challenge%?next=" %.%. esc%(with_query_arg%(') do n = n + 1 end
check(n == 2, "expected both challenge_resume redirects (Step 2 WAF, Step 3) to use /__cfm_challenge, found " .. n)

if fails > 0 then os.exit(1) end
print("ok: challenge_resume redirects go through /__cfm_challenge")
