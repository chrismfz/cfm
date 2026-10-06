-- Behavioural test: a stored POST-resume entry (cfm_rt) is consumed by its
-- OWNER only.
--
-- WHY THIS EXISTS
--   try_apply_post_resume() used to delete the "pr|<token>" entry BEFORE it
--   checked that the request's ip and host match the entry's. The first GET
--   carrying the token, from ANY client, therefore spent it, and the visitor's
--   replay was lost. The token is in the visitor's address bar while they
--   solve (escaped inside the challenge page's next=), and a fetcher handed
--   that URL that solves the challenge and follows next (Google-Read-Aloud
--   does both) could get there first. A foreign GET must now leave the entry,
--   and the request, alone.
--
--   cfm.lua is a top-to-bottom access script that is impractical to require
--   standalone (see cfm_post_resume_readbody_test.lua), so this extracts the
--   function from the source and runs it against stubs of ngx, the shared dict
--   and cjson.

local function read(path)
  local f = assert(io.open(path, "r"), "cannot open " .. path)
  local s = f:read("*a")
  f:close()
  return s
end

local fails = 0
local function check(cond, msg)
  if not cond then
    io.stderr:write("FAIL: " .. msg .. "\n")
    fails = fails + 1
  end
end

local cfm = read("configs/lua/cfm.lua")
local src = cfm:match("(local function try_apply_post_resume%s*%b().-\nend)")
assert(src, "try_apply_post_resume() not found in cfm.lua (signature changed?)")

-- Shared dict stub.
local dict = {}
local SH = {
  get = function(_, k) return dict[k] end,
  set = function(_, k, v) dict[k] = v; return true end,
  delete = function(_, k) dict[k] = nil end,
}
-- cjson stub: an entry's raw value is a key into this registry.
local objs = {}
local cjson = { decode = function(raw) return objs[raw] end }
local CFG = { post_resume_enable = true, post_resume_max_len = 65536 }

local chunk = "local CFG, SH, cjson, lower, log_route = ...\n" .. src .. "\nreturn try_apply_post_resume"
local loader = assert((loadstring or load)(chunk))
local try_apply_post_resume = loader(CFG, SH, cjson, string.lower, function() end)

-- One request's ngx: a GET carrying ?cfm_rt=<tok>.
local applied
local function request(tok)
  applied = {}
  _G.ngx = {
    HTTP_POST = "POST", INFO = 7,
    ctx = {},
    var = { arg_cfm_rt = tok },
    decode_base64 = function(s) return s end,
    req = {
      get_method = function() return "GET" end,
      get_uri_args = function() return { cfm_rt = tok } end,
      read_body = function() applied.read = true end,
      set_method = function(m) applied.method = m end,
      set_header = function(k, v) applied[k] = v end,
      set_body_data = function(b) applied.body = b end,
      set_uri = function(u) applied.uri = u end,
      set_uri_args = function(a) applied.args = a end,
    },
  }
end

local function store(tok, ip, host)
  local raw = "raw-" .. tok
  objs[raw] = { ip = ip, host = host, uri = "/wp-admin/post.php?post=7",
                method = "POST", ctype = "application/x-www-form-urlencoded",
                body_b64 = "title=hello" }
  dict["pr|" .. tok] = raw
end

local OWNER, HOST = "203.0.113.10", "shop.example.com"

-- A fetcher on another IP (the visitor's URL, handed to Google-Read-Aloud).
store("tok1", OWNER, HOST)
request("tok1")
check(try_apply_post_resume("66.102.8.73", HOST) == false, "a foreign IP must not apply the replay")
check(next(applied) == nil, "a foreign IP's request must be left alone")
check(dict["pr|tok1"] ~= nil, "a foreign IP must not spend the owner's token")

-- The owner's IP on another host.
store("tok2", OWNER, HOST)
request("tok2")
check(try_apply_post_resume(OWNER, "other.example.com") == false, "another host must not apply the replay")
check(next(applied) == nil, "another host's request must be left alone")
check(dict["pr|tok2"] ~= nil, "another host must not spend the owner's token")

-- The owner: the replay applies and the token is spent.
store("tok3", OWNER, HOST)
request("tok3")
check(try_apply_post_resume(OWNER, HOST) == true, "the owner's GET must apply the replay")
check(applied.method == "POST" and applied.body == "title=hello" and applied.read == true,
  "the replay must read the body, then set POST and the stored body")
check(applied["Content-Type"] == "application/x-www-form-urlencoded", "the replay must restore the stored Content-Type")
check(applied.uri == "/wp-admin/post.php" and applied.args == "post=7", "the replay must restore the stored uri")
check(ngx.ctx.cfm_resumed_post == true, "the replay must mark ngx.ctx.cfm_resumed_post")
check(dict["pr|tok3"] == nil, "the owner's replay must spend the token")

-- Spent: a second GET with the same token replays nothing.
request("tok3")
check(try_apply_post_resume(OWNER, HOST) == false, "a spent token must not replay twice")

-- The case that broke: a fetcher's GET first, then the owner's.
store("tok4", OWNER, HOST)
request("tok4")
try_apply_post_resume("66.102.8.73", HOST)
request("tok4")
check(try_apply_post_resume(OWNER, HOST) == true, "the owner must still replay after a foreign GET")

-- An entry that does not decode can never apply: it is dropped.
dict["pr|bad"] = "garbage"
request("bad")
check(try_apply_post_resume(OWNER, HOST) == false, "an undecodable entry must not apply")
check(dict["pr|bad"] == nil, "an undecodable entry must be dropped")

-- An unknown token.
request("nope")
check(try_apply_post_resume(OWNER, HOST) == false, "an unknown token must not apply")

if fails > 0 then
  io.stderr:write(("cfm post-resume owner tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: a POST-resume token is consumed by its owner only")
