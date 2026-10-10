-- try_apply_post_resume on a POST whose original URI had no query string
-- (edge Lua sweep 2026-10-09). It cleared the carrier's `?cfm_rt=…` with
-- ngx.req.set_uri_args(nil), which raises ("string, number, or table
-- expected, got nil"): under fail_open the access phase ended there and the
-- replayed POST went on still carrying ?cfm_rt= (fleet: `/wp-admin/post.php`
-- saves on rigel and orion). Extracts the production function and runs it
-- against an ngx.req that, like the real one, refuses a nil.

local f = assert(io.open("configs/lua/cfm.lua", "r"))
local src = f:read("*a"); f:close()
local a = assert(src:find("local function try_apply_post_resume(", 1, true), "try_apply_post_resume() not found")
local body = src:sub(a)
local fnsrc = body:sub(1, assert(body:find("\nend\n")) + 4)

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local uri_args, uri, method, body_data
local store = {}
_G.SH = {
  get = function(_, k) return store[k] end,
  delete = function(_, k) store[k] = nil end,
}
_G.CFG = { post_resume_enable = true, post_resume_max_len = 65536 }
_G.lower = string.lower
_G.log_route = function() end
_G.cjson = { decode = function(s) return assert(load("return " .. s))() end }
_G.ngx = {
  INFO = 1, HTTP_POST = "POST",
  var = { arg_cfm_rt = "tok1" },
  ctx = {},
  decode_base64 = function(s) return s end,
  req = {
    get_method = function() return "GET" end,
    get_uri_args = function() return { cfm_rt = "tok1" } end,
    read_body = function() end,
    set_method = function(m) method = m end,
    set_header = function() end,
    set_body_data = function(b) body_data = b end,
    set_uri = function(u) uri = u end,
    set_uri_args = function(v)
      local t = type(v)
      if t ~= "string" and t ~= "number" and t ~= "table" then
        error("bad argument #1 to 'set_uri_args' (string, number, or table expected, got " .. t .. ")")
      end
      uri_args = v
    end,
  },
}

local try_apply = assert(load(fnsrc .. "\nreturn try_apply_post_resume"))()

-- The original POST had no query string.
store["pr|tok1"] = '{ ip = "203.0.113.4", host = "a.gr", uri = "/wp-admin/post.php", body_b64 = "action=editpost&post_ID=1" }'
local ok, res = pcall(try_apply, "203.0.113.4", "a.gr")
check(ok and res == true, "a resume to a query-less URI applies (" .. tostring(res) .. ")")
check(uri == "/wp-admin/post.php" and (uri_args == "" or (type(uri_args) == "table" and next(uri_args) == nil)),
      "the carrier's ?cfm_rt= is cleared (args " .. tostring(uri_args) .. ")")
check(method == "POST" and body_data == "action=editpost&post_ID=1", "the POST is replayed")
check(ngx.ctx.cfm_resumed_post == true, "the request is marked a resumed POST")

-- With a query string: the original's args replace the carrier's.
uri_args, ngx.ctx = nil, {}
store["pr|tok1"] = '{ ip = "203.0.113.4", host = "a.gr", uri = "/index.php?route=x", body_b64 = "a=1" }'
ok, res = pcall(try_apply, "203.0.113.4", "a.gr")
check(ok and res == true and uri == "/index.php" and uri_args == "route=x", "a resume with a query keeps it")

if fails > 0 then
  io.stderr:write(("post-resume uri args tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: post-resume clears the carrier's query without set_uri_args(nil)")
