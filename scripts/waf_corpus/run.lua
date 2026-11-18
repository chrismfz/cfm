-- scripts/waf_corpus/run.lua — run a labelled raw-HTTP corpus through the
-- real in-path WAF (configs/lua/cfm_waf.lua) and report detection and false
-- positives, per sample and per rule. LuaJIT, no nginx, no network.
--
--   luajit scripts/waf_corpus/run.lua [options] <corpus-dir>
--
-- A sample is one file holding one raw HTTP/1.x request (request line,
-- header lines, blank line, body). Its label is its extension: `.black` is an
-- attack, `.white` is benign (BlazeHTTP's layout); any other file is skipped.
-- scripts/waf_corpus/blazehttp.sh fetches BlazeHTTP and runs this on it.
--
-- What it measures: the ENGINE, cfm_waf.check(), given what the edge would
-- hand it. cfm.lua is not run, so these are NOT modelled: the bypass lists,
-- per-vhost exclusions, clearance, the body read gate (allowlist, size cap,
-- burn-in pass: every POST/PUT/PATCH body is given to the WAF here, cut at
-- waf_body_max_len like the edge does), traffic rules, IP / vhost decisions.
-- Rule modes are the shipped defaults plus configs/lua/cfm_waf_config.lua
-- overrides, as on a node with no local overrides.
--
-- What it emulates from nginx: ngx.var.uri (percent-decoded, slashes merged,
-- dot segments resolved; a bad %-escape or a path above the root is a 400, so
-- the request never reaches the WAF: reported as `nginx_400`), lowercased
-- header names with repeated headers as a list, and header names nginx drops
-- by default (ignore_invalid_headers on, underscores_in_headers off).
--
-- Options:
--   --out FILE        per-sample TSV: path label outcome action headline_rule rule_ids
--   --baseline FILE   a previous --out file: list the samples whose outcome changed
--   --keep-host       keep each sample's Host header. By default it is set to
--                     waf-corpus.example: BlazeHTTP's attacks mostly name an IP
--                     literal (10.10.3.128) and its benign samples a hostname,
--                     so the IP-host rule (602) would "detect" the corpus layout.
--   --max-body N      body cap (default: CFM_WAF_BODY_MAX_LEN or 32768, as cfm_cfg)
--   --limit N         stop after N samples (smoke runs)
--   --top N           rows in the per-rule and missed-sample tables (default 25)

package.path = "configs/lua/?.lua;" .. package.path

local bit = require("bit")

-- ── ngx stand-in ───────────────────────────────────────────────────────────
-- The WAF modules read ngx.now, ngx.log and ngx.decode_base64 (returns nil on
-- invalid input, like lua-nginx-module), and nothing else on this path.
local B64 = {}
do
  local alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  for i = 1, 64 do B64[alpha:byte(i)] = i - 1 end
end
-- As nginx's ngx_decode_base64: read up to the first '=', refuse any other
-- non-alphabet byte or a length of 1 mod 4, decode what was read. Unpadded
-- input decodes; bytes after the first '=' are ignored.
local function decode_base64(s)
  if type(s) ~= "string" then return nil end
  local len = #s
  local eq = s:find("=", 1, true)
  if eq then len = eq - 1 end
  for i = 1, len do
    if B64[s:byte(i)] == nil then return nil end
  end
  if len % 4 == 1 then return nil end
  local out = {}
  local i = 1
  while i <= len do
    local a, b = B64[s:byte(i)], B64[s:byte(i + 1)]
    local c, d = B64[s:byte(i + 2) or -1], B64[s:byte(i + 3) or -1]
    if i + 1 > len then break end
    out[#out + 1] = string.char(bit.band(bit.bor(bit.lshift(a, 2), bit.rshift(b, 4)), 255))
    if i + 2 <= len then
      out[#out + 1] = string.char(bit.band(bit.bor(bit.lshift(b, 4), bit.rshift(c, 2)), 255))
    end
    if i + 3 <= len then
      out[#out + 1] = string.char(bit.band(bit.bor(bit.lshift(c, 6), d), 255))
    end
    i = i + 4
  end
  return table.concat(out)
end

local LOGS = 0
_G.ngx = _G.ngx or {
  now = function() return 1000 end,
  time = function() return 1000 end,
  decode_base64 = decode_base64,
  log = function() LOGS = LOGS + 1 end,
  ERR = 0, WARN = 1, INFO = 2, DEBUG = 3,
}

local M = { decode_base64 = decode_base64 }

-- ── nginx request emulation ────────────────────────────────────────────────

local function hexval(c)
  if c >= 48 and c <= 57 then return c - 48 end
  if c >= 65 and c <= 70 then return c - 55 end
  if c >= 97 and c <= 102 then return c - 87 end
  return nil
end

-- ngx.var.uri for a raw request path: nil when nginx answers 400.
function M.nginx_uri(raw)
  local out, i, n = {}, 1, #raw
  while i <= n do
    local c = raw:byte(i)
    if c == 37 then -- %
      local h1, h2 = hexval(raw:byte(i + 1) or 0), hexval(raw:byte(i + 2) or 0)
      if not (h1 and h2) then return nil end
      out[#out + 1] = string.char(h1 * 16 + h2)
      i = i + 3
    else
      out[#out + 1] = string.char(c)
      i = i + 1
    end
  end
  local path = table.concat(out)
  if path:sub(1, 1) ~= "/" then return nil end
  local segs = {}
  for seg in path:gmatch("[^/]+") do
    if seg == ".." then
      if #segs == 0 then return nil end
      segs[#segs] = nil
    elseif seg ~= "." then
      segs[#segs + 1] = seg
    end
  end
  local trailing = path:sub(-1) == "/" or path:match("/%.%.?$") ~= nil
  local res = "/" .. table.concat(segs, "/")
  if trailing and res ~= "/" then res = res .. "/" end
  return res
end

-- A header name nginx keeps with its defaults (ignore_invalid_headers on,
-- underscores_in_headers off): letters, digits and '-'.
local function valid_header_name(name)
  return name ~= "" and not name:find("[^%w%-]")
end

-- Parse one raw request. Returns a table or nil, err.
function M.parse(raw)
  local head_end, body_start = raw:find("\r\n\r\n", 1, true)
  local sep = "\r\n"
  if not head_end then
    head_end, body_start = raw:find("\n\n", 1, true)
    sep = "\n"
  end
  local head, body
  if head_end then
    head, body = raw:sub(1, head_end - 1), raw:sub(body_start + 1)
  else
    head, body = raw, ""
  end
  local lines = {}
  for line in (head .. sep):gmatch("(.-)" .. sep) do lines[#lines + 1] = line end
  local method, target, proto = (lines[1] or ""):match("^(%S+) (.+) (HTTP/%d%.%d)$")
  if not method then return nil, "bad request line" end
  local headers, order = {}, {}
  for i = 2, #lines do
    local name, value = lines[i]:match("^([^:]+):%s*(.-)%s*$")
    if name then
      local k = name:lower()
      if valid_header_name(name) then
        local cur = headers[k]
        if cur == nil then
          headers[k] = value
          order[#order + 1] = k
        elseif type(cur) == "table" then
          cur[#cur + 1] = value
        else
          headers[k] = { cur, value }
        end
      end
    end
  end
  -- absolute-form request target: drop scheme and authority
  local t = target:gsub("^[hH][tT][tT][pP][sS]?://[^/?]*", "")
  if t == "" then t = "/" end
  local raw_path, args = t:match("^([^?]*)%??(.*)$")
  return { method = method, raw_uri = t, raw_path = raw_path, args = args or "",
           proto = proto, headers = headers, body = body }
end

-- In-memory stand-in for an ngx.shared dict (one per sample: the burst rules
-- count per IP, and every corpus sample is a different client).
local function newdict()
  local d = { store = {} }
  function d:get(k) return self.store[k] end
  function d:set(k, v) self.store[k] = v; return true end
  function d:add(k, v) if self.store[k] ~= nil then return false, "exists" end self.store[k] = v; return true end
  function d:delete(k) self.store[k] = nil end
  function d:incr(k, n)
    if self.store[k] == nil then return nil, "not found" end
    self.store[k] = self.store[k] + (n or 1)
    return self.store[k]
  end
  return d
end

local ENFORCE = { block = true, challenge = true, challenge_v2 = true }

-- Evaluate one parsed request. Returns a result table:
--   outcome  nginx_400 | error | clean | logonly | challenge | challenge_v2 | block
--   action, headline (rule id), ids (sorted distinct rule ids of every hit), err
function M.evaluate(waf, req, opts, seq)
  local uri = M.nginx_uri(req.raw_path)
  if not uri then return { outcome = "nginx_400", ids = {} } end
  local headers = req.headers
  if not opts.keep_host then headers.host = "waf-corpus.example" end
  local body = ""
  local m = req.method:lower()
  if m == "post" or m == "put" or m == "patch" then
    body = req.body or ""
    if #body > opts.max_body then body = body:sub(1, opts.max_body) end
    -- BlazeHTTP rewrites Content-Length to the body it sends; so does this.
    if #(req.body or "") > 0 then headers["content-length"] = tostring(#req.body) end
  end
  local ip = ("198.18.%d.%d"):format(math.floor(seq / 250) % 250, seq % 250 + 1)
  local ctx = {
    uri = uri, args = req.args, method = req.method, raw_uri = req.raw_uri,
    host = "waf-corpus.example", ip = ip, peer = ip,
    cookie = type(headers.cookie) == "table" and table.concat(headers.cookie, "; ") or (headers.cookie or ""),
    shdict = newdict(), headers = headers, body = body, self_origin = false,
  }
  local ok, hit, _, _, action, hits, rule_id = pcall(waf.check, ctx)
  if not ok then return { outcome = "error", err = tostring(hit), ids = {} } end
  -- Does the verdict need the body? Asked again without it. On the edge a
  -- POST body reaches the WAF when its Content-Type is inspectable (none,
  -- urlencoded, json, multipart, xml, text/*) or the path is on cfm.lua's
  -- dynamic-endpoint list; body_ct_ok records the first (the real util
  -- function), the list is not copied here.
  local body_dep, body_ct_ok
  if hit and body ~= "" then
    ctx.body, ctx.shdict, ctx.headers = "", newdict(), headers
    local ok2, hit2, _, _, action2 = pcall(waf.check, ctx)
    if ok2 and (not hit2 or action2 ~= action) then
      body_dep = true
      local ct = headers["content-type"]
      if type(ct) == "table" then ct = ct[1] end
      body_ct_ok = require("cfm_waf_util").ct_is_inspectable(ct)
    end
  end
  local ids, seen = {}, {}
  if type(hits) == "table" then
    for _, h in ipairs(hits) do
      local id = tonumber(h and h.waf_rule_id)
      if id and not seen[id] then seen[id] = true; ids[#ids + 1] = id end
    end
  end
  if rule_id and not seen[rule_id] then ids[#ids + 1] = rule_id end
  table.sort(ids)
  if not hit then return { outcome = "clean", ids = ids } end
  return { outcome = action or "logonly", action = action, headline = rule_id, ids = ids,
           body_dep = body_dep, body_ct_ok = body_ct_ok }
end

-- ── corpus walk + report ───────────────────────────────────────────────────

local function list_files(dir)
  local p = assert(io.popen("find '" .. dir:gsub("'", "'\\''") .. "' -type f \\( -name '*.black' -o -name '*.white' \\) | LC_ALL=C sort"))
  local files = {}
  for f in p:lines() do files[#files + 1] = f end
  p:close()
  return files
end

local function read_file(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local s = f:read("*a")
  f:close()
  return s
end

-- "" = verdict without the body too; "ct" = needs the body, any path reads it;
-- "list" = needs the body, read only on cfm.lua's dynamic-endpoint list.
local function body_tag(r)
  if not r.body_dep then return "" end
  return r.body_ct_ok and "ct" or "list"
end

local function pct(a, b) if b == 0 then return "  -  " end return ("%5.2f%%"):format(100 * a / b) end

local function main(argv)
  local opts = { max_body = tonumber(os.getenv("CFM_WAF_BODY_MAX_LEN") or "") or 32768, top = 25 }
  local dir
  local i = 1
  while i <= #argv do
    local a = argv[i]
    if a == "--out" then opts.out = argv[i + 1]; i = i + 1
    elseif a == "--baseline" then opts.baseline = argv[i + 1]; i = i + 1
    elseif a == "--keep-host" then opts.keep_host = true
    elseif a == "--max-body" then opts.max_body = tonumber(argv[i + 1]); i = i + 1
    elseif a == "--limit" then opts.limit = tonumber(argv[i + 1]); i = i + 1
    elseif a == "--top" then opts.top = tonumber(argv[i + 1]); i = i + 1
    elseif a:sub(1, 2) == "--" then io.stderr:write("unknown option " .. a .. "\n"); os.exit(2)
    else dir = a end
    i = i + 1
  end
  if not dir then
    io.stderr:write("usage: luajit scripts/waf_corpus/run.lua [options] <corpus-dir>\n")
    os.exit(2)
  end
  dir = dir:gsub("/+$", "")

  local waf = require("cfm_waf")
  local names, modes = {}, {}
  local cfg = waf.get_config()
  for k, id in pairs(waf.get_rule_ids()) do names[id] = k; modes[id] = cfg[k] end

  local files = list_files(dir)
  if #files == 0 then io.stderr:write("no .black/.white samples under " .. dir .. "\n"); os.exit(2) end
  local out = opts.out and assert(io.open(opts.out, "w"))
  if out then out:write("path\tlabel\toutcome\taction\theadline_rule\trule_ids\tbody\n") end

  local tot = { black = {}, white = {} }
  local per_rule = {}   -- id -> { black = n, white = n, head_black = n, head_white = n }
  local missed = {}     -- black samples with no enforcing action
  local fps = {}        -- white samples with an enforcing action
  local errors, parse_errors = {}, 0
  local current = {}
  local t0 = os.clock()
  for n, path in ipairs(files) do
    if opts.limit and n > opts.limit then break end
    local label = path:match("%.(%a+)$")
    local raw = read_file(path) or ""
    local req, perr = M.parse(raw)
    local r
    if not req then
      parse_errors = parse_errors + 1
      r = { outcome = "parse_error", ids = {}, err = perr }
    else
      r = M.evaluate(waf, req, opts, n)
    end
    local t = tot[label]
    t.n = (t.n or 0) + 1
    t[r.outcome] = (t[r.outcome] or 0) + 1
    for _, id in ipairs(r.ids) do
      local pr = per_rule[id] or { black = 0, white = 0, head_black = 0, head_white = 0 }
      per_rule[id] = pr
      pr[label] = pr[label] + 1
      if id == r.headline then pr["head_" .. label] = pr["head_" .. label] + 1 end
    end
    if r.outcome == "error" then errors[#errors + 1] = path .. "  " .. (r.err or ""):gsub("\n.*", "") end
    local rel = path:sub(#dir + 2)
    if label == "black" and not ENFORCE[r.outcome] and r.outcome ~= "nginx_400" then missed[#missed + 1] = rel end
    if label == "white" and ENFORCE[r.outcome] then
      local tag = body_tag(r)
      fps[#fps + 1] = rel .. "  rule " .. tostring(r.headline) .. " " .. tostring(names[r.headline] or "")
                      .. (tag ~= "" and ("  (body, " .. tag .. ")") or "")
      if tag ~= "" then t["fp_body_" .. tag] = (t["fp_body_" .. tag] or 0) + 1 end
    end
    local ids = table.concat(r.ids, ",")
    current[rel] = r.outcome .. "\t" .. ids
    if out then
      out:write(rel, "\t", label, "\t", r.outcome, "\t", tostring(r.action or ""), "\t",
                tostring(r.headline or ""), "\t", ids, "\t", body_tag(r), "\n")
    end
  end
  if out then out:close() end
  local secs = os.clock() - t0

  local function line(fmt, ...) io.write(fmt:format(...), "\n") end
  local function enf(t) return (t.block or 0) + (t.challenge or 0) + (t.challenge_v2 or 0) end
  local function any(t) return enf(t) + (t.logonly or 0) end
  local b, w = tot.black, tot.white
  b.n, w.n = b.n or 0, w.n or 0
  line("CFM WAF corpus run: %s", dir)
  line("samples: %d attack (.black), %d benign (.white); %.1f s CPU", b.n, w.n, secs)
  line("")
  line("%-22s %16s %16s", "", "attack (detect)", "benign (FP)")
  line("%-22s %7d %8s %7d %8s", "block", b.block or 0, pct(b.block or 0, b.n), w.block or 0, pct(w.block or 0, w.n))
  line("%-22s %7d %8s %7d %8s", "block+challenge(_v2)", enf(b), pct(enf(b), b.n), enf(w), pct(enf(w), w.n))
  line("%-22s %7d %8s %7d %8s", "any (incl. logonly)", any(b), pct(any(b), b.n), any(w), pct(any(w), w.n))
  line("%-22s %7d %8s %7d %8s", "nginx 400 (no WAF)", b.nginx_400 or 0, pct(b.nginx_400 or 0, b.n), w.nginx_400 or 0, pct(w.nginx_400 or 0, w.n))
  line("%-22s %7d %8s %7d %8s", "WAF raised", b.error or 0, "", w.error or 0, "")
  if parse_errors > 0 then line("%-22s %7d", "unparseable samples", parse_errors) end
  if (w.fp_body_ct or 0) + (w.fp_body_list or 0) > 0 then
    line("benign enforcing hits that need the body: %d read on any path (Content-Type), %d only on cfm.lua's dynamic-endpoint list",
         w.fp_body_ct or 0, w.fp_body_list or 0)
  end
  line("")

  local ids = {}
  for id in pairs(per_rule) do ids[#ids + 1] = id end
  table.sort(ids, function(x, y)
    local px, py = per_rule[x], per_rule[y]
    if px.white ~= py.white then return px.white > py.white end
    if px.black ~= py.black then return px.black > py.black end
    return x < y
  end)
  line("per rule (every hit, not only the headline; sorted by benign hits):")
  line("  %-6s %-34s %-13s %8s %8s", "id", "rule", "mode", "attack", "benign")
  for k, id in ipairs(ids) do
    if k > opts.top then line("  … %d more rules", #ids - opts.top) break end
    local pr = per_rule[id]
    line("  %-6s %-34s %-13s %8d %8d", tostring(id), (names[id] or "?"):sub(1, 34), tostring(modes[id] or "?"), pr.black, pr.white)
  end
  line("")
  if #fps > 0 then
    line("benign samples with an enforcing action (%d, first %d):", #fps, math.min(#fps, opts.top))
    for k = 1, math.min(#fps, opts.top) do line("  %s", fps[k]) end
    line("")
  end
  if #missed > 0 then
    line("attack samples not enforced (%d, first %d):", #missed, math.min(#missed, opts.top))
    for k = 1, math.min(#missed, opts.top) do line("  %s", missed[k]) end
    line("")
  end
  if #errors > 0 then
    line("WAF raised on (%d, first %d):", #errors, math.min(#errors, opts.top))
    for k = 1, math.min(#errors, opts.top) do line("  %s", errors[k]) end
    line("")
  end

  if opts.baseline then
    local f = assert(io.open(opts.baseline, "r"))
    local changed, rows, matched = {}, 0, 0
    local first = true
    for l in f:lines() do
      if first then first = false else
        local col = {}
        for c in (l .. "\t"):gmatch("([^\t]*)\t") do col[#col + 1] = c end
        local path, outcome, rids = col[1], col[3], col[6]
        if path and outcome and rids then
          rows = rows + 1
          local now = current[path]
          if now then
            matched = matched + 1
            if now ~= (outcome .. "\t" .. rids) then
              local o2, r2 = now:match("^([^\t]*)\t(.*)$")
              changed[#changed + 1] = ("  %s  %s [%s] -> %s [%s]"):format(path, outcome, rids, o2, r2)
            end
          end
        end
      end
    end
    f:close()
    if rows == 0 then
      io.stderr:write("baseline " .. opts.baseline .. " has no readable rows\n")
      os.exit(2)
    end
    line("changed vs baseline %s: %d (%d of its %d samples in this run)", opts.baseline, #changed, matched, rows)
    for k = 1, math.min(#changed, opts.top * 4) do line("%s", changed[k]) end
    line("")
  end
end

-- Run as a script, or return the helpers when loaded by a test.
if arg and arg[0] and arg[0]:match("run%.lua$") then
  main(arg)
else
  return M
end
