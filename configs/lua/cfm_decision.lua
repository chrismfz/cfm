-- cfm_decision.lua — bridge decision-RPC client: unix-socket transport plus the
-- per-request /nginx/decision verdict with clean-allow caching.
--
-- WHY THIS MODULE EXISTS
--
-- Extracted VERBATIM from cfm.lua (edge-unification Phase 2, commit 1 of the
-- panel-decision PR) so cfm_panel.lua can make the SAME bridge decision on the
-- panel ports (commit 2) instead of the web path being the only caller. This is
-- a pure move: the web path constructs one client bound to its live CFG table
-- and calls it exactly where it previously called the inline locals, so web
-- behaviour is unchanged. See docs/edge-unification-plan.md §6 Phase 2.
--
-- CONSTRUCTION: cfm_decision.new(cfg, hooks)
--
--   cfg   — the caller's LIVE config table, held BY REFERENCE. Every field is
--           read live on each call (cfg.token, cfg.fail_open, the timeouts, …),
--           and cfg.token is MUTATED in place on a token rotation so the caller
--           sees the fresh token on its other bridge RPCs — exactly what the
--           inline code did when it wrote `CFG.token = fresh`.
--           Fields consumed: sock_path, token, token_header,
--           decision_timeout_ms, keepalive_idle_ms, keepalive_pool, fail_open,
--           decision_cache_ttl_ms, debug, debug_headers.
--
--   hooks — caller-local helpers the module must NOT reimplement (they carry
--           per-surface policy or state):
--             shdict        ngx shared dict for the clean-allow cache (or nil)
--             is_static     function(uri) -> bool   (static-asset cache coalesce)
--             real_ip       function() -> ip        (rpc error-log ctx fallback)
--             log_route     function(level, msg)    (rpc error log)
--             on_token_403  function() -> token|nil (throttled refresh on 401/403)
--             token_path    string   (for the token-missing log line)
--             token_err     function() -> err|nil   (for the token-missing log line)

local cjson = require "cjson.safe"

local lower = string.lower
local function esc(s) return ngx.escape_uri(s or "") end

local M = {}
local Client = {}
Client.__index = Client

function M.new(cfg, hooks)
  hooks = hooks or {}
  return setmetatable({ cfg = cfg, h = hooks, sh = hooks.shdict }, Client)
end

-- read_chunked drains a Transfer-Encoding: chunked body from the bridge socket.
local function read_chunked(sock)
  local out = {}
  while true do
    local line, err = sock:receive("*l")
    if not line then return nil, "chunked size line: " .. (err or "?") end
    local hex = line:match("^%s*([0-9a-fA-F]+)")
    if not hex then return nil, "bad chunk size line: " .. tostring(line) end
    local n = tonumber(hex, 16)
    if not n then return nil, "bad chunk size hex: " .. tostring(hex) end
    if n == 0 then
      while true do local tl = sock:receive("*l"); if not tl or tl == "" then break end end
      break
    end
    local data, derr = sock:receive(n)
    if not data then return nil, "chunk read: " .. (derr or "?") end
    table.insert(out, data); sock:receive(2)
  end
  return table.concat(out), nil
end

function Client:http(method, path, body)
  local cfg = self.cfg
  local s, err = ngx.socket.tcp()
  if not s then return nil, "socket.tcp: " .. (err or "unknown") end
  s:settimeouts(cfg.decision_timeout_ms, cfg.decision_timeout_ms, cfg.decision_timeout_ms)
  local ok, cerr = s:connect("unix:" .. cfg.sock_path)
  if not ok then s:close(); return nil, "connect: " .. (cerr or "unknown") end
  body = body or ""
  local req = method .. " " .. path .. " HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n"
  if cfg.token and cfg.token ~= "" then
    req = req .. cfg.token_header .. ": " .. cfg.token .. "\r\n"
  end
  if method == "POST" then
    req = req .. "Content-Type: application/json\r\nContent-Length: " .. tostring(#body) .. "\r\n"
  end
  req = req .. "\r\n" .. body
  local _, werr = s:send(req)
  if werr then s:close(); return nil, "send: " .. (werr or "unknown") end
  local status_line, rerr = s:receive("*l")
  if not status_line then s:close(); return nil, "recv status: " .. (rerr or "unknown") end
  local code = tonumber(status_line:match("%s(%d%d%d)%s"))
  if not code then s:close(); return nil, "bad status line: " .. status_line end
  local content_length, is_chunked
  while true do
    local line, _ = s:receive("*l")
    if not line or line == "" then break end
    local k, v = line:match("^([^:]+):%s*(.*)$")
    if k and v then
      local kl = k:lower()
      if kl == "content-length" then content_length = tonumber(v)
      elseif kl == "transfer-encoding" and v:lower():find("chunked", 1, true) then is_chunked = true end
    end
  end
  local resp = ""
  if method == "HEAD" or code == 204 or code == 304 then resp = ""
  -- Explicit empty body (Content-Length: 0). The bridge's ip/vhost push and
  -- clear handlers (/nginx/ip, /nginx/vhost) reply 200 with Content-Length: 0.
  -- (observe and ok-touch instead return a small JSON body, so they take the
  -- content_length > 0 branch — they were never "*a" victims.) This MUST be
  -- handled before the fall-through "*a" read below: on a keep-alive connection
  -- the server never closes, so "*a" would block until decision_timeout_ms
  -- (~300ms) on every such call — a per-push worker stall that amplifies under
  -- a WAF-tripping flood. The hot-path victim is the WAF autoblock push. [F04]
  elseif content_length == 0 then resp = ""
  elseif content_length and content_length > 0 then resp = s:receive(content_length)
  elseif is_chunked then
    local b, berr = read_chunked(s); if not b then s:close(); return nil, berr end; resp = b
  else resp = s:receive("*a") or "" end
  local ok_ka = s:setkeepalive(cfg.keepalive_idle_ms, cfg.keepalive_pool)
  if not ok_ka then s:close() end
  if code ~= 200 then return nil, "http " .. tostring(code) .. " body=" .. tostring(resp) end
  return resp, nil
end

local function classify_bridge_err(err)
  local msg = lower(tostring(err or ""))
  if msg == "" then return "unknown" end
  if msg:find("timeout", 1, true) then return "timeout" end
  if msg:find("connect:", 1, true) then return "connect" end
  local code = msg:match("http%s+(%d%d%d)")
  if code then return "http_" .. code end
  if msg:find("decode", 1, true) or msg:find("json", 1, true) then return "json" end
  return "unknown"
end

-- classify exposed so callers can key retry/log logic on the error class.
M.classify_bridge_err = classify_bridge_err

function Client:rpc(kind, method, path, body, req_ctx)
  local cfg = self.cfg
  local t0 = ngx.now()
  local resp, err = self:http(method, path, body)
  local elapsed_ms = math.floor((ngx.now() - t0) * 1000 + 0.5)
  if err then
    req_ctx = req_ctx or {}
    local ctx_ip = req_ctx.ip or (self.h.real_ip and self.h.real_ip())
    local ctx_host = req_ctx.host or (ngx.var.host or "-")
    local ctx_uri = req_ctx.uri or (ngx.var.request_uri or ngx.var.uri or "-")
    local err_class = classify_bridge_err(err)

    if cfg.debug or cfg.debug_headers then
      ngx.ctx.cfm_bridge_error = err_class
      ngx.ctx.cfm_bridge_latency_ms = elapsed_ms
      if cfg.debug_headers then
        ngx.header["X-CFM-Bridge-Error"] = err_class
        ngx.header["X-CFM-Bridge-Latency-Ms"] = tostring(elapsed_ms)
      end
    end

    if cfg.debug and self.h.log_route then
      self.h.log_route(ngx.WARN, "rpc_err kind=" .. tostring(kind or "-") ..
        " path=" .. tostring(path or "-") ..
        " class=" .. tostring(err_class) ..
        " elapsed_ms=" .. tostring(elapsed_ms) ..
        " ip=" .. tostring(ctx_ip or "-") ..
        " host=" .. tostring(ctx_host or "-") ..
        " uri=" .. tostring(ctx_uri or "-"))
    end
  end
  return resp, err
end

function Client:cache_key(ip, host, method, scheme, uri, qs, scope)
  if self.h.is_static and self.h.is_static(uri) then
    -- Static assets coalesce to ONE entry per (ip,host,scope) with path AND
    -- query dropped. Known limitation: a query-scoped traffic rule written for
    -- a static-extension path (e.g. "/x.css?token=…") can be served a cached
    -- clean-allow warmed by a benign hit to the same extension. Query-scoping a
    -- static-asset path is unusual; the static coalesce (hot-path win) is kept.
    return "ds|" .. ip .. "|" .. host .. "|" .. (scope or "web")
  end
  -- Fold the query into the key by hashing path and query INDEPENDENTLY. Each
  -- ngx.md5 is a fixed 32-hex field, so md5(uri)..md5(qs) is injective in
  -- (uri, qs). Do NOT concat "uri.."?"..qs" and hash once: '?' can legitimately
  -- appear in a DECODED path (from %3F), so "/x?y" with no query and "/x" with
  -- query "y" would hash the same string — letting an attacker warm a
  -- clean-allow under the harmless "/x?y" form and reuse it for the real
  -- "/x?y" that a query-scoped rule would challenge/block. A query-less request
  -- hashes exactly md5(uri) (== the old key), so no-query traffic keeps its
  -- previous cache entry.
  local h = ngx.md5(uri or "-")
  if qs and qs ~= "" then h = h .. ngx.md5(qs) end
  return "d|" .. ip .. "|" .. host .. "|" .. method .. "|" .. scheme .. "|" ..
         h .. "|" .. (scope or "web")
end

function Client:fail(errmsg)
  if self.cfg.fail_open then
    return { ip_action = "allow", vhost_action = "allow", err = errmsg }
  else
    return { ip_action = "block", vhost_action = "block", err = errmsg }
  end
end

-- [R1] Pass ua + country so Go evaluates traffic rules. Cache clean allows only.
-- `uri` is the DECODED path (ngx.var.uri); `qs` is the raw query (ngx.var.args,
-- may be ""). They are sent as separate RPC params so the bridge never has to
-- re-split a "path?query" concat (a decoded path can contain a literal '?').
function Client:get(ip, host, uri, qs, method, scheme, ua, country, scope)
  local cfg = self.cfg
  local SH = self.sh
  local key = self:cache_key(ip, host, method, scheme, uri, qs, scope)

  -- Accepted residual (2026-07 audit round-2): a cache HIT serves the prior
  -- clean-allow for up to decision_cache_ttl_ms (90s) WITHOUT re-consulting the
  -- bridge, so an IP the daemon block/challenge-flags DURING that window keeps
  -- being served on URLs it already warmed. Bounded and accepted, not closed:
  --   * only clean allows are cached (see the cache write below), so a
  --     currently-blocked IP hitting a NEW url misses and sees the block;
  --   * the WAF runs uncached on EVERY request — payloads are always caught;
  --   * nft autoblock is kernel-level — severe bans drop before the edge.
  -- The residual is thus "evade an edge behavioural challenge/block for <=90s on
  -- already-cached URLs", which is self-healing. Closing it would need a per-IP
  -- block-generation marker checked on every hit + Go-side publishing — a poor
  -- trade for a <=90s soft window, and this file deliberately does no snapshot
  -- polling (see header). Revisit only if edge-only challenge/block evasion
  -- becomes an observed problem.
  if SH then
    local cached = SH:get(key)
    if cached then
      local obj = cjson.decode(cached)
      if obj then obj._cache = true; return obj end
    end
  end

  -- Missing bridge token (daemon not yet ready): fail through the SAME policy as
  -- an unreachable daemon — self:fail() honours cfg.fail_open (allow by
  -- default) — instead of RPC'ing with no auth token (which the bridge would
  -- 401/403 anyway). Uniform behaviour regardless of token-file presence (F47).
  -- Loud but throttled to once/60s across workers so a prolonged outage can't
  -- flood the error log; the first occurrence still logs immediately.
  if not cfg.token or cfg.token == "" then
    if (not SH) or SH:add("cfm_token_missing_log", "1", 60) then
      ngx.log(ngx.ERR,
        "[cfm] bridge token unavailable — FAILING ",
        (cfg.fail_open and "OPEN (requests pass WITHOUT bridge IP/vhost/rule enforcement)"
                        or "CLOSED (requests blocked)"),
        "; ensure the cfm daemon has started. path: ",
        tostring(self.h.token_path or "/var/lib/cfm/lua/cfm_bridge_token.lua"),
        " details: ", tostring(self.h.token_err and self.h.token_err()))
    end
    return self:fail("bridge_token_missing")
  end

  local path = "/nginx/decision?ip=" .. esc(ip) ..
               "&host="    .. esc(host)    ..
               "&uri="     .. esc(uri)     ..
               "&qs="      .. esc(qs or "")      ..
               "&method="  .. esc(method)  ..
               "&scheme="  .. esc(scheme)  ..
               "&ua="      .. esc(ua or "")      ..
               "&country=" .. esc(country or "") ..
               "&scope="   .. esc(scope or "web")

  local body, err = self:rpc("decision", "GET", path, nil, {
    ip = ip, host = host, uri = uri, method = method,
  })
  if not body then
    -- A bridge 403 on a request that DID present a token usually means the daemon
    -- just rotated the token (weak-token replacement at startup) and our ~10s
    -- cached copy is stale. Force-refresh once (throttled per worker) and — only
    -- if the token actually CHANGED — retry with the fresh token before failing
    -- open. This closes the up-to-10s rotation fail-open window (audit F45). The
    -- "changed" guard means a persistent 403 from a genuinely wrong token (file
    -- unchanged) does NOT retry (it would 403 again) and does NOT loop; the
    -- throttle bounds the re-read cost under that misconfig. Updating cfg.token
    -- also switches this request's later bridge RPCs to the fresh secret.
    local klass = classify_bridge_err(err)
    if (klass == "http_403" or klass == "http_401") and cfg.token and cfg.token ~= "" then
      local fresh = self.h.on_token_403 and self.h.on_token_403()
      if fresh and fresh ~= "" and fresh ~= cfg.token then
        if self.h.log_route then
          self.h.log_route(ngx.WARN, "bridge token rotated (403 on stale token); refreshed + retrying ip=" ..
            tostring(ip or "-") .. " host=" .. tostring(host or "-"))
        end
        cfg.token = fresh
        body, err = self:rpc("decision", "GET", path, nil, {
          ip = ip, host = host, uri = uri, method = method,
        })
      end
    end
    if not body then
      return self:fail(err)
    end
  end
  local obj = cjson.decode(body)
  if not obj then
    if cfg.debug or cfg.debug_headers then
      ngx.ctx.cfm_bridge_error = "json"
    end
    if cfg.debug_headers then
      ngx.header["X-CFM-Bridge-Error"] = "json"
    end
    if cfg.debug and self.h.log_route then
      self.h.log_route(ngx.WARN, "rpc_err kind=decision class=json elapsed_ms=- ip=" .. tostring(ip or "-") ..
        " host=" .. tostring(host or "-") ..
        " uri=" .. tostring(uri or "-"))
    end
    return self:fail("decode_failed")
  end

  -- Only cache clean allows (no rule action = no challenge/block/throttle pending)
  if SH and obj.ip_action == "allow" and obj.vhost_action == "allow"
     and not obj.rule_action then
    SH:set(key, body, cfg.decision_cache_ttl_ms / 1000)
  end
  return obj
end

return M
