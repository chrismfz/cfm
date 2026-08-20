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

-- ── Circuit breaker (bridge hung/down) ───────────────────────────────────────
-- When the cfm daemon is HUNG (accepts the unix connection but never replies)
-- or down, every uncached request otherwise pays the full decision_timeout_ms
-- (~300ms) before self:fail() falls open — a hung daemon becomes a fleet-wide
-- latency cliff. A shdict-gated breaker trips after BREAKER_FAIL_THRESHOLD
-- daemon-unreachable failures in an unbroken CONSECUTIVE run (any success resets the count) and
-- then SKIPS the RPC for BREAKER_COOLDOWN_SEC, so requests fail fast per policy
-- instead of stacking timeouts. State lives in the shared cfm_decisions dict, so
-- it is node-wide across workers. The VERDICT is unchanged — a hung/down daemon
-- already fails open (or closed, under fail_open=0); the breaker only removes the
-- latency.
--
-- Hard-won specifics (each closes a review finding):
--   * ONLY the `decision` rpc kind drives the breaker. The best-effort telemetry
--     RPCs (observe / ip_push / ok_touch / waf_stats) share this client but must
--     NEVER trip it — a slow /nginx/ip autoblock push under a WAF flood must not
--     disable the healthy /nginx/decision enforcement path.
--   * ONLY `timeout`/`connect` classes count — an http_4xx/5xx or json error
--     means the daemon RESPONDED, not the unreachable condition we protect.
--   * The failure count is CONSECUTIVE — any success resets it — so on a busy
--     healthy node an occasional timeout among many successes never accumulates;
--     only an unbroken run of BREAKER_FAIL_THRESHOLD failures (a real outage)
--     trips. A fixed-window init_ttl (from the first failure) backstops a stalled partial count.
--   * NO single-flight probe lock and NO presence-based re-arm (both raced /
--     mis-fired: a lock deadlocked get()'s own token-rotation retry; a
--     presence-based re-arm let a lone stray timeout re-open on ONE blip). Once
--     the cooldown lapses, concurrent cache-miss requests probe freely; a
--     persistent hang simply re-accumulates a fresh 3-consecutive run (a few slow
--     probes per cooldown), still orders of magnitude better than the un-broken
--     cliff, while a recovered daemon's single stray timeout never re-trips.
local BREAKER_FAIL_THRESHOLD  = 3    -- consecutive unreachable decision failures to trip
local BREAKER_FAIL_WINDOW_SEC = 10   -- fixed-window TTL that decays a stalled partial count
local BREAKER_COOLDOWN_SEC    = 3    -- seconds to skip the RPC once open (then probe)
-- Key lifetime for BRK_UNTIL. The OPEN duration is the value comparison
-- (until_ts > now); the key just needs to cover the open window and then vanish
-- (there is no presence-based re-arm to keep alive), so a +1s guard suffices.
-- Keeping it tight means nothing lingers into the recovery period.
local BREAKER_OPEN_TTL_SEC    = BREAKER_COOLDOWN_SEC + 1
local BRK_UNTIL = "cfm_dec_brk_until"   -- open while ngx.now() < this value
local BRK_FAILS = "cfm_dec_brk_fails"   -- windowed failure counter
-- Observability: the breaker is otherwise silent (it just fails fast). Emit a
-- throttled ngx.log line to the edge error.log on the OPEN and CLOSED
-- transitions so an operator can SEE it engage — greppable via the MCP
-- `edge_error_tail` tool (grep "decision breaker"). Each line type has its own
-- INDEPENDENT BRK_LOG_THROTTLE_SEC window, so at most one OPEN and one CLOSED
-- per window regardless of a persistent hang (re-trips ~once per cooldown) OR a
-- flapping daemon — both are coalesced, not spammed. This is an EVENT-HISTORY
-- signal ("has the breaker been engaging, and roughly when"), not a real-time
-- state readout: under coalescing the newest line can lag the live state by up
-- to one window, and a recovery during a quiet gap (BRK_UNTIL already
-- TTL-expired, so no success hits the CLOSED branch) may emit no CLOSED at all.
-- The OPEN marker self-expires after the window, so nothing stays "stuck OPEN".
local BRK_LOG_OPEN   = "cfm_dec_brk_log_open"
local BRK_LOG_CLOSED = "cfm_dec_brk_log_closed"
local BRK_LOG_THROTTLE_SEC = 60

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
  elseif content_length and content_length > 0 then
    -- A daemon that sends 200 + Content-Length then HANGS mid-body times out
    -- here. Return a real timeout error (not resp=nil with code==200, which the
    -- caller would read as a success — masking the hang AND clearing the
    -- breaker); this is a partial-reply variant of the hung-daemon condition.
    local rb, rerr = s:receive(content_length)
    if not rb then s:close(); return nil, "recv body: " .. (rerr or "timeout") end
    resp = rb
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

-- breaker_should_skip: should this RPC be short-circuited? true only for a
-- `decision` RPC while the breaker is OPEN (BRK_UNTIL in the future). ONLY the
-- decision kind is gated — it is the per-cache-miss blocking path; the
-- lower-frequency best-effort telemetry RPCs (observe / ip_push / ok_touch /
-- waf_stats / waf_excludes) must never be silenced by a decision-only trip (the
-- daemon may still be able to serve a push). Once the cooldown lapses requests
-- probe freely — deliberately NO single-flight lock: a probe lock raced with
-- get()'s own token-rotation retry (the retry re-enters rpc() and would fail its
-- own held lock) and left zombie half-open states on http-error probes. Without
-- it, at a cooldown boundary the concurrent cache-miss requests probe (each pays
-- one decision_timeout_ms) and the first failure re-arms for another cooldown —
-- residual latency bounded to one cooldown's concurrent probes, still orders of
-- magnitude better than every request paying the timeout. No shdict → false.
--
-- Trade-off (inherent to any breaker): once tripped it stays open for the whole
-- cooldown even if the daemon recovers 50ms later — so a recovered daemon is not
-- consulted for up to BREAKER_COOLDOWN_SEC. Under the default fail_open=1 that is
-- a ≤3s window of allowing traffic a recovered daemon might have challenged (the
-- WAF still runs uncached, nft autoblock still applies); under fail_open=0 it is
-- ≤3s of fast-blocking after recovery — acceptable for a fail-CLOSED operator,
-- who already blocks during the hang. The cooldown is kept short for this reason.
function Client:breaker_should_skip(kind)
  if kind ~= "decision" then return false end
  local SH = self.sh
  if not SH then return false end
  local until_ts = SH:get(BRK_UNTIL)
  return type(until_ts) == "number" and until_ts > ngx.now()
end

-- breaker_note: fold ONE decision-RPC outcome into the breaker. Gated to the
-- `decision` kind up front: a telemetry outcome must neither trip the breaker
-- NOR clear it (a telemetry success while /nginx/decision itself is deadlocked
-- must not keep resetting the breaker and re-exposing the latency cliff). No
-- request-scoped state on self (the client may be a per-worker singleton, and
-- http() yields), so each decision reads shdict fresh.
function Client:breaker_note(kind, err_class)
  local SH = self.sh
  if not SH or kind ~= "decision" then return end
  if err_class == nil then
    -- A decision SUCCESS breaks the consecutive-failure streak → reset the count
    -- and clear any trip (this is also the half-open probe's success path).
    -- Gated on presence so a clean node (both unset — the common case) does
    -- reads but NO writes.
    if SH:get(BRK_FAILS) ~= nil then SH:delete(BRK_FAILS) end
    if SH:get(BRK_UNTIL) ~= nil then
      SH:delete(BRK_UNTIL)
      -- open → closed transition: the daemon answered again. Throttled log
      -- (independent 60s window; no cross-reset, so a flapping daemon can't spam).
      if SH:add(BRK_LOG_CLOSED, "1", BRK_LOG_THROTTLE_SEC) then
        ngx.log(ngx.WARN, "[cfm] decision breaker CLOSED — cfm daemon reachable again; decision RPCs resumed")
      end
    end
    return
  end
  -- A responded-with-error (http 4xx/5xx, json) is not the unreachable condition
  -- (and responds fast, so it has no latency cliff) — don't count it.
  if err_class ~= "timeout" and err_class ~= "connect" then return end
  -- CONSECUTIVE failure count: a success (above) resets it, so on a busy healthy
  -- node an occasional timeout among many successes never accumulates — only an
  -- unbroken run of BREAKER_FAIL_THRESHOLD failures (a real hang/outage) trips.
  -- No presence-based re-arm: re-tripping after a cooldown requires a FRESH
  -- 3-consecutive run (the counter is dropped on trip), so a single ISOLATED
  -- timeout during a quiet recovery can never re-open on one blip. On a
  -- persistent hang the post-cooldown probes simply re-accumulate to 3 (a few
  -- slow requests per cooldown — still bounded and far below the un-broken cliff).
  local n = SH:incr(BRK_FAILS, 1, 0, BREAKER_FAIL_WINDOW_SEC)
  if n and n >= BREAKER_FAIL_THRESHOLD then
    SH:set(BRK_UNTIL, ngx.now() + BREAKER_COOLDOWN_SEC, BREAKER_OPEN_TTL_SEC)
    SH:delete(BRK_FAILS)   -- reset so the next trip needs a fresh 3-consecutive run
    -- closed → open transition (or a re-trip on a persistent hang). Throttled log
    -- (independent 60s window) so a sustained outage or a flapping daemon can't
    -- spam; visible via MCP edge_error_tail.
    if SH:add(BRK_LOG_OPEN, "1", BRK_LOG_THROTTLE_SEC) then
      ngx.log(ngx.WARN, "[cfm] decision breaker OPEN — cfm daemon unreachable (",
        BREAKER_FAIL_THRESHOLD, " consecutive ", err_class,
        "); skipping the decision RPC for ", BREAKER_COOLDOWN_SEC,
        "s and failing ", (self.cfg and self.cfg.fail_open and "OPEN" or "CLOSED"),
        " per policy. The WAF still runs uncached; nft autoblock still applies")
    end
  end
end

function Client:rpc(kind, method, path, body, req_ctx)
  local cfg = self.cfg
  -- Circuit breaker: when the daemon is in a known hung/down window, skip the
  -- socket round-trip entirely and return a fast error so the caller fails per
  -- policy (fail-open) instead of paying decision_timeout_ms. Self-heals below.
  if self:breaker_should_skip(kind) then
    return nil, "breaker_open"
  end
  local t0 = ngx.now()
  local resp, err = self:http(method, path, body)
  local err_class = err and classify_bridge_err(err) or nil
  local elapsed_ms = math.floor((ngx.now() - t0) * 1000 + 0.5)
  if err then
    req_ctx = req_ctx or {}
    local ctx_ip = req_ctx.ip or (self.h.real_ip and self.h.real_ip())
    local ctx_host = req_ctx.host or (ngx.var.host or "-")
    local ctx_uri = req_ctx.uri or (ngx.var.request_uri or ngx.var.uri or "-")

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
  -- Fold this outcome into the breaker: a success clears it; a decision-kind
  -- timeout/connect failure counts toward tripping it.
  self:breaker_note(kind, err_class)
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
