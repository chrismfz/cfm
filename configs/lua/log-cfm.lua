-- /var/lib/cfm/lua/log-cfm.lua (CFM-managed canonical location)
--
-- CFM webdetector log ingestion via Unix socket.
--
-- Intended for use inside log_by_lua_block. ngx.socket.tcp() is DISABLED in
-- the log phase, so the build-the-line part runs inline (where ngx.var.* is
-- available) and the actual socket send is deferred into ngx.timer.at(...)
-- which executes in a light-thread context where cosockets are allowed.
--
-- Batching (per worker): rather than one timer + one socket send PER request
-- (1000 rps ⇒ 1000 timers/s/worker, which flirts with `too many pending
-- timers`), each request appends its TSV line to a per-worker buffer and a
-- SINGLE timer drains the whole buffer — after at most FLUSH_INTERVAL, or
-- immediately once FLUSH_LINES have accumulated. The receiver already reads
-- newline-delimited records in a loop (ingest_socket.go serveConn →
-- handleLine per '\n'), so N lines concatenated into one send parse
-- identically, one record at a time. Net: ~FLUSH_LINES× fewer timers and
-- socket sends, and FEWER concurrent connections (kinder to the ingest
-- connection cap), at the cost of ≤FLUSH_INTERVAL of extra log latency —
-- negligible for the detector's seconds-to-minutes behavioural windows.
--
-- Accepted best-effort tradeoffs of batching (these logs may always be lost;
-- the request is never affected): a single failed send now drops its whole
-- batch instead of one line — bounded by FLUSH_LINES/FLUSH_BYTES, which cap a
-- normal batch — and a mid-send timeout can truncate the final record, which
-- the receiver's parseTSV already rejects as a malformed line. Memory is
-- bounded by BOTH a line and a byte cap (request_uri/UA are attacker-
-- influenced). Record order across a batch boundary is not guaranteed (each
-- record carries its own ts; the old per-request path was in fact MORE
-- concurrent). On worker shutdown the ≤FLUSH_INTERVAL tail is dropped (cosockets
-- are disabled in a premature timer), same best-effort class as before.
--
-- Emits one TSV record per request to /run/cfm/ingest.sock, matching the
-- exact column order and delimiters produced by the cfm_tsv access_log
-- format. The receiver (CFM socket listener) reuses the existing TSV
-- parser, so the contract MUST stay in sync with
-- internal/webdetector/engine.go::parseTSV.
--
-- Field order (TAB-separated, newline-terminated, 12 columns):
--
--   idx  field   ngx source               type / notes
--   ---  ------  -----------------------  ----------------------------------
--    0   ts      ngx.var.msec             seconds, fractional
--    1   ip      ngx.var.remote_addr      string
--    2   host    ngx.var.host             string (lowercased downstream)
--    3   method  ngx.var.request_method   string
--    4   uri     ngx.var.request_uri      full URI with query string
--    5   proto   ngx.var.server_protocol  "HTTP/1.1" etc.
--    6   status  ngx.var.status           int
--    7   bytes   ngx.var.body_bytes_sent  int64
--    8   rt      ngx.var.request_time     seconds (float)
--    9   urt     ngx.var.upstream_response_time  seconds or "-" (normalized to 0 downstream)
--   10   ref     ngx.var.http_referer     string (tabs/newlines stripped)
--   11   ua      ngx.var.http_user_agent  string (tabs/newlines stripped)
--
-- Connection reuse: setkeepalive(10000, 100) gives us up to 100 pooled
-- cosockets per worker, idle timeout 10s. First timer per worker pays
-- the connect cost (≤50ms), subsequent ones reuse the pool.
--
-- Failure policy: if the socket is missing or the send fails (CFM not
-- running, socket being rotated, etc.) we drop the line silently. The
-- request must NEVER be affected.

local _M = {}
local shd = require "cfm_shdict" -- counters: never dict:incr(key, n, init) (see cfm_shdict.lua)

local SOCK_PATH    = "/run/cfm/ingest.sock"
local CONNECT_MS   = 50
local SEND_MS      = 50
local KEEPALIVE_MS = 10000
local POOL_SIZE    = 100

-- Batching knobs (per worker). FLUSH_INTERVAL caps how stale a buffered line
-- may get; FLUSH_LINES/FLUSH_BYTES force an early drain so a burst doesn't wait
-- the full interval or grow the batch without bound (which also bounds how much
-- a single failed send can lose); MAX_LINES/MAX_BYTES are the hard memory caps —
-- if timers cannot be scheduled at all (extreme load), the buffer is dropped
-- rather than grown unbounded (these are best-effort logs; today's code drops
-- individual lines under the same `too many pending timers` condition). Byte
-- caps sit alongside the line caps because request_uri / user-agent are
-- attacker-influenced and a few huge lines can blow a line-only budget.
local FLUSH_INTERVAL = 0.1               -- seconds; max added latency per line
local FLUSH_LINES    = 64                -- drain early at this many buffered lines
local FLUSH_BYTES    = 256 * 1024        -- …or this many buffered bytes
local MAX_LINES      = 4096              -- hard cap: drop the batch past this
local MAX_BYTES      = 8 * 1024 * 1024   -- …or past this many bytes

local RETRY_MIN_SECS = 0.1
local RETRY_MAX_SECS = 5

local function retry_key(suffix)
  return "cfm_log_sock:" .. suffix
end

local function should_skip_connect()
  local dict = ngx.shared.cfm_metrics
  if not dict then return false end
  local until_ts = dict:get(retry_key("retry_after"))
  return type(until_ts) == "number" and until_ts > ngx.now()
end

local function record_connect_failure(err)
  local dict = ngx.shared.cfm_metrics
  if not dict then return end
  local fails = shd.incr(dict, retry_key("fail_count"), 1) or 1
  local backoff = RETRY_MIN_SECS * (2 ^ math.min(fails-1, 6))
  if backoff > RETRY_MAX_SECS then backoff = RETRY_MAX_SECS end
  dict:set(retry_key("retry_after"), ngx.now() + backoff, backoff + 1)
  if err and fails <= 3 then
    ngx.log(ngx.WARN, "cfm log socket connect failed; backoff=", backoff, "s err=", err)
  end
end

local function record_connect_success()
  local dict = ngx.shared.cfm_metrics
  if not dict then return end
  dict:set(retry_key("fail_count"), 0, 60)
  dict:delete(retry_key("retry_after"))
end

-- Sanitize a field so it cannot break the TSV contract: strip \t, \r, \n.
local function clean(s)
  if s == nil then return "" end
  if type(s) ~= "string" then s = tostring(s) end
  s = s:gsub("[\t\r\n]", " ")
  return s
end

local function nz(s)
  if s == nil or s == "" then return "-" end
  return s
end

-- Send one payload (one or many newline-terminated records) over the ingest
-- socket. The receiver splits on '\n', so a concatenated batch is parsed as
-- individual records. Reuses the pooled cosocket (setkeepalive) so only the
-- first send per worker pays the connect cost.
local function send_payload(payload)
  -- During connect backoff (ingest socket down) the caller has already swapped
  -- the buffer out, so returning here intentionally DROPS this batch — the same
  -- loss rate as the pre-batching per-line drop, just in ≤FLUSH_INTERVAL chunks.
  if should_skip_connect() then
    return
  end

  local sock = ngx.socket.tcp()
  sock:settimeouts(CONNECT_MS, SEND_MS, SEND_MS)

  local ok, err = sock:connect("unix:" .. SOCK_PATH)
  if not ok then
    record_connect_failure(err)
    return
  end
  record_connect_success()

  local _, serr = sock:send(payload)
  if serr then
    sock:close()
    return
  end

  local kok, kerr = sock:setkeepalive(KEEPALIVE_MS, POOL_SIZE)
  if not kok then
    sock:close()
    if kerr and kerr ~= "closed" then
      ngx.log(ngx.WARN, "cfm log socket keepalive failed: ", kerr)
    end
  end
end

-- ── Per-worker line buffer ───────────────────────────────────────────────────
-- These upvalues persist across requests within one worker (the module is
-- require()'d once per worker VM). nginx Lua is cooperatively single-threaded,
-- so the append in _M.log() and the swap in flush() never interleave mid-
-- statement; the only yields are inside send_payload's socket ops, which run
-- AFTER the buffer has been swapped out — so a line is never sent twice or
-- lost to a concurrent append.
local buf       = {}       -- array of "…\n" TSV records
local buf_n     = 0        -- #buf, tracked to avoid table.getn on the hot path
local buf_bytes = 0        -- running byte size of buf, for the byte-based caps
local timer_set = false    -- an interval flush timer is pending
local eager_set = false    -- a 0-delay (FLUSH_LINES/FLUSH_BYTES) flush timer pending

-- flush drains the whole buffer in one send. `kind` names which timer fired
-- ("interval"/"eager"); we clear ONLY that flag so a still-pending timer of the
-- other kind is not re-armed — this caps concurrently-pending flush timers at
-- ≤2 per worker (the whole point of batching is to relieve `too many pending
-- timers`, so we must not let interval timers accumulate). Ordering note: both
-- kinds can fire and their sends run concurrently across the socket yield, so
-- record order ACROSS a batch boundary is not guaranteed — same as (in fact
-- less concurrent than) the old one-timer-per-request path, and harmless since
-- every record carries its own `ts` and the detector scores over long windows.
local function flush(premature, kind)
  if kind == "eager" then eager_set = false else timer_set = false end
  -- Drop the tail on worker shutdown, matching the pre-batching behaviour.
  -- Cosockets are disabled in a premature timer, so a send would fail anyway —
  -- and worse, record_connect_failure() would bump the SHARED backoff dict from
  -- a dying worker and make the surviving workers back off. So never touch the
  -- socket here; the ≤FLUSH_INTERVAL tail is best-effort and acceptably lost.
  if premature then return end
  if buf_n == 0 then return end

  -- Snapshot synchronously (no yield) so concurrent appends land in a fresh
  -- buffer and are drained by the next timer, not double-sent or lost.
  local batch = buf
  buf       = {}
  buf_n     = 0
  buf_bytes = 0

  send_payload(table.concat(batch))
end

-- Arm a flush timer of the given kind. Returns whether it was armed.
local function arm(delay, kind)
  local ok, terr = ngx.timer.at(delay, flush, kind)
  if ok then return true end
  -- Pending-timer exhaustion is expected under extreme load and must not spam
  -- the error log; anything else is unusual.
  if terr ~= "too many pending timers" then
    ngx.log(ngx.WARN, "cfm log timer.at failed: ", terr)
  end
  return false
end

function _M.log()
  local var = ngx.var
  local line = table.concat({
    nz(var.msec),
    nz(var.remote_addr),
    nz(var.host),
    nz(var.request_method),
    clean(var.request_uri),
    nz(var.server_protocol),
    nz(var.status),
    nz(var.body_bytes_sent),
    nz(var.request_time),
    nz(var.upstream_response_time),
    clean(var.http_referer),
    clean(var.http_user_agent),
  }, "\t") .. "\n"

  buf_n     = buf_n + 1
  buf_bytes = buf_bytes + #line
  buf[buf_n] = line

  if buf_n >= MAX_LINES or buf_bytes >= MAX_BYTES then
    -- Timers can't drain (extreme load) and the buffer is unbounded — drop it
    -- to protect worker memory. Best-effort logs; same class of loss as the
    -- pre-batching "too many pending timers" per-line drop, just batched. Both
    -- a line and a byte ceiling, since request_uri / UA are attacker-influenced.
    buf       = {}
    buf_n     = 0
    buf_bytes = 0
    return
  end

  -- Interval timer: bounds how stale the OLDEST buffered line may get. If arming
  -- fails (`too many pending timers` — near-impossible now that batching cuts our
  -- timer rate ~FLUSH_LINES×), timer_set stays false and the NEXT append retries;
  -- a sub-cap tail can only strand if traffic also stops dead in that window
  -- (best-effort logs, an accepted corner under global timer exhaustion).
  if not timer_set then
    timer_set = arm(FLUSH_INTERVAL, "interval")
  end
  -- Eager timer: once a burst has piled up FLUSH_LINES (or FLUSH_BYTES), drain
  -- now rather than wait out the interval — this also bounds how much a single
  -- failed send can lose. NOT gated on timer_set: under timer pressure the early
  -- drain is exactly when it matters most, and eager_set caps it to one pending
  -- eager timer, so the retry cost is a cheap failing ngx.timer.at, not loss.
  if not eager_set and (buf_n >= FLUSH_LINES or buf_bytes >= FLUSH_BYTES) then
    eager_set = arm(0, "eager")
  end
end

return _M
