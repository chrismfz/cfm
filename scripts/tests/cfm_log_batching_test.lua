-- Tests for log-cfm.lua's per-worker line batching.
--
-- Before: one ngx.timer.at + one socket send PER request (1000 rps ⇒ 1000
-- timers/s/worker, brushing `too many pending timers`). After: lines are
-- buffered per worker and a single timer drains the whole buffer — after at
-- most FLUSH_INTERVAL, or immediately once FLUSH_LINES accumulate. The Go
-- receiver splits on '\n', so a concatenated batch parses as individual
-- records; these tests assert the batch is well-formed, ordered, drained
-- exactly once, and memory-bounded.

package.path = "configs/lua/?.lua;" .. package.path

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. tostring(msg) .. "\n")
end

-- ── ngx stub: capture armed timers and socket sends ──────────────────────────
local timers, sent
local function new_dict()
  local store = {}
  return {
    get    = function(_, k) return store[k] end,
    set    = function(_, k, v) store[k] = v end,
    incr   = function(_, k, v, init) store[k] = (store[k] or init or 0) + v; return store[k] end,
    delete = function(_, k) store[k] = nil end,
  }
end
local function fake_sock()
  return {
    settimeouts  = function() end,
    connect      = function() return true end,
    send         = function(_, payload) sent[#sent + 1] = payload; return true end,
    setkeepalive = function() return true end,
    close        = function() end,
  }
end
_G.ngx = {
  now    = function() return 1000 end,
  log    = function() end,
  WARN   = 1,
  var    = {},
  shared = { cfm_metrics = new_dict() },
  timer  = { at = function(delay, cb, kind) timers[#timers + 1] = { delay = delay, cb = cb, kind = kind }; return true end },
  socket = { tcp = fake_sock },
}

-- Load a FRESH module instance (upvalue buffer reset) and clear the captures.
local function fresh()
  package.loaded["log-cfm"] = nil
  timers, sent = {}, {}
  return require("log-cfm")
end

-- Emit one request whose URI encodes `i`, so order/content is verifiable.
local function emit(m, i)
  ngx.var = { msec = "1000.0", remote_addr = "1.2.3.4", host = "h", request_method = "GET",
              request_uri = "/r" .. i, server_protocol = "HTTP/1.1", status = "200",
              body_bytes_sent = "10", request_time = "0.001", upstream_response_time = "-",
              http_referer = "", http_user_agent = "ua" }
  m.log()
end

local function fire(kind)
  for _, t in ipairs(timers) do
    if (kind == "interval" and t.delay > 0) or (kind == "eager" and t.delay == 0) then
      t.cb(false, t.kind)   -- ngx passes the bound `kind` arg through to the callback
    end
  end
end
local function count_records(payload)
  local n = 0
  for _ in payload:gmatch("[^\n]+") do n = n + 1 end
  return n
end

-- ── 1) sub-FLUSH_LINES burst → ONE interval timer, ONE send, all records ─────
do
  local m = fresh()
  for i = 1, 3 do emit(m, i) end
  check(#timers == 1 and timers[1].delay > 0, "3 lines arm exactly one interval timer (no eager)")
  check(#sent == 0, "nothing sent until the timer fires (buffered)")
  fire("interval")
  check(#sent == 1, "one flush → one socket send for the whole batch (got " .. #sent .. ")")
  check(count_records(sent[1]) == 3, "batch carries all 3 records")
  check(sent[1]:find("/r1\t", 1, true) and sent[1]:find("/r3\t", 1, true), "records preserved in the batch")
  check(select(2, sent[1]:gsub("\n", "")) == 3, "each record is newline-terminated (3 newlines)")
end

-- ── 2) reaching FLUSH_LINES (64) arms an eager (0-delay) drain ────────────────
do
  local m = fresh()
  for i = 1, 64 do emit(m, i) end
  local has_eager = false
  for _, t in ipairs(timers) do if t.delay == 0 then has_eager = true end end
  check(has_eager, "64th line arms an eager 0-delay flush")
  fire("eager")
  check(#sent == 1 and count_records(sent[1]) == 64, "eager flush sends all 64 as one batch")
  -- Buffer drained: firing the interval timer now sends nothing.
  fire("interval")
  check(#sent == 1, "buffer was drained by the eager flush (interval flush is a no-op)")
end

-- ── 3) snapshot: appends during/after a flush are not double-sent or lost ─────
do
  local m = fresh()
  emit(m, 1); emit(m, 2)
  fire("interval")                       -- drains r1,r2
  check(#sent == 1 and count_records(sent[1]) == 2, "first flush drains the first two")
  emit(m, 3)                             -- new line after the drain
  fire("interval")                       -- a re-armed interval timer drains r3
  check(#sent == 2 and count_records(sent[2]) == 1, "only the NEW record is sent by the next flush")
  check(sent[2]:find("/r3\t", 1, true) ~= nil and sent[2]:find("/r1\t", 1, true) == nil,
        "no double-send of already-flushed records")
end

-- ── 3b) an eager drain does not spawn a second interval timer ─────────────────
-- flush(kind) clears only the fired kind's flag, so the interval timer armed on
-- line 1 stays "pending" after an eager flush and is NOT re-armed — pending
-- flush timers stay capped at ≤2/worker (the point of batching).
do
  local m = fresh()
  for i = 1, 64 do emit(m, i) end          -- arms interval (line 1) + eager (line 64)
  fire("eager")                            -- drains; clears eager_set only
  emit(m, 65)                              -- interval still pending → must NOT arm another
  local intervals = 0
  for _, t in ipairs(timers) do if t.delay > 0 then intervals = intervals + 1 end end
  check(intervals == 1, "only one interval timer ever armed (no accumulation after eager drain), got " .. intervals)
end

-- ── 3c) FLUSH_BYTES arms an eager drain even below FLUSH_LINES ───────────────
-- A few very large lines (long URI/UA) must not sit for the whole interval;
-- crossing the byte threshold triggers the same eager flush as the line count.
do
  local m = fresh()
  local big = string.rep("A", 200 * 1024)          -- 200 KB UA
  ngx.var = { msec = "1", remote_addr = "1", host = "h", request_method = "GET",
              request_uri = "/big1", server_protocol = "HTTP/1.1", status = "200",
              body_bytes_sent = "1", request_time = "0.001", upstream_response_time = "-",
              http_referer = "", http_user_agent = big }
  m.log(); m.log()                                   -- ~400 KB, 2 lines (< FLUSH_LINES)
  local has_eager = false
  for _, t in ipairs(timers) do if t.delay == 0 then has_eager = true end end
  check(has_eager, "crossing FLUSH_BYTES arms an eager flush with only 2 lines")
end

-- ── 3d) premature (worker shutdown) drops the tail without touching the socket ─
-- Cosockets are disabled in a premature timer, and a send would also pollute the
-- SHARED backoff dict from a dying worker — so flush() must not send on premature.
do
  local m = fresh()
  emit(m, 1); emit(m, 2)
  for _, t in ipairs(timers) do if t.delay > 0 then t.cb(true, t.kind) end end  -- shutdown
  check(#sent == 0, "premature flush does NOT hit the socket (tail dropped, no shared-dict pollution)")
end

-- ── 4) MAX_LINES hard cap drops the batch (memory bound) when timers stall ────
do
  local m = fresh()
  -- Do NOT fire any timer, so the buffer keeps growing until the cap.
  for i = 1, 4096 do emit(m, i) end       -- the 4096th append hits MAX_LINES → drop
  emit(m, 999999)                         -- one post-drop line
  fire("interval")
  check(#sent == 1, "after the drop, a flush sends only what accumulated since")
  check(count_records(sent[1]) == 1 and sent[1]:find("/r999999\t", 1, true) ~= nil,
        "MAX_LINES dropped the overflowed batch, keeping memory bounded")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_log_batching_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: log-cfm per-worker line batching (single-drain, eager at FLUSH_LINES, snapshot, MAX_LINES cap)\n")
