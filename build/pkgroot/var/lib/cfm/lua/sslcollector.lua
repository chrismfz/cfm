-- /opt/openresty/nginx/lua/sslcollector.lua
-- QUIC-safe SSL Collector (preload + refresh + disk snapshot):
-- - Background poll /stats (version change) and fetches /dumpall over unix socket
-- - Stores PEM strings in worker-local table (not shared dict — see note below)
-- - Writes disk snapshot atomically; loads it on startup so restarts survive CFM downtime
-- - ssl_certificate_by_lua_block ONLY does dict lookup + PEM parse + set_cert (no I/O, no yield)
--
-- Security model (see also docs/ssl-collector.md and internal/sslcollector/socketapi.go):
--   The bearer token is written to /var/lib/cfm/lua/cfm_token.lua at mode 0640 (root:cfm).
--   The only members of the cfm OS group are nginx/OpenResty/Angie worker processes.
--   Any cfm-group principal is therefore trusted at the same level as a running nginx worker.
--
--   Future hardening options (not yet implemented):
--     1. SO_PEERCRED — restrict socket callers to the exact nginx worker binary via kernel
--        credential verification rather than a group-readable file token.
--     2. Encrypted offline snapshot — encrypt dump.json so the on-disk artifact cannot be
--        used in isolation if exfiltrated.  Toggle via SSLCOLLECTOR_OFFLINE_CACHE = 0/1.
--
--
-- Health keys written to shared dict (all TTL=0, never expire):
--   meta:ready                  "1" once at least one cert was ingested
--   meta:version                last known upstream version string
--   meta:generated_at           upstream-reported generation timestamp
--   meta:last_dumpall_at        unix time of last SUCCESSFUL ingest
--   meta:last_dumpall_src       "dumpall" | "snapshot" | ...
--   meta:last_dumpall_attempt_at unix time of last do_dumpall() call (success or fail)
--   meta:snapshot_written_at    unix time of last successful snapshot write
--   meta:last_stats_at          unix time of last successful /stats response
--   meta:poll_interval          current backoff interval in seconds
--   meta:last_error             last error message
--   meta:last_error_at          unix time of last error

local ssl  = require "ngx.ssl"
local http = require "resty.http"
local json = require "cjson.safe"

local dict = ngx.shared.sslcache

-- Worker-local cert store.
-- Keys: "e:<host>" (exact) or "w:<suffix>" (wildcard)
-- Values: { cert = "<PEM>", key = "<PEM>" }
--
-- Intentionally NOT stored in ngx.shared dict: shared dicts are accessible to
-- any Lua code in the same OpenResty process via dict:get_keys() + dict:get().
-- A worker-local table is only reachable by code that holds a reference to this
-- module — significantly smaller attack surface for key material enumeration.
local _store = {}

-- Socket(s) + token
local SOCKS = {
  "/var/run/sslcollector.sock",
  -- "/var/run/sslcollector2.sock",  -- optional secondary for HA
}

-- Token is written by CFM at startup/reload (root:cfm 0640) and loaded from
-- a single canonical path to prevent stale legacy copies from being used.
-- The file returns a single string: return "deadbeef..."
local _TOKEN_FILE = "/var/lib/cfm/lua/cfm_token.lua"
local TOKEN
do
  local chunk, load_err = loadfile(_TOKEN_FILE)
  if not chunk then
    ngx.log(ngx.ERR, "[sslcollector] cannot load token file ", _TOKEN_FILE, ": ", tostring(load_err))
    error("[sslcollector] missing token file — cfm may not have started yet; path: "
          .. _TOKEN_FILE .. "; details: load: " .. tostring(load_err))
  end
  local ok, val = pcall(chunk)
  if not ok or type(val) ~= "string" or #val < 32 then
    ngx.log(ngx.ERR, "[sslcollector] token file invalid or too short: ", _TOKEN_FILE)
    error("[sslcollector] invalid token in " .. _TOKEN_FILE)
  end
  TOKEN = val
end

-- ---------------------------------------------------------------------------
-- Per-daemon runtime config (written by CFM at startup, optional)
-- ---------------------------------------------------------------------------
-- cfm_sslcollector_config.lua returns a table with boolean flags.
-- If the file is absent (e.g. older cfm build) all flags default to true.
-- cfm daemon reads SSLCOLLECTOR_OFFLINE_CACHE from /etc/cfm/cfm.conf (root-only)
-- and writes the resolved value here (0640 root:cfm) — same indirection as the
-- token file.  Nginx workers read this file, not cfm.conf directly.
local _CFG_FILE = "/var/lib/cfm/lua/cfm_sslcollector_config.lua"
local _cfg = {}
do
  local chunk = loadfile(_CFG_FILE)
  if chunk then
    local ok, result = pcall(chunk)
    if ok and type(result) == "table" then
      _cfg = result
    end
  end
end

-- OFFLINE_CACHE: when false, skip snapshot read/write.
-- Disable via SSLCOLLECTOR_OFFLINE_CACHE = 0 in cfm.conf.
-- Default true when config file is absent (older cfm build compatibility).
local OFFLINE_CACHE = (_cfg.offline_cache ~= false)

-- ---------------------------------------------------------------------------
-- Tunables
-- ---------------------------------------------------------------------------

-- Poll backoff: starts at POLL_SECS_MIN, doubles on each /stats failure.
-- Resets to POLL_SECS_MIN on any successful /stats response.
local POLL_SECS_MIN = 300   -- 5m  base (healthy)
local POLL_SECS_MAX = 1200  -- 20m ceiling (sustained failures)

-- Lock TTL for do_dumpall(). High enough to cover large payloads + latency.
local LOCK_TTL = 180  -- 3m

-- Force a dumpall if the last SUCCESSFUL ingest is older than this.
-- Evaluated on every poll tick (success AND failure).
-- Set to 0 to disable.
local FORCE_DUMPALL_AFTER = 3600  -- 1h

-- [FIX-A] Minimum time between force-dumpall ATTEMPTS (success or fail).
-- Prevents hammering /dumpall on every poll tick during sustained outages.
-- The lock (LOCK_TTL) already prevents concurrent runs within a single worker,
-- but this cross-worker shared-dict key throttles across all workers.
-- Must be < FORCE_DUMPALL_AFTER to be useful; < POLL_SECS_MAX to allow retries.
local FORCE_DUMPALL_MIN_RETRY = 600  -- 10m; do not attempt more often than this

-- HTTP socket timeout
local HTTP_TIMEOUT_MS = 5000

-- Minimum valid /dumpall response byte length.
-- Guards against truncated/empty responses overwriting a good snapshot.
local SNAP_MIN_BYTES = 256

-- If true, a /dumpall payload without a Version field is a hard reject for
-- both RAM ingest AND snapshot write. Keep false unless upstream always provides
-- a version and you want strict enforcement.
-- Note: even with false, a version-less payload is still NEVER written to disk.
-- See [FIX-B] — REQUIRE_VERSION_FIELD only controls whether RAM ingest is allowed.
local REQUIRE_VERSION_FIELD = false

-- Disk snapshot paths (never used on the handshake path)
local SNAP_DIR  = "/var/lib/cfm/sslcollector"
local SNAP_FILE = SNAP_DIR .. "/dump.json"
local SNAP_TMP  = SNAP_DIR .. "/dump.json.tmp"

-- ---------------------------------------------------------------------------
-- Worker-local state
-- ---------------------------------------------------------------------------

local poll_interval       = POLL_SECS_MIN  -- per-worker mutable backoff level
local snap_dir_ok         = false          -- ensures os.execute runs once per worker
-- Per-worker version and freshness tracking.
-- Must NOT use the shared dict for version comparison: when storage was
-- shared, one worker's fetch covered all workers so version-dedup was
-- correct. With worker-local _store, each worker must independently detect
-- version changes and fetch for itself. Using the shared dict's meta:version
-- would cause workers whose do_dumpall() was blocked (lock held) to see the
-- version already updated and never retry — leaving their _store stale until
-- the hourly force-refresh.
local _worker_version     = ""   -- last version this worker successfully ingested
local _worker_last_dumpall = 0   -- unix time of last successful ingest for this worker

local M = {}

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

local function normalize_name(s)
  if not s then return "" end
  s = tostring(s)
  s = s:lower()
  s = s:gsub("^%s+", ""):gsub("%s+$", "")
  s = s:gsub("%.$", "")
  return s
end

local function set_last_error(msg)
  if msg and msg ~= "" then
    dict:set("meta:last_error",    tostring(msg), 0)
    dict:set("meta:last_error_at", ngx.time(),    0)
  end
end

local function auth_headers()
  local h = { ["Host"] = "localhost" }
  if TOKEN and TOKEN ~= "" then
    h["X-SSLCollector-Token"] = TOKEN
  end
  return h
end

local function sock_get_one(sock, path)
  local httpc = http.new()
  httpc:set_timeout(HTTP_TIMEOUT_MS)

  local ok, err = httpc:connect("unix:" .. sock)
  if not ok then
    return nil, "connect(" .. sock .. "): " .. (err or "?")
  end

  local res, rerr = httpc:request({
    method  = "GET",
    path    = path,
    headers = auth_headers(),
  })

  if not res then
    httpc:close()
    return nil, "request: " .. (rerr or "?")
  end

  local body, berr = res:read_body()
  httpc:close()

  if not body then
    return nil, "read_body: " .. (berr or "?")
  end

  return { status = res.status, body = body }
end

local function sock_get(path)
  local lastErr
  for _, s in ipairs(SOCKS) do
    local r, e = sock_get_one(s, path)
    if r then return r end
    lastErr = e
  end
  return nil, lastErr or "no sockets configured"
end

-- ---------------------------------------------------------------------------
-- Shared dict: cert pair storage
-- ---------------------------------------------------------------------------

local function store_pair(prefix, name, cert_pem, key_pem)
  if not name or name == "" then
    return false, "empty name"
  end
  if not cert_pem or cert_pem == "" then
    return false, "empty cert_pem"
  end
  if not key_pem or key_pem == "" then
    return false, "empty key_pem"
  end

  _store[prefix .. name] = { cert = cert_pem, key = key_pem }
  return true
end

-- ---------------------------------------------------------------------------
-- Validation
-- ---------------------------------------------------------------------------

-- Validates a raw /dumpall JSON body.
-- Returns on success: true, parsed_table, has_version (bool)
-- Returns on failure: nil,  error_string, false
--
-- Hard checks (always enforced):
--   - minimum byte length
--   - valid JSON
--   - Exact/exact and Wild/wild are tables
--
-- Soft check:
--   - Version/version present and non-empty
--   - If REQUIRE_VERSION_FIELD=true: hard reject for both RAM + disk
--   - If REQUIRE_VERSION_FIELD=false (default): RAM ingest allowed with warning
--     but [FIX-B] disk snapshot is never written without a version field
local function validate_dumpall_body(body)
  if not body then
    return nil, "nil body", false
  end

  if #body < SNAP_MIN_BYTES then
    return nil, string.format("too small (%d bytes, min %d)", #body, SNAP_MIN_BYTES), false
  end

  local data = json.decode(body)
  if not data then
    return nil, "json.decode failed", false
  end

  local exact = data.Exact or data.exact
  local wild  = data.Wild  or data.wild
  if type(exact) ~= "table" or type(wild) ~= "table" then
    return nil, "Exact/exact or Wild/wild missing or not a table", false
  end

  local ver = data.Version or data.version
  local has_version = (ver and ver ~= "")

  if not has_version then
    if REQUIRE_VERSION_FIELD then
      return nil, "missing Version/version (REQUIRE_VERSION_FIELD=true)", false
    end
    ngx.log(ngx.WARN, "[sslcollector] dumpall payload has no Version field")
  end

  return true, data, has_version
end

-- ---------------------------------------------------------------------------
-- Disk snapshot: write / read
-- ---------------------------------------------------------------------------

local function ensure_snap_dir()
  if snap_dir_ok then return end
  -- Directory is created and owned by the cfm daemon at startup (root:cfm 0770).
  -- Verify it exists; log and abort if missing rather than trying to create it
  -- from inside an nginx worker (which may lack the necessary permissions).
  local ok = os.execute("test -d " .. SNAP_DIR)
  if not ok then
    ngx.log(ngx.ERR, "[sslcollector] snapshot dir missing: ", SNAP_DIR,
      " — ensure cfm daemon has started at least once")
    return
  end
  snap_dir_ok = true
end

-- [FIX-B] write_snapshot is only called when has_version=true.
-- The check is enforced in do_dumpall(); this function assumes the caller
-- has already verified version presence. It re-validates for safety.
local function write_snapshot(body, parsed_data)
  -- Double-check version gate (defensive; caller should already have checked)
  local ver = (parsed_data and (parsed_data.Version or parsed_data.version)) or ""
  if ver == "" then
    return false, "refused: no Version field in payload (would overwrite versioned snapshot)"
  end

  ensure_snap_dir()

  local f, ferr = io.open(SNAP_TMP, "wb")
  if not f then
    return false, "open tmp: " .. (ferr or "?")
  end
  f:write(body)
  f:close()

  local ok, ren_err = os.rename(SNAP_TMP, SNAP_FILE)
  if not ok then
    return false, "rename: " .. (ren_err or "?")
  end

-- best-effort tighten permissions on the snapshot file (contains private keys).
-- Directory permissions are managed by the cfm daemon (root:cfm 0770) — do
-- not chmod the directory here or it will fight the daemon setting.
os.execute("chmod 0640 " .. SNAP_FILE .. " >/dev/null 2>&1")

  dict:set("meta:snapshot_written_at", ngx.time(), 0)
  return true
end

local function read_snapshot()
  local f = io.open(SNAP_FILE, "rb")
  if not f then return nil end
  local body = f:read("*a")
  f:close()
  if not body or body == "" then return nil end
  return body
end

-- ---------------------------------------------------------------------------
-- Core ingestion
-- ---------------------------------------------------------------------------
local function ingest_dumpall(data, src)
  local ver = data.version or data.Version or ""
  if ver ~= "" then
    dict:set("meta:version", ver, 86400)
  end
  if data.generated_at then
    dict:set("meta:generated_at", tostring(data.generated_at), 86400)
  end

  local exact_list = data.exact or data.Exact or {}
  local wild_list  = data.wild  or data.Wild  or {}

  local reported_exact = #exact_list
  local reported_wild  = #wild_list

  local okN, failN = 0, 0

  for _, it in ipairs(exact_list) do
    local host     = normalize_name(it.host or it.Host)
    local cert_pem = it.cert_pem or it.cert or it.CertPEM
    local key_pem  = it.key_pem  or it.key  or it.KeyPEM

    if host ~= "" and cert_pem and key_pem then
      local ok, e = store_pair("e:", host, cert_pem, key_pem)
      if ok then
        okN = okN + 1
      else
        failN = failN + 1
        ngx.log(ngx.WARN, "[sslcollector] store exact fail host=", host, " err=", e)
      end
    else
      failN = failN + 1
      ngx.log(ngx.WARN, "[sslcollector] skip exact host=",
        tostring(host ~= "" and host or (it.host or it.Host or "?")),
        " reason=missing_host_or_pem")
    end
  end

  for _, it in ipairs(wild_list) do
    local suf      = normalize_name(it.suffix or it.Suffix)
    local cert_pem = it.cert_pem or it.cert or it.CertPEM
    local key_pem  = it.key_pem  or it.key  or it.KeyPEM

    if suf ~= "" and cert_pem and key_pem then
      local ok, e = store_pair("w:", suf, cert_pem, key_pem)
      if ok then
        okN = okN + 1
      else
        failN = failN + 1
        ngx.log(ngx.WARN, "[sslcollector] store wild fail suffix=", suf, " err=", e)
      end
    else
      failN = failN + 1
      ngx.log(ngx.WARN, "[sslcollector] skip wild suffix=",
        tostring(suf ~= "" and suf or (it.suffix or it.Suffix or "?")),
        " reason=missing_suffix_or_pem")
    end
  end

  if okN > 0 then
    dict:set("meta:ready",            "1",         86400)
    dict:set("meta:last_dumpall_at",   ngx.time(), 0)
    dict:set("meta:last_dumpall_src",  src or "?", 86400)
    -- Advance this worker's view of its version and freshness timestamp.
    -- Doing it here (inside ingest) covers all paths: version-triggered
    -- dumpall, force-refresh, and snapshot load on startup.
    if ver ~= "" then _worker_version = ver end
    _worker_last_dumpall = ngx.time()
  end

  local cached_exact, cached_wild = 0, 0
  for k in pairs(_store) do
    if k:sub(1, 2) == "e:" then
      cached_exact = cached_exact + 1
    elseif k:sub(1, 2) == "w:" then
      cached_wild = cached_wild + 1
    end
  end

  ngx.log(ngx.WARN, "[sslcollector] ingest src=", (src or "?"),
    " reported_exact=", reported_exact,
    " reported_wild=", reported_wild,
    " cached_exact=", cached_exact,
    " cached_wild=", cached_wild,
    " ok=", okN,
    " fail=", failN,
    " ver=", (ver ~= "" and ver or "-"))

  return okN, failN
end

local function load_from_snapshot()
  if not OFFLINE_CACHE then
    ngx.log(ngx.INFO, "[sslcollector] offline cache disabled (SSLCOLLECTOR_OFFLINE_CACHE=0), skipping snapshot load")
    return
  end
  local body = read_snapshot()
  if not body then
    ngx.log(ngx.WARN, "[sslcollector] no snapshot on disk (first boot?)")
    return
  end

  local data = json.decode(body)
  if not data then
    ngx.log(ngx.ERR, "[sslcollector] snapshot bad json (ignored)")
    set_last_error("startup: snapshot bad json")
    return
  end

  ingest_dumpall(data, "snapshot")
end

-- ---------------------------------------------------------------------------
-- do_dumpall: fetch, validate, ingest, conditionally persist
-- ---------------------------------------------------------------------------

local function do_dumpall()
  local lock_key = "lock:dumpall"
  if not dict:add(lock_key, true, LOCK_TTL) then
    return  -- another worker is already running; skip
  end

  -- [FIX-A] Record attempt time immediately, before any I/O.
  -- Written to shared dict so all workers see it and respect FORCE_DUMPALL_MIN_RETRY.
  -- This fires on every call to do_dumpall() — version-triggered or force — so the
  -- throttle correctly suppresses redundant force attempts after any dumpall type.
  dict:set("meta:last_dumpall_attempt_at", ngx.time(), 0)

  local ok, err = pcall(function()
    local r, rerr = sock_get("/dumpall")
    if not r then
      ngx.log(ngx.ERR, "[sslcollector] dumpall socket error: ", rerr)
      set_last_error("dumpall socket: " .. tostring(rerr))
      return
    end
    if r.status ~= 200 then
      ngx.log(ngx.ERR, "[sslcollector] dumpall unexpected status: ", r.status)
      set_last_error("dumpall status: " .. tostring(r.status))
      return
    end

    local vok, vdata, has_version = validate_dumpall_body(r.body)
    if not vok then
      ngx.log(ngx.ERR, "[sslcollector] dumpall body invalid: ", vdata)
      set_last_error("dumpall invalid: " .. tostring(vdata))
      return
    end

    -- Always update RAM cache (soft: version optional)
    ingest_dumpall(vdata, "dumpall")

    -- [FIX-B] Only write disk snapshot if payload carries a Version field AND
    -- offline cache is enabled (SSLCOLLECTOR_OFFLINE_CACHE).
    if not OFFLINE_CACHE then
      -- offline cache disabled: skip snapshot write entirely
    elseif has_version then
      local wok, we = write_snapshot(r.body, vdata)
      if not wok then
        ngx.log(ngx.WARN, "[sslcollector] snapshot write skipped: ", we)
        set_last_error("snapshot write: " .. tostring(we))
      end
    else
      ngx.log(ngx.WARN, "[sslcollector] skipping snapshot write: payload has no Version field")
    end
  end)

  -- Always release the lock
  dict:delete(lock_key)

  if not ok then
    ngx.log(ngx.ERR, "[sslcollector] do_dumpall unhandled error (lock released): ", err)
    set_last_error("do_dumpall panic: " .. tostring(err))
  end
end

-- ---------------------------------------------------------------------------
-- Age-based force refresh with throttle
-- ---------------------------------------------------------------------------

-- Freshness check uses _worker_last_dumpall (worker-local) so each worker
-- independently detects its own stale store. The throttle key
-- (meta:last_dumpall_attempt_at) remains shared to prevent all workers from
-- hammering the socket simultaneously during a sustained outage.
--
-- Decision matrix per poll tick:
--   _worker_last_dumpall == 0               -> force (this worker never ingested)
--   age(_worker_last_dumpall) <= FORCE_AFTER -> no-op (this worker's store is fresh)
--   age(last_attempt_at) < MIN_RETRY        -> skip  (cross-worker throttle)
--   age(_worker_last_dumpall) > FORCE_AFTER
--     AND throttle clear                    -> force
local function maybe_force_dumpall()
  if not FORCE_DUMPALL_AFTER or FORCE_DUMPALL_AFTER <= 0 then
    return
  end

  if _worker_last_dumpall == 0 then
    -- This worker has never successfully ingested (startup blocked or failed).
    local last_attempt = dict:get("meta:last_dumpall_attempt_at") or 0
    local since_attempt = ngx.time() - last_attempt
    if last_attempt > 0 and since_attempt < FORCE_DUMPALL_MIN_RETRY then
      ngx.log(ngx.INFO,
        "[sslcollector] worker has no dumpall yet; next retry in ",
        FORCE_DUMPALL_MIN_RETRY - since_attempt, "s")
      return
    end
    ngx.log(ngx.WARN, "[sslcollector] worker has no dumpall record, forcing now")
    do_dumpall()
    return
  end

  local age = ngx.time() - _worker_last_dumpall
  if age <= FORCE_DUMPALL_AFTER then
    return  -- this worker's store is fresh enough
  end

  -- This worker's store is stale; check cross-worker throttle before hitting socket
  local last_attempt = dict:get("meta:last_dumpall_attempt_at") or 0
  local since_attempt = ngx.time() - last_attempt
  if last_attempt > 0 and since_attempt < FORCE_DUMPALL_MIN_RETRY then
    ngx.log(ngx.INFO,
      "[sslcollector] worker store stale (", age, "s) but cross-worker throttle active; next in ",
      FORCE_DUMPALL_MIN_RETRY - since_attempt, "s")
    return
  end

  ngx.log(ngx.WARN,
    "[sslcollector] worker store ", age, "s old (limit ", FORCE_DUMPALL_AFTER, "s), forcing refresh")
  do_dumpall()
end

-- ---------------------------------------------------------------------------
-- Poll loop
-- ---------------------------------------------------------------------------

local function poll_stats(premature)
  if premature then return end

  dict:set("meta:poll_interval", poll_interval, 0)

  local r, err = sock_get("/stats")

  if r and r.status == 200 then
    poll_interval = POLL_SECS_MIN
    dict:set("meta:last_stats_at", ngx.time(), 0)

    local st = json.decode(r.body)
    if st then
      local newv = st.Version or st.version or ""
      if newv ~= "" then
        -- Compare against _worker_version, not the shared dict. Each worker
        -- must independently detect version changes and fetch for itself.
        -- If do_dumpall() is blocked by lock, _worker_version won't advance
        -- (ingest_dumpall never ran), so the next poll tick will see the
        -- mismatch again and retry — giving each worker eventual consistency
        -- within one poll interval rather than waiting for the force-refresh.
        if newv ~= _worker_version then
          ngx.log(ngx.NOTICE,
            "[sslcollector] worker version change ", _worker_version, " -> ", newv,
            " (triggering worker refresh)")
          do_dumpall()
          -- Always update the shared monitoring key regardless of whether
          -- do_dumpall() was blocked — other workers and cfm_stats read it.
          dict:set("meta:version", newv, 86400)
        end
      end
    end

  else
    local prev = poll_interval
    poll_interval = math.min(poll_interval * 2, POLL_SECS_MAX)
    ngx.log(ngx.WARN,
      "[sslcollector] /stats failed (", (err or (r and r.status) or "?"), ")",
      " backoff ", prev, "s -> ", poll_interval, "s")
    set_last_error("stats: " .. tostring(err or (r and r.status) or "?"))
  end

  -- Always evaluate age-based force refresh, regardless of /stats health
  maybe_force_dumpall()

  local tok, te = ngx.timer.at(poll_interval, poll_stats)
  if not tok then
    ngx.log(ngx.ERR, "[sslcollector] poll reschedule error: ", te)
    set_last_error("poll reschedule: " .. tostring(te))
  end
end

-- ---------------------------------------------------------------------------
-- Public API
-- ---------------------------------------------------------------------------

function M.start_background()
  local ok, e = ngx.timer.at(0, function(premature)
    if premature then return end

    -- 1) Warm RAM from disk snapshot
    load_from_snapshot()

    -- 2) Attempt live dumpall immediately.
    --    Sets meta:last_dumpall_attempt_at + meta:last_dumpall_at (on success)
    --    so the first maybe_force_dumpall() tick (~1s later) is correctly throttled.
    do_dumpall()

    -- 3) Start poll loop
    ngx.timer.at(1, poll_stats)
  end)

  if not ok then
    ngx.log(ngx.ERR, "[sslcollector] start_background timer error: ", e)
    set_last_error("start_background: " .. tostring(e))
  end
end

-- QUIC-safe: no socket I/O, no yield points.
function M.set_cert()
  local sni = ssl.server_name()
  if not sni or sni == "" then
    return
  end
  sni = normalize_name(sni)

  -- 1) Exact match
  local entry = _store["e:" .. sni]

  -- 2) Wildcard: longest-suffix match
  --    foo.bar.example.com -> bar.example.com -> example.com
  if not entry then
    local tmp = sni
    while true do
      local dot = string.find(tmp, "%.")
      if not dot then break end
      tmp = string.sub(tmp, dot + 1)
      entry = _store["w:" .. tmp]
      if entry then break end
    end
  end

  if not entry then
    ngx.log(ngx.WARN, "[sslcollector] cache miss sni=", sni, " -> nginx fallback cert")
    return
  end

  local cert_der, cerr = ssl.parse_pem_cert(entry.cert)
  if not cert_der then
    ngx.log(ngx.ERR, "[sslcollector] parse cert failed sni=", sni, " err=", (cerr or "?"))
    return
  end

  local key_der, kerr = ssl.parse_pem_priv_key(entry.key)
  if not key_der then
    ngx.log(ngx.ERR, "[sslcollector] parse key failed sni=", sni, " err=", (kerr or "?"))
    return
  end

  ssl.clear_certs()

  local ok1, err1 = ssl.set_cert(cert_der)
  if not ok1 then
    ngx.log(ngx.ERR, "[sslcollector] ssl.set_cert failed sni=", sni, " err=", (err1 or "?"))
    return
  end

  local ok2, err2 = ssl.set_priv_key(key_der)
  if not ok2 then
    ngx.log(ngx.ERR, "[sslcollector] ssl.set_priv_key failed sni=", sni, " err=", (err2 or "?"))
    return
  end
end

-- Returns exact-host and wildcard counts from the worker-local store.
-- Used by cfm_stats.lua since cert keys are no longer in the shared dict.
function M.cert_counts()
  local exact, wild = 0, 0
  for k in pairs(_store) do
    if k:sub(1, 2) == "e:" then
      exact = exact + 1
    elseif k:sub(1, 2) == "w:" then
      wild = wild + 1
    end
  end
  return exact, wild
end

return M
