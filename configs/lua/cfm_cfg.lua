-- /var/lib/cfm/lua/cfm_cfg.lua (CFM-managed canonical location)
--
-- The request-INVARIANT slice of cfm.lua's CFG, built ONCE per worker.
--
-- cfm.lua is an access_by_lua_file: its whole body re-executes on EVERY request
-- (see the PITFALL block at the top of cfm.lua). The original inline CFG literal
-- therefore re-ran ~21 os.getenv() reads and re-allocated a couple of temporary
-- tables and a closure per request. Those inputs are all process-lifetime
-- constants — a worker's environment cannot change after it starts. In practice
-- none of these CFM_* knobs is ever set anyway: the systemd units export none,
-- and nginx/openresty/angie strip every env var NOT declared with `env NAME;`
-- (only 6 are declared, none set), so os.getenv() here returns nil and the
-- defaults always win. Reading them once per worker — this module is loaded via
-- require(), whose package.loaded cache persists for the worker's lifetime — is
-- byte-identical to the per-request read, minus the per-request garbage.
--
-- ONLY request-invariant fields belong here. The bridge-derived fields (token,
-- ok_ttl_sec, clearance_refresh, origin_keepalive) refresh on the bridge file's
-- 10s TTL and MUST stay per-request; cfm.lua layers those onto this table via a
-- metatable __index (a small per-request table shadows them). Do NOT move a
-- bridge-derived value here — it would freeze operator toggles (e.g.
-- ORIGIN_KEEPALIVE) until a worker restart.

local M = {
  sock_path = "/var/run/cfm/cfm_nginx.sock",

  token_header = "X-CFM-Token",

  -- Default 100ms: headroom for the first connect (no pooled socket yet),
  -- plus the bridge's synchronous-state mutation. Hook-backed work (WAF
  -- history, observations) is dispatched async on the Go side so this
  -- budget only needs to cover state mutation + JSON (sub-millisecond).
  decision_timeout_ms   = tonumber(os.getenv("CFM_DECISION_TIMEOUT_MS") or "300"),
  -- Clean-allow verdicts are cached this long (90s) before the bridge is
  -- re-consulted. This bounds enforcement lag: a newly flagged IP keeps a
  -- cached allow for up to 90s. Deliberately NOT env-overridable (unlike its
  -- neighbours) — a single hard-coded, reviewed value. Keep the doc-comments
  -- that cite this window (header "Design principles", the static-asset and
  -- geo-cache notes) in sync if you change it.
  decision_cache_ttl_ms = 90000,
  waf_excl_cache_ttl_ms = tonumber(os.getenv("CFM_WAF_EXCL_CACHE_TTL_MS") or "6000"),
  waf_excl_meta_ttl_sec = tonumber(os.getenv("CFM_WAF_EXCL_META_TTL_SEC") or "15"),
  waf_excl_refresh_sec  = tonumber(os.getenv("CFM_WAF_EXCL_REFRESH_SEC") or "10"),

  block_code = 403,
  fail_open  = (os.getenv("CFM_FAIL_OPEN") or "1") ~= "0",

  debug         = (os.getenv("CFM_DEBUG") == "1"),
  debug_headers = (os.getenv("CFM_DEBUG_HEADERS") == "1"),
  log_allows    = (os.getenv("CFM_LOG_ALLOWS") == "1"),

  ok_touch_every_sec = tonumber(os.getenv("CFM_OK_TOUCH_EVERY_SEC") or "120"),

  keepalive_idle_ms = tonumber(os.getenv("CFM_BRIDGE_KA_IDLE_MS") or "60000"),
  keepalive_pool    = tonumber(os.getenv("CFM_BRIDGE_KA_POOL")    or "512"),

  -- Upper bound on the request-body bytes handed to the WAF (audit F08). This
  -- must be >= the largest per-Content-Type budget in cfm_waf.lua's
  -- `body_scan_budget` (json = 32768 today), otherwise this reader truncates
  -- the body BEFORE the WAF applies its budget and the larger budgets are never
  -- realised — a payload past byte 8192 in a JSON/multipart/xml body escaped
  -- every body-aware rule. Kept at the max budget so the get_norm_ab rules'
  -- per-type budget is the effective limit. (Raw-body detectors that ignore
  -- body_budget — e.g. detect_upload_filename — are truncated directly by this
  -- cap, so it also sets their scan window, now above the nominal multipart
  -- budget.) The invariant is asserted by
  -- scripts/tests/cfm_waf_body_budget_test.lua. Well within post_resume_max_len
  -- = 65536, which already buffers the body for challenge replay.
  --
  -- OPERATORS: if you OVERRIDE CFM_WAF_BODY_MAX_LEN below the largest
  -- body_scan_budget (e.g. to 8192 for memory) you REOPEN F08 — a JSON payload
  -- past your value escapes the body rules. Keep it >= 32768. The CI guardrail
  -- only checks this source default, not the runtime env override.
  waf_body_max_len = tonumber(os.getenv("CFM_WAF_BODY_MAX_LEN") or "32768"),

  -- F07: on non-allowlisted paths the WAF body-read gate skips (does not read,
  -- and so does not buffer) request bodies whose Content-Length exceeds this.
  -- We would only ever scan the first waf_body_max_len bytes anyway, so
  -- buffering a large upload just to peek would regress streaming on the
  -- proxy_request_buffering=off media location. 1 MiB comfortably covers form /
  -- JSON / API bodies; larger uploads stream. Allowlisted paths are unaffected
  -- (they read regardless of size, as before).
  waf_body_read_max_cl = tonumber(os.getenv("CFM_WAF_BODY_READ_MAX_CL") or "1048576"),

  -- Challenge POST replay: a challenged POST's body is stashed (shared dict,
  -- base64) and re-applied after the challenge solves, so form content is not
  -- lost. Allowed content-types: urlencoded / json / text/plain / multipart
  -- (see ct_allows_resume). max_len bounds the stored body — raising it
  -- trades shared-dict memory for replaying bigger (e.g. attachment-bearing)
  -- posts; a body over the cap falls back to the old lose-the-form behaviour.
  post_resume_enable  = (os.getenv("CFM_POST_RESUME_ENABLE") or "1") == "1",
  post_resume_max_len = tonumber(os.getenv("CFM_POST_RESUME_MAX_LEN") or "65536"),
  post_resume_ttl_sec = tonumber(os.getenv("CFM_POST_RESUME_TTL_SEC") or "90"),

  -- Post-clearance WAF policy. cfm_clearance proves the client passed the
  -- challenge gate, NOT that the payload is safe. So when WAF wants to
  -- challenge a request that already has clearance we must NOT re-challenge
  -- (would loop), but we also must not silently allow. Convert via these
  -- knobs: high-risk reason families escalate, the rest degrade to logonly.
  -- Allowed values: "block" | "logonly". "challenge" is intentionally NOT
  -- accepted here because it would re-introduce the loop.
  waf_after_clearance_challenge =
      ({ block = "block", logonly = "logonly" })[os.getenv("CFM_WAF_AFTER_CLEARANCE_CHALLENGE") or ""]
      or "logonly",
  waf_after_clearance_high_risk =
      ({ block = "block", logonly = "logonly" })[os.getenv("CFM_WAF_AFTER_CLEARANCE_HIGH_RISK") or ""]
      or "block",

  -- Hit-rate counters: every WAF inspection increments a per-host bucketed
  -- shdict counter; one worker periodically flushes the snapshot to Go via
  -- /nginx/waf/stats. Required by the rollout playbook (gate promotions on
  -- <0.01% hit-rate evidence). See docs/waf.md "Hit-rate measurement".
  waf_stats_enable    = (os.getenv("CFM_WAF_STATS_ENABLE") or "1") == "1",
  waf_stats_flush_sec = tonumber(os.getenv("CFM_WAF_STATS_FLUSH_SEC") or "60"),
  -- NOTE: the post-clearance cadence shadow toggle (cfm_pcw, B2) is NOT here — it
  -- is bridge-derived ([webdetector] POST_CLEARANCE_CADENCE), read per-request from
  -- cfm_bridge_cfg so it refreshes on the 10s TTL. See cfm.lua CFG.post_clearance_cadence.
}

-- ok_ttl_sec resolution, in priority order: explicit env override; the
-- daemon-published authoritative cookie life (cfm_bridge_config.lua
-- cookie_life_sec — the same CHALLENGE_COOKIE_LIFE chain the challenge server
-- mints tokens with, so sliding re-mints can't silently extend or shorten the
-- operator-configured clearance lifetime); historical 3600 fallback (upgrade
-- lag: old daemon, new Lua). The published value is honored only when > 0 — a
-- sub-second configured life truncates to 0 in the file, and 0 is truthy in Lua
-- (Max-Age=0 would expire the cookie immediately). Same guard cfm_panel.lua's
-- clearance_cookie_ttl uses.
--
-- The env override is request-invariant (hoisted here, read once); the cookie
-- life is bridge-derived (10s TTL), so cfm.lua calls this per request with the
-- live _bridge_cfg.cookie_life_sec. Keeping the env read out of the hot path is
-- the whole point of this module; the closure that used to build this inline in
-- cfm.lua's CFG literal allocated on every request.
local ok_ttl_env = tonumber(os.getenv("CFM_OK_TTL_SEC") or "")
function M.resolve_ok_ttl(cookie_life_sec)
  if ok_ttl_env then return ok_ttl_env end
  local pub = tonumber(cookie_life_sec or "")
  if pub and pub > 0 then return pub end
  return 3600
end

return M
