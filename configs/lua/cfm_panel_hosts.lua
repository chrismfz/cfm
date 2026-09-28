-- cfm_panel_hosts.lua — the canonical list of panel-ish subdomain prefixes.
--
-- Single source of truth consumed by both edge entrypoints (cfm.lua Step 0
-- panel-likeness on the web listeners; cfm_panel.lua has_panel_prefix on the
-- 12xxx panel listeners) and by cfm_cache.lua (Site Cache never caches a panel
-- host). Before this module each file carried its own copy and they drifted:
-- cfm.lua had `mail.` but not `webdisk.`, cfm_panel.lua had `webdisk.` but
-- not `mail.` (CLAUDE.md: never keep a second copy of a list/matcher that can
-- drift). See docs/edge-unification-plan.md §6 Phase 0.
--
-- The two entrypoints pcall-require this module and keep their previous inline
-- PREFIX list as a fallback, so an upgrade-lag deploy (new cfm.lua, old
-- /var/lib/cfm/lua set) degrades to the old behaviour instead of failing the
-- request path. cfm_cache.lua has no fallback list: without this module it
-- caches nothing (fail closed).
--
-- It also owns the cPanel API/SSO passthrough matcher (is_panel_api_or_sso,
-- whose /cpsess<N>/ subset is_session_api is what the web edge passes) and
-- the web-edge gates (is_proxy_panel_host, proxy_hosts_reach_panel). Those
-- have NO inline copy anywhere: without this module, cfm_panel.lua passes no
-- API path through and cfm.lua skips Step 0d. That fails closed: the WAF and
-- challenge still run.

local _M = {}

-- cPanel/WHM proxy-style subdomains plus the common webmail aliases.
_M.PREFIXES = { "cpanel", "whm", "webmail", "webdisk", "mail" }

local set = {}
for _, p in ipairs(_M.PREFIXES) do set[p] = true end

-- is_panel_prefix("cpanel") → true. Accepts the bare first label.
function _M.is_panel_prefix(label)
  return label ~= nil and set[label] == true
end

-- has_panel_prefix("webmail.example.com") → true. Accepts a full host;
-- port-less matching is the caller's job (both callers already strip ports).
function _M.has_panel_prefix(host)
  local h = (host or ""):lower()
  local label = h:match("^([^%.]+)%.")
  return _M.is_panel_prefix(label)
end

-- The cPanel proxy subdomains that Apache hands to cpsrvd (cpanel.X → :2083,
-- whm.X → :2087, webmail.X → :2096). A narrower set than PREFIXES on purpose:
-- `mail.` is an ordinary vhost name and `webdisk.` goes to cpdavd, so neither
-- is known to reach cpsrvd's API. Only these hosts get the web-edge API
-- passthrough (cfm.lua Step 0d).
_M.PROXY_PREFIXES = { "cpanel", "whm", "webmail" }

local proxy_set = {}
for _, p in ipairs(_M.PROXY_PREFIXES) do proxy_set[p] = true end

-- SECOND_LEVEL_LABELS: the second-level names ccTLD registries sell under
-- (com.gr, co.uk, com.au, …). Under one of them a tenant's OWN registrable
-- domain has three labels (`cpanel.com.gr`, `webmail.co.uk`).
_M.SECOND_LEVEL_LABELS = { "com", "net", "org", "edu", "gov", "co", "ac", "or", "ne", "go", "mil", "nom", "gen", "biz", "info" }

local sld_set = {}
for _, l in ipairs(_M.SECOND_LEVEL_LABELS) do sld_set[l] = true end

-- is_proxy_panel_host("cpanel.example.com") → true. The part after the prefix
-- must be a domain that is NOT itself a bare public suffix. A proxy subdomain
-- always sits on a registrable domain (cpanel.example.gr,
-- cpanel.example.com.gr). A name that is prefix + suffix (`webmail.gr`,
-- `cpanel.com.gr`, `whm.co.uk`) can only be a tenant's OWN domain, and that
-- vhost comes before cPanel's catch-all proxy vhost in Apache's order.
-- Rule: at least three labels, and exactly three only if the middle label is
-- not a second-level name under a two-letter ccTLD. This is a heuristic, not
-- the Public Suffix List. Residual: a tenant domain named like
-- `cpanel.<3rd-level-suffix>`.
function _M.is_proxy_panel_host(host)
  local h = (host or ""):lower()
  local labels = {}
  for l in (h .. "."):gmatch("([^%.]*)%.") do labels[#labels + 1] = l end
  if #labels < 3 or proxy_set[labels[1]] ~= true then return false end
  for i = 1, #labels do
    if labels[i] == "" then return false end -- empty label / trailing dot
  end
  if #labels == 3 and sld_set[labels[2]] and #labels[3] == 2 then return false end
  return true
end

-- proxy_hosts_reach_panel() — on this node, does Apache route EVERY
-- cpanel.*/whm.*/webmail.* Host to cpsrvd? True only when
-- /var/cpanel/cpanel.config has BOTH:
--   * proxysubdomains=1: cPanel installs a catch-all proxy vhost
--     (`ServerAlias cpanel.* whm.* webmail.* …`), so even a Host naming no
--     local domain reaches the panel;
--   * proxysubdomainsoverride=0: tenants cannot create a real subdomain named
--     cpanel./webmail./whm. The cPanel default is 1, which lets a tenant's own
--     `webmail.example.com` vhost (a docroot app) win over the proxy.
-- Anywhere else (DirectAdmin or no panel, proxysubdomains off, override on)
-- a `Host: cpanel.x` can land on a docroot or the default vhost, and the
-- web-edge passthrough would be a WAF bypass into that site, so it stays off.
-- Fail closed: an unreadable/missing file or an absent key reads as off
-- (an absent override key is cPanel's default, 1). Re-read at most once per
-- PROXY_CFG_TTL seconds, by one worker when a shared dict is passed (module
-- state survives requests via package.loaded). The file is 0644 root on cPanel.
_M.CPANEL_CONFIG = "/var/cpanel/cpanel.config"
_M.PROXY_CFG_TTL = 60

local proxy_cfg = { at = nil, on = false }

local function read_proxy_cfg()
  local proxy, override
  local f = io.open(_M.CPANEL_CONFIG, "r")
  if f then
    for line in f:lines() do
      local k, v = line:match("^(proxysubdomains%a*)%s*=%s*(%S*)")
      if k == "proxysubdomains" then proxy = v
      elseif k == "proxysubdomainsoverride" then override = v end
      if proxy and override then break end
    end
    f:close()
  end
  return proxy == "1" and override == "0"
end

-- sh (optional): a shared dict. When given, one worker reads the file per
-- TTL and the others read the dict, so there is no per-worker blocking read.
-- The dict value carries the time of the file read ("1|<t>" / "0|<t>"), and a
-- worker trusts it only until <t> + TTL. So a cpanel.config change reaches
-- every worker within one TTL, not two stacked ones.
function _M.proxy_hosts_reach_panel(now, sh)
  now = now or ((ngx and ngx.now) and ngx.now()) or os.time()
  if proxy_cfg.at and now - proxy_cfg.at < _M.PROXY_CFG_TTL then
    return proxy_cfg.on
  end
  local on, read_at
  if sh then
    local v = sh:get("cfm_cpanel_proxy_reach")
    if type(v) == "string" then
      local bit, t = v:match("^([01])|([%d%.]+)$")
      t = tonumber(t)
      if bit and t and now - t < _M.PROXY_CFG_TTL and t <= now then
        on, read_at = (bit == "1"), t
      end
    end
  end
  if on == nil then
    on, read_at = read_proxy_cfg(), now
    if sh then
      sh:set("cfm_cpanel_proxy_reach", (on and "1|" or "0|") .. tostring(now), _M.PROXY_CFG_TTL)
    end
  end
  proxy_cfg.at, proxy_cfg.on = read_at, on
  return on
end

-- Tests only: forget the cached answer.
function _M._reset_proxy_cfg() proxy_cfg.at, proxy_cfg.on = nil, false end

local function starts_with(s, p)
  return s and p and s:sub(1, #p) == p
end

-- is_session_api(uri) — the /cpsess<N>/ session-token subset: the API, login
-- and websocket calls cPanel's own UI makes (File Manager save/upload, …).
-- It is the ONLY part the web edge passes through (cfm.lua Step 0d). The rest
-- of is_panel_api_or_sso (/api/, /session, /execute/, /json-api/ …) are
-- ordinary app route names; a Host that did not really reach cpsrvd would
-- hand those to a docroot app without the WAF. A `/cpsess<digits>/` path is
-- cPanel's alone.
local SESSION_KINDS = { "json-api", "execute", "xml-api", "login", "websocket" }
_M.SESSION_KINDS = SESSION_KINDS

-- Case-insensitive: the Go decision engine sees only a lowercased URI (its
-- log parser lowercases), so both sides must agree on that. Under Step 0d's
-- gates the request reaches cpsrvd, which rejects a bogus-case path itself.
function _M.is_session_api(uri)
  local kind = (uri or ""):lower():match("^/cpsess%d+/([%a%-]+)/")
  if not kind then return false end
  for _, k in ipairs(SESSION_KINDS) do
    if kind == k then return true end
  end
  return false
end

-- is_panel_api_or_sso(uri) — cPanel/WHM/webmail API, SSO and transfer
-- endpoints. Each one is authenticated by cpsrvd itself (a /cpsess<N>/ token
-- bound to the session cookie, an API token / Authorization header, an SSO
-- assertion, or the transfer session). CFM passes them straight to the
-- panel: no challenge (an XHR cannot solve one; the cPanel UI then reports
-- "Your login session has expired") and no WAF (the File Manager editor save
-- and upload legitimately carry PHP source).
--
-- Single source for BOTH edges: the panel listeners (cfm_panel.lua step 1)
-- and the web edge for a panel proxy host (cfm.lua Step 0d), so
-- cpanel.X:443 and X:2083 treat the same request the same way. There is no
-- other copy; change the list here.
-- `uri` is ngx.var.uri (decoded, dot-segment-normalized) on both sides.
function _M.is_panel_api_or_sso(uri)
  uri = uri or ""
  return starts_with(uri, "/json-api/")
      or starts_with(uri, "/execute/")
      or starts_with(uri, "/xml-api/")
      or starts_with(uri, "/cpanelwebcall")
      or starts_with(uri, "/openid_connect/")
      or _M.is_session_api(uri)
      or uri == "/session"
      or starts_with(uri, "/session/")
      or uri == "/xfercpanel"
      or uri == "/xfercpsess"
      or uri == "/api"
      or starts_with(uri, "/api/")
      -- WHM live-transfer file / rsync streams. cPanel's transfer tool
      -- pulls account archives and tunnels rsync over these endpoints
      -- on port 2087; routing them through the challenge layer breaks
      -- the binary stream with a 300s upstream timeout, which the
      -- receiving side reports as `failed to read up to 64 KB from a
      -- file handle ... Is a directory`.
      or starts_with(uri, "/acctxfer")
      or starts_with(uri, "/cgi/transfer")
      or starts_with(uri, "/cgi/live_tail_log")
end

return _M
