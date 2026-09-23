-- cfm_panel_hosts.lua — the canonical list of panel-ish subdomain prefixes.
--
-- Single source of truth consumed by both edge entrypoints (cfm.lua Step 0
-- panel-likeness on the web listeners; cfm_panel.lua has_panel_prefix on the
-- 12xxx panel listeners) and by cfm_cache.lua (Site Cache never caches a panel
-- host). Before this module each file carried its own copy
-- and they drifted: cfm.lua had `mail.` but not `webdisk.`, cfm_panel.lua had
-- `webdisk.` but not `mail.` (CLAUDE.md: never keep a second copy of a
-- list/matcher that can drift). See docs/edge-unification-plan.md §6 Phase 0.
--
-- The two entrypoints pcall-require this module and keep their previous inline
-- list as a fallback, so an upgrade-lag deploy (new cfm.lua, old
-- /var/lib/cfm/lua set) degrades to the old behaviour instead of failing the
-- request path. cfm_cache.lua has no fallback list: without this module it
-- caches nothing (fail closed).

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

return _M
