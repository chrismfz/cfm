-- configs/lua/cfm_hostmatch.lua
--
-- Shared host normalization + the minimal glob matcher used by the edge modules
-- that key per-vhost policy on a normalized host (cfm_h3_config.lua,
-- cfm_cache.lua, …). These functions were duplicated verbatim across those
-- modules; per CLAUDE.md §5 ("never keep a second copy of a list/matcher that
-- can drift") they live here once so every consumer agrees on the host key and
-- the supported pattern class.
--
-- Pure Lua: no ngx, no cjson, no I/O — trivially unit-testable
-- (scripts/tests/cfm_hostmatch_test.lua).
--
-- Supported pattern class (kept in step with the Go stores' normalize():
-- http3_overrides_store.go / site_cache.go): an EXACT host and a single
-- "*.suffix" wildcard only. Anything richer (`?`, `[abc]`, mid-pattern `*`) is
-- rejected by is_supported_pattern so a consumer never routes a pattern this
-- matcher cannot honor.

local _M = {}

-- normalize_host: lowercase, strip a trailing dot, strip an optional port.
-- IPv6-aware: `[::1]:443` and `[2001:db8::1]` keep their brackets and inner
-- colons; only a trailing `:port` outside the brackets is stripped.
function _M.normalize_host(raw)
    local h = string.lower(tostring(raw or ""))
    if h == "" then return "" end
    if h:sub(-1) == "." then h = h:sub(1, -2) end
    if h:sub(1, 1) == "[" then
        -- IPv6 literal. Keep everything up to the closing bracket; strip a
        -- trailing ":port" after it if present.
        local close = h:find("]", 1, true)
        if close then
            return h:sub(1, close)
        end
        return h
    end
    -- IPv4 / hostname. Strip ":port" if present.
    local colon = h:find(":", 1, true)
    if colon then h = h:sub(1, colon - 1) end
    return h
end

-- glob_match: minimal subset of shell glob — exact host and "*.suffix.tld".
function _M.glob_match(pattern, host)
    if pattern == host then return true end
    if pattern:sub(1, 2) == "*." then
        local suffix = pattern:sub(2)  -- ".example.com"
        if #host >= #suffix and host:sub(-#suffix) == suffix then
            return true
        end
    end
    return false
end

-- is_supported_pattern: true for an exact host or a single "*.suffix" wildcard
-- only. Anything the local glob_match cannot honor returns false, so callers can
-- drop (and warn about) a pattern rather than silently never matching it.
function _M.is_supported_pattern(p)
    if not p:find("*", 1, true) and not p:find("?", 1, true) and not p:find("[", 1, true) then
        return true  -- exact host
    end
    if p:sub(1, 2) == "*." and not p:sub(3):find("*", 1, true)
       and not p:find("?", 1, true) and not p:find("[", 1, true) then
        return true  -- "*.suffix" only
    end
    return false
end

return _M
