-- Panel-specific CFM guard/router for cPanel/WHM/Webmail ports.
local function log_block(reason)
    ngx.log(ngx.WARN, "CFM_PANEL block reason=", reason, " ip=", ngx.var.remote_addr or "-", " host=", ngx.var.host or "-", " uri=", ngx.var.request_uri or "-", " ua=", ngx.var.http_user_agent or "-")
end
local function deny(reason) log_block(reason); return ngx.exit(ngx.HTTP_FORBIDDEN) end
local function starts_with(s,p) return s and p and s:sub(1,#p)==p end
local function run_basic_guard()
    local auth = ngx.var.http_authorization or ""
    local b64 = auth:match("^[Bb]asic%s+(.+)$")
    if not b64 then return true end
    local decoded = ngx.decode_base64(b64)
    if not decoded then return nil, "basic_bad_base64" end
    if decoded:find("\r",1,true) or decoded:find("\n",1,true) then return nil, "basic_decoded_crlf" end
    if decoded:find("\0",1,true) then return nil, "basic_decoded_nul" end
    if #decoded > 4096 then return nil, "basic_decoded_too_large" end
    return true
end
local ok, reason = run_basic_guard(); if not ok then return deny(reason) end
local uri = ngx.var.uri or "/"; local auth = ngx.var.http_authorization or ""; local origin = ngx.var.cfm_panel_origin or ""
if origin == "" then return deny("panel_origin_empty") end
local is_api = starts_with(uri, "/json-api/") or starts_with(uri, "/execute/") or uri == "/json-api/cpanel" or starts_with(uri, "/json-api/cpanel/")
if starts_with(uri, "/cpanelwebcall") or (is_api and (auth:match("^whm%s+") or auth:match("^cpanel%s+") or auth:match("^[Bb]asic%s+"))) then ngx.var.cfm_pass = origin; ngx.var.cfm_upstream = "cfm_panel_api"; return end
ngx.var.cfm_pass = origin; ngx.var.cfm_upstream = "cfm_panel_origin"; return
