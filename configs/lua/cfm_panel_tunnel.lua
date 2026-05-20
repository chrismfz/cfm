-- /var/lib/cfm/lua/cfm_panel_tunnel.lua
--
-- Raw TCP/TLS tunnel for panel endpoints that don't follow standard HTTP
-- request/response semantics.
--
-- ──────────────────────────────────────────────────────────────────────
-- WHY THIS FILE EXISTS
-- ──────────────────────────────────────────────────────────────────────
--
-- cPanel's WHM transfer tool tunnels rsync over HTTPS via the
-- /usr/local/cpanel/bin/whm_xfer_download-ssl helper. The helper opens a
-- single HTTPS connection to the source server's port 2087 and issues:
--
--     GET /acctxferrsync/<account>?rsync_command=[...] HTTP/1.1
--
-- ...and then keeps writing rsync protocol bytes on the same socket as if
-- the GET had a request body. By HTTP/1.1 spec, GET has no body, so nginx
-- / Angie / OpenResty — being correct HTTP servers — read the GET headers,
-- consider the request complete, and never read further bytes from the
-- client until they start emitting the response. cpsrvd, when reached
-- directly (no proxy in front), happily accepts this non-standard usage
-- because it's a multi-protocol daemon that treats /acctxferrsync as a
-- bidirectional byte pipe after the GET line.
--
-- Symptom observed in the wild when this protocol mismatch is in play:
--
--     rsync: connection unexpectedly closed (0 bytes received so far)
--     rsync error: error in rsync protocol data stream (code 12)
--
-- ...and at the socket level (`ss -tnp`), nginx's Recv-Q on the client
-- socket steadily grows because client bytes are pooling in the kernel
-- buffer with no nginx worker draining them. proxy_request_buffering off,
-- longer timeouts, Connection: "", Upgrade headers — none of those help.
-- It is a protocol-layer mismatch, not a config knob.
--
-- ──────────────────────────────────────────────────────────────────────
-- WHAT THIS FILE DOES
-- ──────────────────────────────────────────────────────────────────────
--
-- It bypasses the HTTP request/response state machine entirely by:
--
--   1. Hijacking the raw client TCP socket via ngx.req.socket(true).
--      After this call, no further HTTP parsing happens on that socket;
--      we own the bytes.
--   2. Opening a TCP cosocket to the panel origin (e.g. 127.0.0.1:2087),
--      doing the TLS handshake if the origin is https://.
--   3. Replaying the original request line + headers (ngx.req.raw_header)
--      to the upstream, so cpsrvd sees the same GET /acctxferrsync/...?
--      with the same Host/UA/etc. as the client sent.
--   4. Spawning two ngx.thread cosockets — one for each direction — that
--      pump bytes between client and upstream until either side closes.
--
-- The shape is essentially the same as an HTTP CONNECT proxy, except we
-- forward the original GET request instead of swallowing it, because the
-- upstream needs to see the URL (it carries the account name and the
-- rsync command list).
--
-- ──────────────────────────────────────────────────────────────────────
-- HOW TO ADD MORE ENDPOINTS
-- ──────────────────────────────────────────────────────────────────────
--
-- This script is generic. It reads $cfm_panel_origin (already set per
-- listener block) and forwards whatever the client sent. To tunnel a
-- new URI, just add it to the regex of the location that calls this
-- file in configs/cfm-panel-listeners.conf.in:
--
--   location ~ ^/(acctxferrsync|some_other_weird_endpoint) {
--       content_by_lua_file /var/lib/cfm/lua/cfm_panel_tunnel.lua;
--   }
--
-- Currently tunneled:
--   /acctxferrsync     — cPanel WHM live-transfer rsync stream
--
-- Candidates if you ever hit the same symptom on other panels:
--   - DirectAdmin admin-area transfer endpoints that do bidirectional
--     HTTP (e.g. CMD_ADMIN_BACKUP /... live restore streams)
--   - Plesk migration streams
--   - Any custom panel that violates HTTP semantics on a single TCP
--     socket (GET-with-body, or post-headers protocol switch without
--     an HTTP/1.1 Upgrade)
--
-- ──────────────────────────────────────────────────────────────────────
-- SECURITY NOTES
-- ──────────────────────────────────────────────────────────────────────
--
-- This bypass tunnel does not invoke cfm_panel.lua's challenge logic.
-- That is intentional: these endpoints are already on the panel-API
-- bypass list (see is_panel_api_or_sso() in cfm_panel.lua) because they
-- carry binary / streaming protocols that the challenge layer cannot
-- safely wrap. Authentication is enforced by cpsrvd itself via session
-- IDs in the URL (e.g. /cpsess<digits>/...) or via the WHM access-hash
-- the transfer tool presents. The tunnel only relaxes nginx's HTTP
-- enforcement; it does not weaken upstream auth.
--
-- The upstream we connect to is whatever $cfm_panel_origin resolves to
-- — by construction in the listener template this is always 127.0.0.1
-- on a panel port. The sslhandshake() call below skips cert verification
-- (third arg = false) because the target is loopback; we assert that
-- precondition explicitly below so a future template change that points
-- $cfm_panel_origin off-host cannot silently become a MITM hole.
--
-- Limitations worth knowing about:
--   * ngx.req.socket(true) does not work for HTTP/2 streams. These panel
--     listeners use HTTP/1.1 (no `http2` on `listen`); if h2 is ever
--     enabled, this handler will return 500 and we'll need a separate
--     fix path (probably an h2-aware upstream module or stream-level
--     SNI routing).
--   * We forward the client's headers as-is and do NOT inject
--     X-Forwarded-For / X-Real-IP. cpsrvd will see the request as
--     originating from 127.0.0.1 in its audit log. For /acctxferrsync
--     this is fine — cpsrvd authenticates via the WHM access-hash in
--     the URL, not the client IP — but it's a behavioral difference
--     from the regular HTTP-proxied panel paths.

-- Loopback hosts we are willing to talk to with TLS verification skipped.
-- Anything else must fail closed (see sslhandshake() below). The parser
-- below extracts whatever the operator put in $cfm_panel_origin; this
-- table is the post-parse allowlist that locks the security claim down,
-- so trailing-dot ("127.0.0.1."), trailing-whitespace, userinfo
-- ("user@127.0.0.1"), or any other normalization weirdness that slips
-- through the regex is rejected.
local LOOPBACK_HOSTS = {
    ["127.0.0.1"] = true,
    ["localhost"] = true,
    ["::1"]       = true,
}

local origin = ngx.var.cfm_panel_origin or ""
local scheme, host, port_str = origin:match("^(https?)://([^:/]+):?(%d*)$")
if scheme == nil then
    ngx.log(ngx.ERR, "[cfm_panel_tunnel] invalid cfm_panel_origin: ", origin)
    return ngx.exit(500)
end
local is_ssl = (scheme == "https")
local port = tonumber(port_str)
if port == nil or port == 0 then
    port = is_ssl and 443 or 80
end

-- Timeouts:
--   * 30s to establish the upstream TCP+TLS handshake.
--   * 1h gap-between-bytes during the transfer (read AND send). Real
--     rsync streams transmit data continuously when healthy; gaps of
--     hours indicate something is broken end-to-end. 1h also bounds
--     worst-case worker pinning if one direction hangs while the
--     other has already exited.
--
-- Note on bidirectional shutdown: we do NOT impose a separate shorter
-- "drain" timeout once one direction has finished. An earlier version
-- did, but it killed real rsync transfers — when the rsync ack stream
-- from the receiver finishes quickly, the sender side can legitimately
-- pause for minutes while it walks the file tree on the source disk
-- building the incremental file list. The dominant direction
-- (upstream → client carrying file data) must remain on the full
-- IO_TIMEOUT_MS so a slow enumerator doesn't get truncated. The 1h
-- IO timeout itself is the bound on hung-channel exposure.
local CONNECT_TIMEOUT_MS = 30 * 1000
local IO_TIMEOUT_MS      = 60 * 60 * 1000

-- Step 1: hijack the raw client socket. After this point, nginx will not
-- touch the request body or response on this connection; we own it.
local client_sock, sock_err = ngx.req.socket(true)
if not client_sock then
    ngx.log(ngx.ERR, "[cfm_panel_tunnel] ngx.req.socket(true) failed: ", sock_err)
    return ngx.exit(500)
end
client_sock:settimeouts(CONNECT_TIMEOUT_MS, IO_TIMEOUT_MS, IO_TIMEOUT_MS)

-- Step 2: open the upstream TCP cosocket and TLS-handshake if needed.
local up_sock = ngx.socket.tcp()
up_sock:settimeouts(CONNECT_TIMEOUT_MS, IO_TIMEOUT_MS, IO_TIMEOUT_MS)

local ok, conn_err = up_sock:connect(host, port)
if not ok then
    ngx.log(ngx.ERR, "[cfm_panel_tunnel] upstream connect ", host, ":", port,
            " failed: ", conn_err)
    return ngx.exit(502)
end

if is_ssl then
    -- Defence-in-depth: verify=false is only safe when the upstream is
    -- loopback. If a future template change ever points $cfm_panel_origin
    -- at a non-loopback host, refuse to proceed rather than silently
    -- accept any cert. Check the *parsed* host against a strict allowlist
    -- so trailing dots, whitespace, userinfo, or other regex quirks that
    -- slip through the origin parser cannot bypass the assertion.
    if not LOOPBACK_HOSTS[host] then
        ngx.log(ngx.ERR, "[cfm_panel_tunnel] refusing to skip TLS verification for non-loopback origin: ", origin)
        pcall(function() up_sock:close() end)
        return ngx.exit(500)
    end
    -- Args: reused_session (nil = always do a fresh handshake), server_name
    -- for SNI, verify (false because target is loopback per the guard above).
    local session, hs_err = up_sock:sslhandshake(nil, host, false)
    if not session then
        ngx.log(ngx.ERR, "[cfm_panel_tunnel] upstream sslhandshake failed: ", hs_err)
        pcall(function() up_sock:close() end)
        return ngx.exit(502)
    end
end

-- Step 3: replay the original HTTP request line + headers to upstream.
-- ngx.req.raw_header() returns the bytes nginx received from the client
-- up to and including the final CRLF CRLF, which is exactly what cpsrvd
-- needs to know which endpoint we're targeting (URL has the account name
-- and the rsync_command JSON array).
local raw_headers = ngx.req.raw_header()
local _, send_err = up_sock:send(raw_headers)
if send_err then
    ngx.log(ngx.ERR, "[cfm_panel_tunnel] forward request headers: ", send_err)
    pcall(function() up_sock:close() end)
    return ngx.exit(502)
end

-- Step 4: bidirectional pump. Each direction runs in its own ngx.thread
-- so the two reads don't block each other. receiveany(N) blocks until at
-- least one byte is available and returns up to N bytes — this is the
-- right primitive for streaming, unlike receive(N) which insists on the
-- full N bytes before returning.
--
-- Per-direction byte counter is logged at exit so operators can
-- correlate "transfer stuck after X MB" in the rsync output with
-- "pump <direction> exited after N bytes <reason>" in error.log. Log
-- level WARN so the message lands in the default openresty/angie
-- error_log (which ships at "warn"); NOTICE would be silently dropped.
local function pump(src, dst, label)
    local bytes = 0
    while true do
        local data, recv_err = src:receiveany(16384)
        if data and #data > 0 then
            bytes = bytes + #data
            local _, snd_err = dst:send(data)
            if snd_err then
                ngx.log(ngx.WARN, "[cfm_panel_tunnel] ", label,
                        " send error after ", bytes, " bytes: ", snd_err)
                return bytes
            end
        end
        if recv_err then
            local reason = (recv_err == "closed") and "peer closed" or recv_err
            ngx.log(ngx.WARN, "[cfm_panel_tunnel] ", label,
                    " ended after ", bytes, " bytes: ", reason)
            return bytes
        end
    end
end

ngx.log(ngx.WARN, "[cfm_panel_tunnel] start uri=", ngx.var.request_uri or "-",
        " upstream=", host, ":", port, " ssl=", tostring(is_ssl))

local co_up = ngx.thread.spawn(pump, client_sock, up_sock, "client->upstream")
if not co_up then
    ngx.log(ngx.ERR, "[cfm_panel_tunnel] ngx.thread.spawn client->upstream failed")
    pcall(function() up_sock:close() end)
    return ngx.exit(500)
end
local co_down = ngx.thread.spawn(pump, up_sock, client_sock, "upstream->client")
if not co_down then
    ngx.log(ngx.ERR, "[cfm_panel_tunnel] ngx.thread.spawn upstream->client failed")
    -- co_up is already running; closing up_sock surfaces a "closed" error
    -- to its receive and lets it exit cleanly before we leave the handler.
    pcall(function() up_sock:close() end)
    ngx.thread.wait(co_up)
    return ngx.exit(500)
end

-- Wait for the first direction to finish. ngx.thread.wait returns
-- (false, err) on Lua runtime error in the awaited thread; we log but
-- keep going because the other direction still needs to drain.
local ok, wait_err = ngx.thread.wait(co_up, co_down)
if not ok then
    ngx.log(ngx.WARN, "[cfm_panel_tunnel] first pump aborted with lua error: ", tostring(wait_err))
end

-- Then wait for the OTHER direction to finish on its own. Earlier
-- iterations of this code applied a shorter DRAIN_TIMEOUT here so a
-- hung half-channel couldn't pin a worker for IO_TIMEOUT_MS — but that
-- broke real rsync transfers, because the dominant data direction
-- (upstream → client) can legitimately pause for minutes while the
-- source side enumerates files. Leave both sockets on the original
-- IO_TIMEOUT_MS (1h) — that's the bound on hung-channel exposure and
-- it's well above any legitimate rsync gap-between-bytes.
--
-- ngx.thread.wait on an already-finished thread returns its result
-- immediately, so calling it on whichever finished first is a no-op.
local ok_up, err_up = ngx.thread.wait(co_up)
if not ok_up then
    ngx.log(ngx.WARN, "[cfm_panel_tunnel] client->upstream pump aborted with lua error: ", tostring(err_up))
end
local ok_down, err_down = ngx.thread.wait(co_down)
if not ok_down then
    ngx.log(ngx.WARN, "[cfm_panel_tunnel] upstream->client pump aborted with lua error: ", tostring(err_down))
end

-- Best-effort cleanup. The client socket is closed by nginx when the
-- content phase returns.
pcall(function() up_sock:close() end)
ngx.log(ngx.WARN, "[cfm_panel_tunnel] done uri=", ngx.var.request_uri or "-")
