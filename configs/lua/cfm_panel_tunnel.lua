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
-- (third arg = false) because the target is loopback.

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

-- Timeouts: 30s to establish the upstream TCP+TLS handshake, 24h once
-- bytes are flowing. The transfer of a multi-GB home directory over a
-- saturated 100 Mb link can legitimately take several hours, and we
-- don't want to chop it off mid-rsync.
local CONNECT_TIMEOUT_MS = 30 * 1000
local IO_TIMEOUT_MS      = 24 * 60 * 60 * 1000

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
    -- Args: reused_session (nil = always do a fresh handshake), server_name
    -- for SNI, verify (false because target is loopback).
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
local function pump(src, dst, label)
    while true do
        local data, recv_err = src:receiveany(16384)
        if data and #data > 0 then
            local _, snd_err = dst:send(data)
            if snd_err then
                -- "closed" and "broken pipe" are expected at end of
                -- session; don't pollute the error log with them.
                if snd_err ~= "closed" and snd_err ~= "broken pipe" then
                    ngx.log(ngx.NOTICE, "[cfm_panel_tunnel] ", label,
                            " send: ", snd_err)
                end
                return
            end
        end
        if recv_err then
            if recv_err ~= "closed" then
                ngx.log(ngx.NOTICE, "[cfm_panel_tunnel] ", label,
                        " recv: ", recv_err)
            end
            return
        end
    end
end

local co_up   = ngx.thread.spawn(pump, client_sock, up_sock,   "client->upstream")
local co_down = ngx.thread.spawn(pump, up_sock,     client_sock, "upstream->client")

-- ngx.thread.wait returns as soon as ANY of the spawned threads finishes.
-- That's the right behaviour here: rsync's protocol cleanly closes one
-- direction at end-of-session, and once that happens we want to tear the
-- other half down too rather than wait IO_TIMEOUT_MS for it to notice.
ngx.thread.wait(co_up, co_down)

-- Best-effort cleanup. Closing the upstream socket also unblocks any
-- still-pending receive in the partner thread by surfacing a "closed"
-- error to it.
pcall(function() up_sock:close() end)
