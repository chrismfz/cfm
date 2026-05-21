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
--   /acctxferrsync     — cPanel WHM live-transfer rsync stream (homedir)
--   /acctxferdsync     — cPanel WHM live-transfer doveadm sync stream
--                        (mail accounts via dsync_cpsrvd_client). Same
--                        protocol shape as rsync — GET with binary body
--                        on the same socket — so it hits the same
--                        "nginx parses GET as bodyless, never reads
--                        client protocol bytes" pathology if proxied
--                        through the normal HTTP path.
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

-- Step 3: replay the original HTTP request to upstream.
--
-- We DO NOT simply forward ngx.req.raw_header() verbatim. cpsrvd uses
-- X-Forwarded-For (set by the regular nginx proxy_set_header on every
-- other panel location) to attach an incoming request to its transfer-
-- session bookkeeping. Without it, cpsrvd sees the request as coming
-- from the loopback nginx (127.0.0.1), processes the rsync stream
-- correctly but skips the post-completion handshake — and the cPanel
-- client (whm_xfer_download-ssl) on the destination sits in poll()
-- forever waiting for a session-end marker that never arrives, which
-- shows up as "Restore stuck at 20% Homedir" with the connection
-- visibly ESTAB on both sides and zero bytes flowing.
--
-- So splice an X-Forwarded-For / X-Real-IP / X-Forwarded-Proto /
-- X-Forwarded-Host / X-Forwarded-Port set into the original headers,
-- matching what the sibling `location ~ ^/(acctxfer|...)` block does
-- via proxy_set_header. If the client already sent any of these we
-- preserve them (don't double-inject).
local raw_headers = ngx.req.raw_header()

local client_ip      = ngx.var.remote_addr  or "127.0.0.1"
local client_host    = ngx.var.host         or "localhost"
local listener_port  = ngx.var.server_port  or ""
local listener_proto = ngx.var.scheme       or "https"

-- Lowercase header-name index of what the client already sent, so we
-- can avoid re-injecting headers they already provided.
local got = {}
for line in raw_headers:gmatch("[^\r\n]+") do
    local name = line:match("^([%w%-]+)%s*:")
    if name then got[name:lower()] = true end
end

local function maybe_add(name, value)
    if not got[name:lower()] and value and value ~= "" then
        return name .. ": " .. value .. "\r\n"
    end
    return ""
end

local injected =
    maybe_add("X-Real-IP",          client_ip) ..
    maybe_add("X-Forwarded-For",    client_ip) ..
    maybe_add("X-Forwarded-Host",   client_host) ..
    maybe_add("X-Forwarded-Port",   listener_port) ..
    maybe_add("X-Forwarded-Proto",  listener_proto) ..
    maybe_add("X-Forwarded-Server", client_host) ..
    maybe_add("CF-Connecting-IP",   client_ip)

-- raw_headers ends with "\r\n\r\n". Strip the final "\r\n" so we get
-- the headers ending in a single "\r\n", append our injected lines
-- (each already ending in "\r\n"), then append the final "\r\n" that
-- terminates the header block.
local request_to_upstream
if raw_headers:sub(-4) == "\r\n\r\n" then
    request_to_upstream = raw_headers:sub(1, -3) .. injected .. "\r\n"
else
    -- Defensive: header block didn't terminate as expected; just
    -- append and hope for the best (cpsrvd will reject malformed
    -- requests, which is the safe failure mode).
    request_to_upstream = raw_headers .. injected .. "\r\n"
end

local _, send_err = up_sock:send(request_to_upstream)
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

-- Wait for the FIRST direction to finish. Once either side EOFs the tunnel
-- is semantically complete — the HTTP/1.0 transport the client used keys
-- on a TCP close to signal "response complete", so we must propagate that
-- close in the opposite direction or the client (e.g. cPanel's
-- whm_xfer_download-ssl) sits forever waiting for an HTTP response that
-- has already finished at the byte level.
--
-- Empirically observed (paired-host packet+socket capture, run B):
-- after cpsrvd FINed its loopback half, both lo:openresty<->cpsrvd
-- sockets walked all the way through CLOSED within ~2s, but the
-- external rigel <-> earth:12087 socket stayed ESTABLISHED with
-- Recv-Q=0/Send-Q=0 for the full 2+ minutes until the capture was
-- stopped — i.e. nginx never sent FIN downstream even though the
-- handler called client_sock:close(). On the destination side
-- whm_xfer_download-ssl was blocked in read(fd=4) on that idle
-- socket, which is the "16% / 20% Homedir" hang fingerprint.
--
-- Root cause: client_sock and up_sock are each touched by BOTH pump
-- coroutines (one reads, one writes). lua-nginx-module's cosocket
-- contract is "one cosocket per thread at a time"; in practice the
-- pump itself works because the two ops are independent, but the
-- cleanup path is undefined. With one pump dead and the other still
-- inside client_sock:receiveany(), calling :close() on that same
-- cosocket from the entry thread is not enough to release nginx's
-- underlying connection — the TCP socket stays open until a
-- keepalive timeout, which is hours.
--
-- Fix: tear down in an order that's defined.
--   1. Close up_sock first. The dead pump is already gone, and the
--      surviving pump is blocked on client_sock (not up_sock), so
--      this close has no thread-collision issue.
--   2. Explicitly ngx.thread.kill() any still-alive sub-thread. This
--      is the cosocket-safe way to break out of receiveany() before
--      we touch the shared client cosocket. It is a no-op on the
--      already-exited pump.
--   3. THEN close client_sock and finalize with ngx.exit(444). 444
--      is nginx's "close connection without response" status; after
--      a socket(true) hijack the normal handler-exit close path is
--      what's been leaving the downstream socket pinned, so we
--      force the connection teardown explicitly instead of relying
--      on it.
local ok, wait_err = ngx.thread.wait(co_up, co_down)
if not ok then
    ngx.log(ngx.WARN, "[cfm_panel_tunnel] first pump aborted with lua error: ", tostring(wait_err))
end

pcall(function() up_sock:close() end)

pcall(function() ngx.thread.kill(co_up)   end)
pcall(function() ngx.thread.kill(co_down) end)

pcall(function() client_sock:close() end)
ngx.log(ngx.WARN, "[cfm_panel_tunnel] done uri=", ngx.var.request_uri or "-")
return ngx.exit(444)
