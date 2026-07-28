-- cfm_tlsfp.lua — stamp a summary of the client's TLS ClientHello onto the
-- request the edge forwards to the CFM daemon.
--
-- WHY THIS EXISTS
--
-- Every other signal on a challenge solve is written by the client: the
-- User-Agent, the cookies, the PoW solution, even the timing. The TLS handshake
-- is written by its TLS stack before a byte of HTTP is sent. So a client
-- claiming "Chrome/118" whose handshake does not look like Chrome's is lying in
-- a way it cannot fix by editing a header — and the solver farm we are looking
-- at sends one exact User-Agent for 100% of its solves.
--
-- WHAT THIS IS NOT
--
-- A poor-man's JA3, not a JA4. nginx exposes the cipher suites and curves the
-- client offered, the negotiated protocol and ALPN — but not the extension list
-- or its order, which is what a real JA4 hashes. That needs a module or a
-- patched edge; this needs nothing, which is why it goes first.
--
-- LOG-FIRST. Nothing decides on this value. It is stamped so the daemon can
-- record it beside the UA and the solve latency, and so the fingerprint↔UA
-- mapping can be DERIVED FROM REAL TRAFFIC later. Do not turn it into a rule
-- from a hand-written table of "what Chrome 118 looks like" — that is the exact
-- mistake internal/uaplausible's doc comment warns about.
-- See docs/roadmaps/challenge-engine.md.

local M = {}

local HEADER  = "X-CFM-TLS"
local VERSION = "1"

-- Chrome offers ~15 cipher suites and OpenSSL renders those as names, so a
-- browser list runs a few hundred characters. A stack that offers the whole
-- OpenSSL default set runs far longer: Meta's crawler was measured at over 512
-- bytes of ciphers alone in production on 2026-07-28, which the previous bound
-- cut mid-name ("...:ECDHE-RSA-AES256-S"). So these are NOT "above anything a
-- real stack sends" — they are a backstop, and truncation is a thing that
-- happens and must be legible. MAX_TOTAL must stay <= internal/tlsfp.maxHeader,
-- which rejects anything longer outright.
local MAX_FIELD = 1024
local MAX_TOTAL = 2048

-- TRUNC_MARK is appended as its own token when a field had to be cut, for two
-- reasons. It keeps a truncated list from hashing equal to a client that
-- genuinely offered exactly that shorter list, and it makes the cut visible in
-- the log instead of something a reader has to infer from a value that happens
-- to sit on the bound.
local TRUNC_MARK = "TRUNC"

-- getvar reads an nginx variable without ever raising. $ssl_curves needs
-- OpenSSL 1.0.2+ and $ssl_alpn_protocol needs nginx 1.21.4+; on an older edge
-- those names simply do not exist. Reading them through pcall degrades to an
-- empty field instead of taking the verify endpoint down, and — unlike naming
-- them in a proxy_set_header — it cannot stop the edge from starting at all.
local function getvar(name)
  local ok, v = pcall(function() return ngx.var[name] end)
  if not ok then return nil end
  return v
end

-- clean restricts a field to the characters nginx can legitimately produce
-- here. That is what guarantees the value cannot smuggle CR/LF (header
-- splitting) or the "|" field separator into the daemon's parser.
local function clean(v)
  if v == nil then return "" end
  v = tostring(v)
  if v == "" or v == "-" then return "" end
  v = v:gsub("[^%w%.%-%_%:%/%,%+]", "")
  if #v > MAX_FIELD then
    -- Cut on a ":" boundary so half a cipher name never becomes a token. A
    -- partial name is worse than a missing one: it looks like a cipher, it
    -- differs between two clients that offered the same list under different
    -- bounds, and it silently invents a fingerprint nobody can look up.
    local cut = v:sub(1, MAX_FIELD - #TRUNC_MARK - 1)
    local sep = cut:match("^.*()%:")
    if sep then cut = cut:sub(1, sep - 1) end
    v = cut .. ":" .. TRUNC_MARK
  end
  return v
end

-- value returns the versioned tuple, or nil when there is nothing to describe
-- (a plain-HTTP request has no handshake).
--
-- Field order is part of the wire format and is parsed positionally by
-- internal/tlsfp — append, never reorder, and bump VERSION if the meaning of an
-- existing field changes.
--
--   1 version
--   2 $ssl_protocol          negotiated TLS version
--   3 $ssl_ciphers           cipher suites the CLIENT offered
--   4 $ssl_curves            curves the CLIENT offered
--   5 $ssl_alpn_protocol     negotiated ALPN
--   6 $server_protocol       HTTP/2.0 or HTTP/1.1
--   7 $ssl_session_reused    "r" when the session was resumed — on a resumed
--                            handshake fields 3/4 can be thin, so a reader must
--                            be able to tell that apart from a strange client
function M.value()
  local proto = clean(getvar("ssl_protocol"))
  if proto == "" then return nil end
  local v = table.concat({
    VERSION,
    proto,
    clean(getvar("ssl_ciphers")),
    clean(getvar("ssl_curves")),
    clean(getvar("ssl_alpn_protocol")),
    clean(getvar("server_protocol")),
    clean(getvar("ssl_session_reused")),
  }, "|")
  if #v > MAX_TOTAL then v = v:sub(1, MAX_TOTAL) end
  return v
end

-- stamp replaces the header on the request being proxied to the daemon.
--
-- The clear is not optional: this header is edge-generated, and a request that
-- arrives already carrying one is a client trying to choose its own
-- fingerprint. Clearing first means the daemon sees an edge value or nothing.
function M.stamp()
  ngx.req.clear_header(HEADER)
  local v = M.value()
  if v then ngx.req.set_header(HEADER, v) end
end

return M
