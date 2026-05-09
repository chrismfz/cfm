#!/usr/bin/env bash
set -euo pipefail

# OpenResty/Angie embed LuaJIT, so this regression check runs the module
# under luajit to match production semantics. If you see this message and
# you're on Debian/Ubuntu: `sudo apt-get install -y luajit`. On Alpine:
# `apk add luajit`. On macOS: `brew install luajit`.
if ! command -v luajit >/dev/null 2>&1; then
  echo "❌ luajit is required for this check but was not found in PATH." >&2
  echo "   Install it (Debian/Ubuntu: apt-get install luajit) and retry." >&2
  exit 127
fi

luajit -e '
  package.path = "configs/lua/?.lua;" .. package.path
  local expected = "b82fcb791acec57859b989b430a826488ce2e479fdf92326bd0a2e8375a42ba4"
  local payload_token = "eyJ2IjoiMSIsImV4cCI6NDA3MDkwODgwMCwiaXAiOiIxLjIuMy40IiwiaG9zdCI6ImV4YW1wbGUuY29tIiwic2NvcGUiOiJ3ZWIiLCJub25jZSI6Im4iLCJobWFjIjoiYjgyZmNiNzkxYWNlYzU3ODU5Yjk4OWI0MzBhODI2NDg4Y2UyZTQ3OWZkZjkyMzI2YmQwYTJlODM3NWE0MmJhNCJ9"

  local function run_common_asserts(clearance)
    local ok1, why1 = clearance.validate("not-base64url", "1.2.3.4", "example.com", "web", "secret")
    if ok1 ~= false or why1 ~= "bad_sig" then
      error("expected malformed token to fail with bad_sig")
    end

    local ok2, why2 = clearance.validate("e30", "1.2.3.4", "example.com", "web", "secret")
    if ok2 ~= false or why2 ~= "bad_sig" then
      error("expected valid-like token to fail with bad_sig")
    end
  end

  local function reload_clearance()
    package.loaded["cfm_clearance"] = nil
    return require("cfm_clearance")
  end

  local function decode_obj(raw)
    if raw == "{}" then return {} end
    if raw == "{\"v\":\"1\",\"exp\":4070908800,\"ip\":\"1.2.3.4\",\"host\":\"example.com\",\"scope\":\"web\",\"nonce\":\"n\",\"hmac\":\"" .. expected .. "\"}" then
      return { v = "1", exp = 4070908800, ip = "1.2.3.4", host = "example.com", scope = "web", nonce = "n", hmac = expected }
    end
    return nil
  end
  package.preload["cjson.safe"] = function()
    return { decode = decode_obj }
  end
  package.preload["cjson"] = function()
    return { decode = decode_obj }
  end

  _G.ngx = {
    decode_base64 = function(s)
      if s == payload_token then
        return "{\"v\":\"1\",\"exp\":4070908800,\"ip\":\"1.2.3.4\",\"host\":\"example.com\",\"scope\":\"web\",\"nonce\":\"n\",\"hmac\":\"" .. expected .. "\"}"
      end
      return nil
    end,
    time = function() return 0 end,
    hmac_sha256 = function() return "\184/\203y\26\206\197xY\185\137\1800\168&H\140\226\228y\253\249#&\189\n.\131u\164+\164" end,
  }
  local clearance = reload_clearance()
  run_common_asserts(clearance)
  local ok_native, why_native = clearance.validate(payload_token, "1.2.3.4", "example.com", "web", "secret")
  if ok_native ~= true or why_native ~= "ok" then
    error("expected ngx.hmac_sha256 backend to validate token")
  end

  _G.ngx.hmac_sha256 = nil
  package.preload["resty.openssl.hmac"] = function()
    return {
      new = function(secret, algorithm)
        if secret ~= "secret" or algorithm ~= "sha256" then return nil end
        local st = { data = "" }
        function st:update(chunk) self.data = self.data .. chunk end
        function st:final()
          if self.data == "1|4070908800|1.2.3.4|example.com|web|n" then
            return "\184/\203y\26\206\197xY\185\137\1800\168&H\140\226\228y\253\249#&\189\n.\131u\164+\164"
          end
          return ""
        end
        return st
      end,
    }
  end
  clearance = reload_clearance()
  local ok_fallback, why_fallback = clearance.validate(payload_token, "1.2.3.4", "example.com", "web", "secret")
  if ok_fallback ~= true or why_fallback ~= "ok" then
    error("expected resty.openssl.hmac fallback backend to validate token")
  end

  package.preload["resty.openssl.hmac"] = nil
  package.loaded["resty.openssl.hmac"] = nil
  clearance = reload_clearance()
  local ok_none, why_none = clearance.validate(payload_token, "1.2.3.4", "example.com", "web", "secret")
  if ok_none ~= false or why_none ~= "crypto_unavailable" then
    error("expected explicit crypto_unavailable when no HMAC backend is present")
  end
'
echo "OK: cfm_clearance HMAC backend compatibility and deterministic digest checks"
