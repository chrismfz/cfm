#!/usr/bin/env bash
set -euo pipefail

luajit -e '
  package.path = "configs/?.lua;" .. package.path
  package.preload["cjson.safe"] = function()
    return {
      decode = function(raw)
        if raw == "{}" then return {} end
        return nil
      end,
    }
  end
  _G.ngx = {
    decode_base64 = function(_) return nil end,
    time = function() return 0 end,
    hmac_sha256 = function() return "" end,
  }
  local clearance = require("cfm_clearance")
  local ok1, why1 = clearance.validate("not-base64url", "1.2.3.4", "example.com", "web", "secret")
  if ok1 ~= false or why1 ~= "bad_sig" then
    error("expected malformed token to fail with bad_sig")
  end

  local token = "e30"
  local ok2, why2 = clearance.validate(token, "1.2.3.4", "example.com", "web", "secret")
  if ok2 ~= false or why2 ~= "bad_sig" then
    error("expected valid-like token to fail with bad_sig")
  end
'
echo "OK: require('cfm_clearance') and validate() handle malformed/valid-like tokens without global nil access"
