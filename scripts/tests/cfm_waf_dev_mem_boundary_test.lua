-- Rule 324 (rootkit artifacts) matched `/dev/mem` as a substring, so a path
-- such as `/dev/members.db` was challenged (edge Lua sweep 2026-10-09, seen
-- on earth). `/dev/mem` and `/dev/kmem` now match as whole names.
_G.ngx = { now = function() return 1000 end, decode_base64 = function() return nil end,
           log = function() end, ERR = 0, WARN = 1, INFO = 2 }
package.path = "configs/lua/?.lua;" .. package.path
require("cfm_waf")
local det = require("cfm_waf_detectors")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
local function hit(uri, args, body) return det.detect_rootkit_artifacts(uri, args or "", body or "") end

check(hit("/dev/members.db") == nil, "/dev/members.db is not /dev/mem")
check(hit("/x", "f=/dev/memory_report.pdf") == nil, "/dev/memory_report.pdf is not /dev/mem")
check(hit("/x", "", "path=/dev/kmemcache_notes") == nil, "/dev/kmemcache_notes is not /dev/kmem")
check(hit("/x", "cmd=dd+if%3D/dev/mem+bs%3D1") == "DEV_MEM_ACCESS", "dd if=/dev/mem is DEV_MEM_ACCESS")
check(hit("/x", "f=/dev/mem") == "DEV_MEM_ACCESS", "/dev/mem at the end")
check(hit("/x", "", "cat /dev/kmem | strings") == "DEV_KMEM_ACCESS", "/dev/kmem in a body")
check(hit("/x", "a=/dev/members&b=/dev/mem;") == "DEV_MEM_ACCESS", "a later whole /dev/mem after a /dev/members")
check(hit("/x", "f=/dev/mem.bin") == "DEV_MEM_ACCESS", "/dev/mem followed by a dot still counts")

if fails > 0 then
  io.stderr:write(("dev/mem boundary tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: rule 324 matches /dev/mem and /dev/kmem as whole names")
