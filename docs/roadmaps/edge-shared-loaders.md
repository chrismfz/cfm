# CFM — Edge Shared Loaders Roadmap (follow-up unification)

**Status:** Complete (2026-07, same PR as the review that surfaced it) —
`cfm_bridge_cfg.token()` is the single edge token accessor (cfm.lua,
cfm_panel, cfm_purge, cfm_h3_config all migrated; the cfm_panel selftest
hook intentionally still probes the raw file — it is an install preflight
of the file itself); `writeLuaFileAtomic` is the single Go writer behind
all four `Write*Lua*` functions in `internal/sslcollector/token.go`. Only
the "Explicitly NOT planned" decision below remains standing guidance.
**Scope:** `configs/lua/` bridge-token loading · `internal/sslcollector/token.go`
atomic Lua-file writers
**Goal:** One implementation each for (a) reading/validating the bridge token
on the edge and (b) atomically writing root:cfm 0640 Lua files from Go —
so a future change to either contract lands in one place instead of 4-5.

---

## 1. Bridge-token loading — 4 remaining copies on the edge

`cfm.lua` now reads the bridge token through `cfm_filecache` (10s TTL,
validated by a transform: string, ≥32 chars). The same load+validate logic
still exists as private copies in:

| Copy | Freshness today |
|---|---|
| `configs/lua/cfm_panel.lua:48` (`load_token`, used at `:62`) | **once per request** (access_by_lua_file top-level — the PITFALL cfm.lua documents) |
| `configs/lua/cfm_panel.lua:820` (second inline loadfile) | per call |
| `configs/lua/cfm_purge.lua:32` | per purge call (cold path, fine) |
| `configs/lua/cfm_h3_config.lua:137` | **cached forever per worker** — a rotated token means stale H3 bridge auth until nginx reload |

Work item: add a `token()` accessor next to `cfm_bridge_cfg.get()` (backed by
`cfm_filecache`, same transform/TTL as cfm.lua uses today) and migrate the
four sites. Wins: panel hot path stops paying loadfile per request; H3 picks
up rotation within 10s; the ≥32-char validity rule lives in one place.
Watch-outs: cfm_panel is the historically painful area (CLAUDE.md §6) —
migrate with the same pcall-require upgrade-lag guard used for
`panel_bridge_cfg`, and keep `internal/dnat`'s panel-Lua contract tests in
sync (they assert the token-loading shape in `cfm_panel.lua`).

## 2. Go: shared atomic writer for generated Lua files

`internal/sslcollector/token.go` carries four hand-rolled copies of the same
tmp-write → chmod 0640 → chown root:cfm → rename sequence:
`WriteLuaToken` (:128), `WriteLuaConfig` (:252), `WriteClamavLuaConfig`
(:304), `WriteWebdetectorBridgeConfig` (:366) — plus per-writer
bool→"true"/"false" helpers.

Work item: extract a package-local
`writeLuaFileAtomic(luaPath, content string, cfmGID int) error` and route all
four through it. Rationale: CLAUDE.md §5 — generated Lua files have enforced
ownership/mode asserted by post-deploy checks; a future fix (fsync before
rename, umask handling, permission tweak) must not land in three writers and
miss the fourth. Pure refactor; existing `token_test.go` content assertions
already cover all four writers' outputs.

## Explicitly NOT planned (decision, not TODO)

`cfm.lua` allocates small opts tables + transform closures for its
`cfm_filecache.get()` calls on every request (~hundreds of bytes of nursery
garbage), because `access_by_lua_file` chunks re-execute per request. This is
an **accepted trade-off**, documented in `cfm_filecache.lua`'s header: the
alternative (a per-file accessor module or a register-once API) adds a module
per cached file for a LuaJIT nursery-GC cost that is noise next to the work
already on that path (WAF regex battery, shdict ops). Do not "fix" this
without a measurement showing GC pressure from the access phase.
