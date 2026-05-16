# `cfm debug` — diagnostic bundle CLI

One-shot capture of everything an engineer needs to triage a regression
in the cfm daemon or angie/openresty workers (CPU spike, memory leak,
hung handler, latency, weird traffic). Drops a directory of plain-text
+ pprof artifacts into `/var/lib/cfm/debug/<UTC-timestamp>/`.

> **Why /var/lib/cfm/debug, not /tmp?** `/tmp` is mounted noexec on
> many production hosts. `go tool pprof` (used to render the
> `pprof-*-top.txt` files) extracts a helper binary to `$TMPDIR`
> and fork+exec's it; on a noexec /tmp the exec fails with
> "permission denied" and the top renderings are lost. The
> `/var/lib/cfm` tree is writable + exec by project convention
> (already used by `client_body_temp` and `proxy_temp` in
> install-openresty.sh).

## Quick start

```bash
# Default: 60-second pprof + worker mem trace + everything else
cfm debug

# Shorter capture, skip log tails (~45s total):
cfm debug --quick

# Longer trace window when chasing a slow leak:
cfm debug --duration 5m

# When the apiserver is down (skip pprof, keep /proc and logs):
cfm debug --no-pprof
```

The bundle path is printed at the end. Share the directory or tarball
it (`tar -C /var/lib/cfm/debug -czf cfm-debug.tgz <ts>/`) and send to
whoever is helping triage.

## What's in the bundle

| File | What |
|---|---|
| `summary.txt` | Scannable digest: daemon CPU%, top hot funcs, top heap allocators, per-worker memory deltas, leaker warnings, manifest. **Open this first.** |
| `manifest.txt` | Per-artifact `ok` / `skipped` / `error` status, sortable. |
| `system.txt` | uname, uptime, free -h, df -h. |
| `proc-daemon.txt` | `/proc/<daemon>/{status,io}` + thread/fd counts. |
| `proc-workers.txt` | Same shape, one block per worker. |
| `proc-maps-summary.txt` | Per-worker /proc/maps categorised totals (anonymous / file-backed / shared / heap / stack). Lets you tell real RSS growth from address-space inflation. |
| `pprof-cpu.pb.gz` | Go CPU profile of the daemon. Open with `go tool pprof`. |
| `pprof-cpu-top.txt` | `go tool pprof -top -cum` rendering of the above (only if `go` was on PATH at capture time). |
| `pprof-heap.pb.gz` | Heap profile snapshot (in_use_space). |
| `pprof-heap-top.txt` | Heap top, same shape. |
| `goroutines.txt` | Goroutine dump (`debug=2`) — every goroutine's stack. |
| `worker-mem-trace.txt` | Per-worker RSS / VmSize / threads / FDs / maps-count sampled every 30 s. |
| `daemon-cpu-trace.txt` | Daemon CPU% sampled every 30 s. |
| `logs-tail.txt` | Last ~500 lines from cfm.log, cfm.waf.log, cfm.error.log, api.log. |
| `journal-tail.txt` | `journalctl -u cfm` over the trace window (when systemd is the service manager). |
| `ss-listen.txt` | `ss -lntp` — every listening socket on the box. |
| `bridge-conn.txt` | Connection state on `/var/run/cfm/cfm_nginx.sock` — current bridge clients. |
| `waf-hit-rates.json` | Last 1 hour of per-rule hit rates from `/api/v1/waf/hit-rates`. |
| `waf-excludes.json` | Current WAF exclude store. |
| `config.txt` | `cfm.conf` with secrets redacted (`bridge_token`, `hmac_secret`, `clamd_password`, etc. → `<redacted len=N>`). |

## Flags

| Flag | Default | What |
|---|---|---|
| `--duration` | `60s` | Trace window for pprof + worker mem + daemon CPU traces. Min 1 s, max 10 m. |
| `--quick` | off | Shortcut for `--duration 30s --no-logs`. ~45 s total. |
| `--output` | `/var/lib/cfm/debug` | Bundle root directory. Bundle goes in `<root>/<UTC-timestamp>`. Override only if you have a stronger reason than `/tmp` noexec to avoid the default — see the note at the top. |
| `--no-pprof` | off | Skip all pprof captures. Use when the apiserver is down or unreachable. |
| `--no-logs` | off | Skip log tails and journalctl. |
| `--keep` | `10` | After capture, keep only the N most recent bundles in the output dir; older bundles are removed. `0` disables pruning. |
| `--apiserver` | `$CFM_API_ADDR` or `http://127.0.0.1:6060` | Override the apiserver URL (where pprof + WAF API live). |
| `--config` | `/etc/cfm/cfm.conf` | Config file to dump (sanitised). Empty string disables. |
| `--log-root` | `/var/log/cfm` | Directory to scan for log tails. |

## What's NOT in the bundle (intentionally)

- **Raw config secrets.** The sanitiser replaces values for any key
  matching `(?i)token|secret|password|hmac|api_?key|private_?key` with
  `<redacted len=N>`. Check `config.txt` before sharing if your config
  has unusual key names; add the offending key to `secretKeyRE` in
  `internal/cli/debug_summary.go` if needed.
- **Production traffic content.** `logs-tail.txt` includes URIs and
  client IPs (these are already in cfm's logs). It does NOT include
  request bodies or response bodies.
- **Customer data from databases.** `cfm debug` doesn't read the
  history SQLite, the stats counters, or any user-facing DB.

## What to look for in `summary.txt`

The summary is structured for a hurried first read:

1. **Daemon block:**
   - `cpu_pct` — should match expected steady-state. Sustained > 2 %
     warrants a look at `pprof-cpu-top.txt`.
   - `Top hot functions` — flat % > 10 on a single function is a
     candidate hot path to examine.
   - `goroutines` — typically 30–100 for a small daemon. Drift upward
     over time = goroutine leak.
   - `Top heap allocators` — same shape; flat % > 30 on a single
     allocator is a fingerprint of an unbounded data structure.

2. **Workers block:**
   - `growth/min` column — anything ≥ 5 MB/min triggers an explicit
     `⚠ workers growing ≥ 5 MB/min` warning.
   - `size_start`/`size_end` (VmSize) inflating without `rss_start`/
     `rss_end` (VmRSS) doing the same is normal mmap address-space
     behavior, not a leak. Cross-check `proc-maps-summary.txt`.

3. **Captured artifacts:**
   - Any `error:` entry tells you what couldn't be captured (e.g.
     "go binary not on PATH; raw profile retained" — fine, the
     `.pb.gz` is still there).

## Common diagnostic recipes

### "Daemon CPU is 3 % but used to be 1 %"

```bash
cfm debug --duration 60s
# Check summary.txt → "Top hot functions"
# Read pprof-cpu-top.txt for full ranking
# Open the .pb.gz locally for graph view: go tool pprof <bundle>/pprof-cpu.pb.gz
```

If the top function is a `time.Now()` / `logging.Logf` site, that's
instrumentation overhead. If it's a `database/sql.(*DB).Exec`, look at
the per-minute UPSERT path. If it's something in `net/http` it's
probably accept overhead from a connection storm — cross-reference
`bridge-conn.txt`.

### "Worker RSS is climbing 9 MB/min"

```bash
cfm debug --duration 5m
# Check summary.txt → "Workers" table → growth/min column
# Read proc-maps-summary.txt to see which mapping bucket grew
# Read worker-mem-trace.txt for the time-series
```

If `shared` (SYSV/memfd) grew, it's shdict cardinality — count keys
under the suspect zone via the lua_shared_dict free_space introspection.
If `anonymous` grew, it's LuaJIT GC or upstream pool buildup. If
`file_backed` grew, it's nginx temp files (large body buffering).

### "Apiserver is unreachable"

```bash
cfm debug --no-pprof --quick
```

You still get /proc, log tails, ss state, and the sanitised config —
enough to triage most "why is the daemon hung" questions.

## Permissions

`cfm debug` reads `/proc/<pid>/{status,io,maps,stat}` for both the
daemon (root) and workers (the `cfm` user). Run as root on a
production host so all `/proc` files are readable. Running as a
non-root user yields a partial bundle (workers' /proc data may be
inaccessible).

## Implementation notes

- Source: `internal/cli/debug.go` (orchestrator),
  `internal/cli/debug_capture.go` (capture helpers),
  `internal/cli/debug_summary.go` (sanitiser + summary builder).
- Tests: `internal/cli/debug_test.go`.
- Pprof comes from the apiserver's existing `/debug/pprof/*` handlers
  registered in `internal/apiserver/apiserver_debug.go`. No new code
  paths in the daemon.
- Captures run in parallel where independent (pprof + worker mem
  trace + log tails + WAF API queries). The total wall time is
  approximately `--duration` + a few seconds for the synchronous
  setup steps.

## Related but distinct

- `/api/v1/debug/capture` (apiserver) — server-side, API-triggered
  capture of `telemetry.LiveSnapshot` time-series. Useful for remote
  diagnostics on a host you can't shell into. **Different mechanism**
  with a narrower scope (only the `telemetry` counters); doesn't
  include pprof, log tails, or worker /proc data.
