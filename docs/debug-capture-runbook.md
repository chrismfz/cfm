# Debug Capture API + Operations Runbook

## API contract (stable schema)

All endpoints are under `/api/v1/debug/*` and require **admin authentication**.

### `GET /api/v1/debug/live`
Returns:
- `now` (RFC3339)
- `version` (`v1`)
- `telemetry` object with detector/webdetector counters and timings
- `data.status`

### `POST /api/v1/debug/capture`
Request body:
```json
{ "duration_sec": 20 }
```
Allowed durations: `20`, `30`, `60` seconds.

Response (accepted):
- capture record with `id`, `status`, `requested_duration_sec`, `started_at`
- if a capture is already running, returns the same running record (single-flight)

### `GET /api/v1/debug/capture/{id}`
Returns the full capture record and state:
- `running` | `completed` | `failed`
- artifact paths, summary text, collected snapshot count

### `GET /api/v1/debug/export?id={id}&format=json|txt`
Exports completed capture artifacts.

## Operational guardrails

- Cooldown between captures is enforced (default `30s`).
- Duration is capped (default `60s`).
- Retention is bounded by count and age (defaults: `32` captures, `24h`).
- Capture artifacts are written to `/var/lib/cfm/debug-captures` by default.

## Production rollout

1. Deploy with `DEBUG_CAPTURE_ENABLED=0` and verify normal API/webdetector health.
2. Enable on one node with:
   - `DEBUG_CAPTURE_ENABLED=1`
   - conservative cooldown/retention values.
3. Validate:
   - `/api/v1/debug/live` returns telemetry.
   - one 20s capture completes and exports successfully.
4. Roll to remaining nodes.

## Rollback

- Immediate rollback: set `DEBUG_CAPTURE_ENABLED=0` and reload CFM.
- Optional cleanup: remove stale artifacts from `DEBUG_CAPTURE_DIR`.
- Debug UI remains accessible, but capture actions return a disabled error.
