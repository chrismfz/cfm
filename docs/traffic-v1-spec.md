# Traffic V1 Spec

Status: Draft v1  
Audience: CLI + API + Web UI implementers  
Goal: lock field names and update cadence now to avoid downstream rework.

## 1) Core metrics

### Endpoint
- `GET /api/v1/traffic/summary`

### Response payload
```json
{
  "ts_unix": 1713636000,
  "window_sec": 1,
  "totals": {
    "in_bps": 12500400,
    "out_bps": 9012000,
    "in_bytes": 1562550,
    "out_bytes": 1126500,
    "active_connections": 482
  },
  "protocol_counts": {
    "tcp": 331,
    "udp": 145,
    "icmp": 6
  }
}
```

### Field requirements
- `ts_unix` (int64): sample timestamp (epoch seconds).
- `window_sec` (int32): sampling interval used to compute bps/counters.
- `totals.in_bps` / `totals.out_bps` (int64): total ingress/egress bits-per-second.
- `totals.in_bytes` / `totals.out_bytes` (int64): raw bytes for precision math/export.
- `totals.active_connections` (int64): count of current active connections.
- `protocol_counts` (object<string,int64>): active connection count per protocol key.

## 2) Tables

All table endpoints return this envelope:

```json
{
  "ts_unix": 1713636000,
  "window_sec": 1,
  "rows": []
}
```

### Top IPs
- `GET /api/v1/traffic/top_ips?limit=20`
- `rows[]` schema:

```json
{
  "ip": "203.0.113.10",
  "in_bps": 6500000,
  "out_bps": 1200000,
  "in_bytes": 812500,
  "out_bytes": 150000,
  "connections": 84
}
```

### Top processes
- `GET /api/v1/traffic/top_processes?limit=20`
- `rows[]` schema:

```json
{
  "pid": 1274,
  "process_name": "nginx",
  "in_bps": 5400000,
  "out_bps": 2200000,
  "in_bytes": 675000,
  "out_bytes": 275000,
  "connections": 96
}
```

### Top ports/services
- `GET /api/v1/traffic/top_ports?limit=20`
- `rows[]` schema:

```json
{
  "port": 443,
  "protocol": "tcp",
  "service": "https",
  "in_bps": 7100000,
  "out_bps": 3000000,
  "in_bytes": 887500,
  "out_bytes": 375000,
  "connections": 204
}
```

### Live flows
- `GET /api/v1/traffic/flows?limit=200`
- `rows[]` schema:

```json
{
  "flow_id": "tcp:10.0.0.12:51522-198.51.100.4:443",
  "protocol": "tcp",
  "src_ip": "10.0.0.12",
  "src_port": 51522,
  "dst_ip": "198.51.100.4",
  "dst_port": 443,
  "state": "established",
  "in_bps": 310000,
  "out_bps": 92000,
  "in_bytes": 38750,
  "out_bytes": 11500,
  "process_name": "curl",
  "pid": 9321,
  "started_at_unix": 1713635988,
  "last_seen_unix": 1713636000
}
```

## 3) Units and precision

- API must always return integer `*_bps` and `*_bytes` fields (no rounded Mbps in payload).
- UI/CLI display should default to Mbps for throughput columns:
  - `display_mbps = bps / 1_000_000`
  - Show 2 decimals (example: `12.50 Mbps`).
- JSON mode (`--json`) must emit raw fields exactly as specified above (no unit conversion).

## 4) Refresh cadence

- Default live sampling interval: `1s`.
- Default live polling tick for UI/CLI live views: `1s`.
- `window_sec` in responses must reflect the effective backend sampling window.

## 5) CLI modes

Command group: `cfm traffic`

- `cfm traffic live`
  - Uses `/api/v1/traffic/summary` + table endpoints on a 1s tick.
  - Human output uses Mbps display.
- `cfm traffic summary`
  - Single-shot summary from `/api/v1/traffic/summary`.
- `cfm traffic top`
  - Single-shot top tables (`top_ips`, `top_processes`, `top_ports`).
- `cfm traffic conn`
  - Single-shot live-flow/connection table from `/api/v1/traffic/flows`.
- `cfm traffic <mode> --json`
  - Emits raw API-shaped JSON using exact field names in this spec.

## Non-goals (v1)

- No percentile latency fields.
- No packet-loss/retransmit metrics.
- No historical aggregation API beyond current window snapshots.
