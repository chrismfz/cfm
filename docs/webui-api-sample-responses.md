# WebUI API sample responses (redacted)

These are real-shape examples from live API responses, with sensitive host/IP values redacted.

Use this file to understand payload structure when building/testing WebUI components.

> Source context: `curl` calls against `http://127.0.0.1:6060`.

---

## `GET /api/v1/webdet/top-short?limit=20`

```json
{
  "window_sec": 120,
  "long_horizon_sec": 1200,
  "rows": [
    {
      "host": "<vhost-a>",
      "rps": 10.168,
      "rps_2xx": 9.912,
      "rps_3xx": 0.088,
      "rps_4xx": 0.168,
      "rps_5xx": 0,
      "rps_401": 0,
      "rps_403": 0,
      "rps_404": 0.168,
      "rps_499": 0,
      "unique_ips": 105,
      "err_ratio": 0.0165,
      "auth401_ratio": 0,
      "proc_avg_sec": 0.4862,
      "score": 0.414,
      "reasons": ["scanner_like_path_diversity"],
      "bytes_rps": 1530619.944,
      "bot_ratio": 0.1849,
      "ua_diversity": 0.0212,
      "path_diversity": 0.5067,
      "post_ratio": 0.1833
    },
    {
      "host": "<vhost-b>",
      "rps": 8.28,
      "score": 0.1901,
      "reasons": ["scanner_like_path_diversity"]
    }
  ]
}
```

---

## `GET /api/v1/webdet/suspicious`

```json
[
  {
    "host": "<vhost-c>",
    "score": 0.678,
    "reasons": [
      "high_error_ratio",
      "many_bot_user_agents",
      "scanner_like_path_diversity"
    ],
    "rps": 1.2167,
    "rps_3xx": 0.005,
    "rps_4xx": 0.2667,
    "rps_5xx": 0,
    "unique_ips": 49,
    "err_ratio": 0.2647,
    "auth401_ratio": 0,
    "hot_ips": 1,
    "bot_ratio": 0.5321,
    "path_diversity": 0.7119,
    "ua_diversity": 0.2542,
    "post_ratio": 0.3253
  }
]
```

---

## `GET /api/v1/webdet/drilldown?host=<vhost>`

```json
{
  "long": {
    "host": "<vhost>",
    "score": 0.3788,
    "reasons": ["scanner_like_path_diversity"],
    "rps": 1.2608,
    "unique_ips": 38,
    "err_ratio": 0.0594,
    "bot_ratio": 0.0641,
    "path_diversity": 0.87,
    "ua_diversity": 0.2577,
    "post_ratio": 0.141
  },
  "short": {
    "host": "<vhost>",
    "window_sec": 120,
    "total_req": 157,
    "direct_pct": 14.0127,
    "bot_pct": 1.9108,
    "path_diversity": 0.8025,
    "unique_paths": 126,
    "ua_diversity": 0.1274,
    "unique_uas": 20,
    "post_ratio": 0.0955,
    "proc_avg_sec": 0.2038,
    "short_score": 0.319,
    "short_reasons": ["scanner_like_path_diversity"],
    "top_ips": [{ "key": "<ip-1>", "count": 64 }],
    "top_agents": [{ "key": "<agent-1>", "count": 64 }],
    "top_referrers": [{ "key": "<ref-1>", "count": 54 }],
    "top_paths": [{ "key": "/", "count": 9 }],
    "enriched_top_ips": [
      {
        "ip": "<ip-1>",
        "count": "64",
        "country": "Greece",
        "asn": "200736",
        "asn_name": "<asn-name>",
        "ptr": "<optional-ptr>"
      }
    ],
    "median_per_ip_rps": 0.0083,
    "bytes_rps": 613046.03,
    "hot_ips": 0,
    "failure_index": 0.0318,
    "ua_entropy": 0.6652,
    "path_entropy": 0.9594,
    "ip_skew": 13.8599
  }
}
```

---

## `GET /api/v1/webdet/ip-short?limit=30`

```json
{
  "window_sec": 120,
  "long_horizon_sec": 1200,
  "short": [
    {
      "ip": "<ip-1>",
      "req": 458,
      "vhosts": 75,
      "rps": 3.8167,
      "score": 0.7,
      "reasons": ["med_rps", "many_vhosts"],
      "ptr": "<optional-ptr>",
      "asn": "216285",
      "asn_name": "<asn-name>",
      "country": "Greece",
      "proposals": [
        {
          "action": "notify",
          "reason": "ip_score_elevated",
          "score": 0.7
        }
      ]
    }
  ],
  "long": [
    {
      "ip": "<ip-2>",
      "req": 381,
      "vhosts": 72,
      "rps": 3.178,
      "score": 0.7,
      "reasons": ["med_rps", "many_vhosts"]
    }
  ]
}
```

---

## `GET /api/v1/webdet/summary`

```json
{
  "now": "2026-03-16T21:03:08.819216004+02:00",
  "window_sec": 120,
  "long_horizon_sec": 1200
}
```

---

## `GET /api/v1/challenge/vhosts?status=active&mode=all&limit=200`

```json
[
  {
    "host": "<vhost-d>",
    "status": "active",
    "mode": "auto",
    "since": "2026-03-16T20:46:38.748725035+02:00",
    "expires_at": "0001-01-01T00:00:00Z",
    "score": 0.6546,
    "on_threshold": 0.68,
    "off_threshold": 0.64,
    "uniq_ip": 227,
    "rps": 1.1125,
    "reasons": ["many_bot_user_agents", "scanner_like_path_diversity"],
    "last_action": "auto_on",
    "last_changed": "2026-03-16T20:46:38.748725035+02:00"
  }
]
```

---

## Manual challenge success examples

### `POST /api/v1/challenge/vhost/add?host=<vhost>&ttl=30m&reason=manual`

```json
{
  "host": "<vhost>",
  "status": "active",
  "expires_at": "2026-03-16T21:45:33.123456789+02:00",
  "ttl": "30m0s",
  "reason": "manual"
}
```

### `POST /api/v1/challenge/vhost/remove?host=<vhost>`

```json
{
  "host": "<vhost>",
  "status": "removed"
}
```

### `GET /api/v1/challenge/vhost/status?host=<vhost>`

```json
{
  "host": "<vhost>",
  "manual_active": true,
  "expires_at": "2026-03-16T21:45:33.123456789+02:00",
  "reason": "manual",
  "auto_active": false,
  "auto_since": "0001-01-01T00:00:00Z"
}
```

---

## Common error response shapes

### Missing required query field

```json
{ "error": "missing host" }
```

### Invalid duration (manual challenge add)

```json
{ "error": "invalid ttl: banana" }
```

---

## Live environment capture checklist

When adding new samples from production-like systems, try to capture:

1. **Healthy baseline** (`top-short`, `summary`).
2. **At least one suspicious host** (`suspicious`).
3. **One deep drilldown** (`drilldown?host=...`).
4. **One IP aggregate snapshot** (`ip-short`).
5. **Challenge state list** (`challenge/vhosts`).
6. **One controlled error** (e.g. missing `host`) so WebUI error views can be tested.

Keep samples redacted (`<vhost-x>`, `<ip-x>`) and preserve key names/types.

---

## Notes for WebUI developers

- `reasons` may be `null` on some rows; treat as optional.
- `ptr` is optional in IP/enrichment sections.
- `expires_at` can be zero time (`0001-01-01T00:00:00Z`) for auto-mode records.
- Number precision varies (float-heavy payloads); avoid strict string comparisons in tests.
- For snapshot tests, compare selected fields/types (not exact full JSON string equality).
