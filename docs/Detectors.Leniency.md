# Leniency Feature — Implementation Summary

## What It Does

Adds `[section.leniency]` companion blocks to any detector section.
When an IP matches country or ASN criteria, the sink applies a softer
block policy and optionally suppresses global API reporting.

## Files

| File | Action | Lines Changed |
|---|---|---|
| `internal/detectors/leniency.go` | **NEW** — drop in | ~170 lines |
| `internal/detectors/autoblock_sink.go` | 4 edits | ~30 lines net |
| `internal/detectors/manager.go` | 3 edits | ~15 lines net |
| Register files (`*_register.go`) | **NONE** | 0 |
| Detector logic files | **NONE** | 0 |

## How It Works

```
Alert arrives at sectionSink.Publish()
    │
    ├─ pickIP() + decorateIP()      ← already have enrichment
    ├─ global ignore check           ← existing, unchanged
    │
    ├─ NEW: leniency check           ← if IP matches country/ASN,
    │       swap s.pol → effectivePol       swap to softer policy
    │       set sendToAPI flag
    │
    ├─ cooldown check                ← uses effectivePol.Cooldown
    ├─ block switch                  ← uses effectivePol.Mode/TTL
    ├─ notify                        ← unchanged
    └─ ReportBlock                   ← gated by sendToAPI flag
```

## Config Syntax

```ini
[exim_security.leniency]
MATCH_COUNTRY  = "GR,CY"           ; ISO or full name, OR logic
; MATCH_ASN   = "AS6799,AS6866"    ; optional, OR with country
BLOCK          = "1h"              ; no | dryrun | permanent | <duration>
BLOCK_COOLDOWN = "30m"
SEND_TO_API       = YES            ; YES (default) | NO — report the block at all
SEND_TO_BLOCKLIST = lenient        ; lenient | blacklist (default) — destination
                                   ; list when SEND_TO_API=YES. "lenient" records
                                   ; the block centrally for visibility (support /
                                   ; unblock lookups) but is NEVER served to the
                                   ; farm, so a known-good origin is not propagated.
```

## Log Output

When leniency matches:
```
[leniency][exim_security] ip=94.68.43.7 matched (country=GR) → block=1h cooldown=30m0s send_to_api=false
```

Extra fields on the alert:
```
leniency=yes  leniency_reason=country=GR  send_to_api=no
```

## Testing Checklist

- [ ] GR IP failing auth 6x → blocked 1h locally, NOT sent to API
- [ ] AU datacenter IP failing auth 6x → blocked permanent, sent to API
- [ ] GR IP + no `[section.leniency]` configured → normal permanent block
- [ ] Enricher disabled → leniency silently skipped, normal block
- [ ] `[section.leniency]` with no MATCH_* → nil policy, normal block
- [ ] `BLOCK = no` in leniency → alert logged, no firewall action, no API
- [ ] Hot-reload: edit leniency config → picks up on next reload
- [ ] `.leniency` sections don't appear in "enabled sections" log line

## Future: Multi-Leniency (v2)

When you need different policies per match (country=1h vs ASN=no),
use named instances:

```ini
[exim_security.leniency:domestic]
MATCH_COUNTRY = "GR,CY"
BLOCK = "1h"

[exim_security.leniency:trusted]
MATCH_ASN = "AS216285"
BLOCK = no
```

This requires changing `*leniencyPolicy` → `[]*leniencyPolicy` in the
sink + iterating with first-match-wins. ~20 lines of changes on top
of this foundation.
