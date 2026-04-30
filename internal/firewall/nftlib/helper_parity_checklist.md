# nft helper-driven behavior checklist (legacy `internal/firewall/nft/*`)

This checklist tracks behavior currently implemented through legacy nft helper flows that are not guaranteed by `firewall.Backend` interface signatures alone.

## Priority rubric
- **P0 startup correctness**: firewall can start in safe/expected state.
- **P1 rule safety**: avoid unintended allow/drop behavior.
- **P2 observability**: counters/logging/diagnostics parity.

## Checklist and nftlib status

| Domain | Helper-driven behavior from legacy nft backend | nftlib status | Priority |
|---|---|---|---|
| Startup correctness | Flood rebuild dedupe only skips when base table **and flood chain** are present and meter-refresh window is still valid. | **partial** (table checked; chain presence was not part of dedupe gate) | P0 |
| Startup correctness | `ApplyFloodRules` re-seeds self return guards before flood policy rebuild. | present | P0 |
| Rule safety | Outbound observe chain rebuild preserves root/uid/gid early returns before NFLOG rules. | present | P1 |
| Rule safety | Hardening NEW/ICMP throttling creates timeout sets before rule insert. | present | P1 |
| Observability | Throttled-IP dump only reads targeted sets and annotates reasons for autoblock. | present | P2 |
| Observability | Flood counter dump is overlap-guarded and auto-recovers with `EnsureBase` on list failure. | present | P2 |

## Current iteration scope

This change implements the **P0 startup correctness** gap (flood dedupe gate must validate flood chain presence) and adds parity coverage.
