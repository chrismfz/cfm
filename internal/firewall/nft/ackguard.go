package nft

import (
    "fmt"
    cfgpkg "cfm/internal/config"
)

// set name for port list (inet_service)
const ackGuardPortsSet = "ackguard_tcp_ports"

func (b *Backend) ApplyAckGuard(ac *cfgpkg.AckGuardConfig) error {
    // ensure sub-chain
    if !b.chainExists("ackguard") {
        if err := b.nftCmd(`add chain inet cfm ackguard`); err != nil { return err }
    }
    // idempotent: make sure our chain is clean before re-adding rules
    _ = b.nftExpr(`flush chain inet cfm ackguard`)

    // ensure jump at position 0 (idempotent)
    if !b.ruleExists("flood", "jump ackguard") {
        if err := b.nftCmd(`insert rule inet cfm flood position 0 jump ackguard`); err != nil { return err }
    }

    // ensure counter (visible in status)
    _ = b.nftExpr(`add counter inet cfm acknew_drop`)

    // ensure inet_service set and load configured ports (NOT tcp_in)
    if err := b.ensurePortSet(ackGuardPortsSet); err != nil { return err }
    if err := b.replacePortSet(ackGuardPortsSet, ac.Ports); err != nil { return err }

    rate := ac.Rate
    burst := ac.Burst
    if rate <= 0 { rate = 200 }
    if burst <= 0 { burst = 2 * rate }

    // Accept a small per-source trickle (v4)
    expr4 := fmt.Sprintf(
        `add rule inet cfm ackguard `+
            `ct state new tcp dport @%s tcp flags & (syn|ack) == ack `+
            `meter ack_ok_v4 { ip saddr limit rate %d/second burst %d packets } accept`,
        ackGuardPortsSet, rate, burst,
    )
    if err := b.nftExpr(expr4); err != nil { return err }

    // Accept a small per-source trickle (v6)
    expr6 := fmt.Sprintf(
        `add rule inet cfm ackguard `+
            `ct state new tcp dport @%s tcp flags & (syn|ack) == ack `+
            `meter ack_ok_v6 { ip6 saddr limit rate %d/second burst %d packets } accept`,
        ackGuardPortsSet, rate, burst,
    )
    if err := b.nftExpr(expr6); err != nil { return err }

    // NEW: strict-mode path — INVALID+ACK (no prior SYN) → drop & count
    exprInvalid := fmt.Sprintf(
        `add rule inet cfm ackguard `+
            `ct state invalid tcp dport @%s tcp flags & (syn|ack) == ack `+
            `counter name "acknew_drop" drop comment "ack-invalid-over"`,
        ackGuardPortsSet,
    )
    if err := b.nftExpr(exprInvalid); err != nil { return err }

    // Overflow (NEW+ACK) → drop & count
    exprDrop := fmt.Sprintf(
        `add rule inet cfm ackguard `+
            `ct state new tcp dport @%s tcp flags & (syn|ack) == ack `+
            `counter name "acknew_drop" drop comment "ack-new-over"`,
        ackGuardPortsSet,
    )
    return b.nftExpr(exprDrop)
}
