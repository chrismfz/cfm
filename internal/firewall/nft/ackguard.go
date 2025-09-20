package nft

import (
    "fmt"
    cfgpkg "cfm/internal/config"
)

// set name for port list (inet_service)
const ackGuardPortsSet = "ackguard_tcp_ports"

func (b *Backend) ApplyAckGuard(ac *cfgpkg.AckGuardConfig) error {
    // ensure chain + flush each apply
    if !b.chainExists("ackguard") {
        if err := b.nftCmd(`add chain inet cfm ackguard`); err != nil { return err }
    }
    _ = b.nftExpr(`flush chain inet cfm ackguard`)
    if !b.ruleExists("flood", "jump ackguard") {
        if err := b.nftCmd(`insert rule inet cfm flood position 0 jump ackguard`); err != nil { return err }
    }

    // counters we’ll use
    _ = b.nftExpr(`add counter inet cfm acknew_drop`)
    _ = b.nftExpr(`add counter inet cfm nonsynnew_drop`)
    _ = b.nftExpr(`add counter inet cfm synack_in_drop`)
    _ = b.nftExpr(`add counter inet cfm rstnew_drop`)
    _ = b.nftExpr(`add counter inet cfm rst_est_v4`)
    _ = b.nftExpr(`add counter inet cfm rst_est_v6`)
    _ = b.nftExpr(`add counter inet cfm tcp_frag_drop`)
    _ = b.nftExpr(`add counter inet cfm tcp6_frag_drop`)

    // ports set (inet_service) just for ackguard
    if err := b.ensurePortSet(ackGuardPortsSet); err != nil { return err }
    if err := b.replacePortSet(ackGuardPortsSet, ac.Ports); err != nil { return err }

    rate, burst := ac.Rate, ac.Burst
    if rate <= 0 { rate = 200 }
    if burst <= 0 { burst = 2 * rate }

    // --- recent offender sets (hardcoded TTL 60 minutes) ---
    // (ignore "already exists" errors)
    _ = b.nftExpr(`add set inet cfm ackguard_recent_v4 { type ipv4_addr; flags timeout; }`)
    _ = b.nftExpr(`add set inet cfm ackguard_recent_v6 { type ipv6_addr; flags timeout; }`)

    ackRecentTTL := ac.RecentTTL
    if ackRecentTTL <= 0 {
        ackRecentTTL = 3600 // sensible default
    }


    // --- 1) Allow tiny trickle of NEW+ACK (per-source), then count/drop over-limit ---
    _ = b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ct state new tcp dport @%s tcp flags & (syn|ack) == ack `+
            `meter ack_ok_v4 { ip saddr limit rate %d/second burst %d packets } accept`,
        ackGuardPortsSet, rate, burst))
    _ = b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ct state new tcp dport @%s tcp flags & (syn|ack) == ack `+
            `meter ack_ok_v6 { ip6 saddr limit rate %d/second burst %d packets } accept`,
        ackGuardPortsSet, rate, burst))

    // --- 2) (optional) INVALID+ACK (strict mode path) → add-to-recent + drop+count ---
    if ac.MatchInvalid {
        _ = b.nftExpr(fmt.Sprintf(
            `add rule inet cfm ackguard ip protocol tcp ct state invalid tcp dport @%s `+
                `tcp flags & (syn|ack) == ack add @ackguard_recent_v4 { ip saddr timeout %ds } `+
                `counter name "acknew_drop" drop comment "ack-invalid-over"`,
            ackGuardPortsSet, ackRecentTTL))
        _ = b.nftExpr(fmt.Sprintf(
            `add rule inet cfm ackguard ip6 nexthdr tcp ct state invalid tcp dport @%s `+
                `tcp flags & (syn|ack) == ack add @ackguard_recent_v6 { ip6 saddr timeout %ds } `+
                `counter name "acknew_drop" drop comment "ack-invalid-over"`,
            ackGuardPortsSet, ackRecentTTL))
    }


// --- 3) (optional) NEW without SYN (PSH/FIN/RST etc.) → add-to-recent + drop+count ---
if ac.DropNonSynNew {
    _ = b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ip protocol tcp ct state new tcp dport @%s tcp flags & syn == 0 `+
            `add @ackguard_recent_v4 { ip saddr timeout %ds } `+
            `counter name "nonsynnew_drop" drop comment "NEW-without-SYN"`,
        ackGuardPortsSet, ackRecentTTL))
    _ = b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ip6 nexthdr tcp ct state new tcp dport @%s tcp flags & syn == 0 `+
            `add @ackguard_recent_v6 { ip6 saddr timeout %ds } `+
            `counter name "nonsynnew_drop" drop comment "NEW-without-SYN"`,
        ackGuardPortsSet, ackRecentTTL))
}


// --- 4) (optional) unsolicited SYN-ACK inbound → add-to-recent + drop+count ---
if ac.DropSynAckNew {
    _ = b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ip protocol tcp ct state new tcp dport @%s tcp flags & (syn|ack) == (syn|ack) `+
            `add @ackguard_recent_v4 { ip saddr timeout %ds } `+
            `counter name "synack_in_drop" drop comment "unsolicited SYN-ACK"`,
        ackGuardPortsSet, ackRecentTTL))
    _ = b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ip6 nexthdr tcp ct state new tcp dport @%s tcp flags & (syn|ack) == (syn|ack) `+
            `add @ackguard_recent_v6 { ip6 saddr timeout %ds } `+
            `counter name "synack_in_drop" drop comment "unsolicited SYN-ACK"`,
        ackGuardPortsSet, ackRecentTTL))
}


// --- 5) (optional) RST guards ---
if ac.RSTGuard {
    rRate := ac.RSTRate; if rRate <= 0 { rRate = 200 }
    rBurst := ac.RSTBurst; if rBurst <= 0 { rBurst = 300 }

    // NEW+RST nonsense → add-to-recent + drop (v4/v6) and keep it scoped to protected ports
    _ = b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ip protocol tcp ct state new tcp dport @%s tcp flags & rst == rst `+
            `add @ackguard_recent_v4 { ip saddr timeout %ds } `+
            `counter name "rstnew_drop" drop`,
        ackGuardPortsSet, ackRecentTTL))
    _ = b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ip6 nexthdr tcp ct state new tcp dport @%s tcp flags & rst == rst `+
            `add @ackguard_recent_v6 { ip6 saddr timeout %ds } `+
            `counter name "rstnew_drop" drop`,
        ackGuardPortsSet, ackRecentTTL))

    // ESTABLISHED RST rate-limit → add-to-recent + drop (v4/v6)
    _ = b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ct state established tcp dport @%s tcp flags & rst == rst `+
            `meter rst_v4 { ip saddr limit rate over %d/second burst %d packets } `+
            `add @ackguard_recent_v4 { ip saddr timeout %ds } `+
            `counter name "rst_est_v4" drop`,
        ackGuardPortsSet, rRate, rBurst, ackRecentTTL))
    _ = b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ct state established ip6 nexthdr tcp tcp dport @%s tcp flags & rst == rst `+
            `meter rst_v6 { ip6 saddr limit rate over %d/second burst %d packets } `+
            `add @ackguard_recent_v6 { ip6 saddr timeout %ds } `+
            `counter name "rst_est_v6" drop`,
        ackGuardPortsSet, rRate, rBurst, ackRecentTTL))
}



    // --- 6) (optional) fragmented TCP to our ports → drop+count ---
    if ac.FragGuard {
        _ = b.nftExpr(fmt.Sprintf(
            `add rule inet cfm ackguard ip frag-off & 0x1fff != 0 tcp dport @%s counter name "tcp_frag_drop" drop`,
            ackGuardPortsSet))
        _ = b.nftExpr(fmt.Sprintf(
            `add rule inet cfm ackguard ip6 frag frag-off != 0 tcp dport @%s counter name "tcp6_frag_drop" drop`,
            ackGuardPortsSet))
    }

    // --- 7) Overflow (NEW+ACK) → add-to-recent + drop+count (v4 & v6) ---
    if err := b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ip protocol tcp ct state new tcp dport @%s `+
            `tcp flags & (syn|ack) == ack add @ackguard_recent_v4 { ip saddr timeout %ds } `+
            `counter name "acknew_drop" drop comment "ack-new-over"`,
        ackGuardPortsSet, ackRecentTTL)); err != nil {
        return err
    }
    if err := b.nftExpr(fmt.Sprintf(
        `add rule inet cfm ackguard ip6 nexthdr tcp ct state new tcp dport @%s `+
            `tcp flags & (syn|ack) == ack add @ackguard_recent_v6 { ip6 saddr timeout %ds } `+
            `counter name "acknew_drop" drop comment "ack-new-over"`,
        ackGuardPortsSet, ackRecentTTL)); err != nil {
        return err
    }

    return nil
}
