package firewall

import (
	"net"
	"time"
)

type BlockedEntry struct {
	IP      net.IP
	Expires *time.Time
	Comment string
}

type Backend interface {
	EnsureBase() error
	AddBlock(ip net.IP, comment string, ttl *time.Duration) error
	RemoveBlock(ip net.IP) error
	ListBlocks() ([]BlockedEntry, error)
	ListAllows() ([]BlockedEntry, error)
	AddAllow(ip net.IP, ttl *time.Duration) error
	RemoveAllow(ip net.IP) error

	// NEW: CIDR subnets (manual)
	// cidr must be canonical (but we’ll also accept any valid ParseCIDR) e.g. "47.128.0.0/14"
	AddBlockNet(cidr string, ttl *time.Duration) error
	RemoveBlockNet(cidr string) error
	AddAllowNet(cidr string, ttl *time.Duration) error
	RemoveAllowNet(cidr string) error


	// NEW: Ignore (manual) — skip enforcement but still log/notify/report
	AddIgnore(ip net.IP, ttl *time.Duration) error
	RemoveIgnore(ip net.IP) error
	AddIgnoreNet(cidr string, ttl *time.Duration) error
	RemoveIgnoreNet(cidr string) error

	// NEW: Challenge (HTTP/HTTPS redirect for selected source IPs)
	AddChallenge(ip net.IP, ttl *time.Duration) error
	RemoveChallenge(ip net.IP) error


        // ReportBlock: centralized policy-aware API reporting.
        // source: "detector" | "autoblock" | "manual"
        // mode:   "ttl" | "permanent" | "dryrun"
        // ttlSeconds used only when mode == "ttl".
        ReportBlock(ip, comment, source, mode string, ttlSeconds int) error



}
