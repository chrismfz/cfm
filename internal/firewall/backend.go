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
}
