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
}
