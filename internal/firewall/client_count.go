package firewall

import (
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/ipkey"
	"cfm/internal/logging"
)

// countBackend is the backend CountKey reads the guards from (the daemon's,
// SetCountBackend); nil in tests and the one-shot CLI: the /64 then.
var countBackend atomic.Pointer[Backend]

// SetCountBackend makes CountKey ask be's guards (the daemon, at startup).
func SetCountBackend(be Backend) {
	if be == nil {
		countBackend.Store(nil)
		return
	}
	countBackend.Store(&be)
}

// countKeyTTL is how long CountKey reuses its answer for a /64 (a var:
// tests set 0). The guards it reads change rarely (an allow, an ignore, a
// node address); the ban itself checks them again.
var countKeyTTL = 10 * time.Second

var countKeyCache = struct {
	sync.Mutex
	m map[netip.Prefix]countKeyEntry
}{m: map[netip.Prefix]countKeyEntry{}}

type countKeyEntry struct {
	guarded bool
	at      time.Time
}

// CountKey is the key a per-client counter, rate limit or cooldown uses for
// the address ip: an IPv6 client's /64 (ipkey.Client) when an automatic ban
// would take that /64, and the address itself when a guard keeps the /64
// from being banned as a whole (it holds this node, its gateway, an ignored,
// allowed or trusted proxy address; or nft cannot tell). Counting a guarded
// /64 as one client would spend its alert on one address's ban and leave its
// other addresses unbanned, or name an ignored neighbour. IPv4 and the
// addresses ipkey leaves ungrouped come back as ipkey.Client gives them.
// Never key an allow or an exact match on it (ipkey).
func CountKey(ip string) string {
	k := ipkey.Client(ip)
	if !strings.Contains(k, "/") {
		return k
	}
	p, err := netip.ParsePrefix(k)
	if err != nil {
		return k
	}
	if countKeyGuarded(p) {
		if a, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
			return a.Unmap().String()
		}
	}
	return k
}

func countKeyGuarded(p netip.Prefix) bool {
	now := time.Now()
	countKeyCache.Lock()
	if e, ok := countKeyCache.m[p]; ok && countKeyTTL > 0 && now.Sub(e.at) < countKeyTTL {
		countKeyCache.Unlock()
		return e.guarded
	}
	countKeyCache.Unlock()

	guarded := ClientNetExempted(p) != ""
	if !guarded {
		if bp := countBackend.Load(); bp != nil {
			if _, ok := (*bp).(SetElemWriter); !ok {
				guarded = true // this backend bans the address alone
			} else {
				why, err := clientNetGuard(*bp, p)
				if err != nil {
					countKeyLogErr(err)
				}
				guarded = err != nil || why != "" // unknown: as the ban, the address
			}
		}
	}
	countKeyCache.Lock()
	if len(countKeyCache.m) > 50000 {
		countKeyCache.m = map[netip.Prefix]countKeyEntry{} // bounded
	}
	countKeyCache.m[p] = countKeyEntry{guarded: guarded, at: now}
	countKeyCache.Unlock()
	return guarded
}

// ResetCountKeyCache drops CountKey's answers (tests).
func ResetCountKeyCache() {
	countKeyCache.Lock()
	countKeyCache.m = map[netip.Prefix]countKeyEntry{}
	countKeyCache.Unlock()
}

var countKeyErrLogged atomic.Int64 // unix seconds of the last log line

// countKeyLogErr says, at most once a minute, that IPv6 clients count per
// address because the guards cannot be read (the ban path logs its own).
func countKeyLogErr(err error) {
	now := time.Now().Unix()
	if last := countKeyErrLogged.Load(); now-last < 60 || !countKeyErrLogged.CompareAndSwap(last, now) {
		return
	}
	logging.Logf("[firewall] IPv6 client counters: cannot read the /64 guards (%v); counting per address", err)
}
