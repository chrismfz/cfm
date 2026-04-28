package outbound

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// dnsRecentPerUIDMax is the default maximum number of pre-trigger DNS
	// packet summaries retained per uid.
	dnsRecentPerUIDMax = 32
	// dnsRecentTTL is the default age limit for pre-trigger DNS summaries.
	dnsRecentTTL = 2 * time.Minute
	// dnsRecentUIDMax caps concurrent uid buckets so memory remains bounded.
	dnsRecentUIDMax = 1024
)

// DNSPacketSummary is the compact forensic breadcrumb persisted in-memory and
// flushed into dns_debug logs on trigger.
type DNSPacketSummary struct {
	When       time.Time
	Src        string
	Dst        string
	QName      string
	QType      uint16
	QTypeKnown bool
	RCode      uint8
	RCodeKnown bool
}

type dnsRecentUIDBucket struct {
	entries []DNSPacketSummary
	next    int
	size    int
	seenAt  time.Time
}

type dnsRecentRing struct {
	mu        sync.Mutex
	perUIDMax int
	ttl       time.Duration
	uidMax    int
	buckets   map[uint32]*dnsRecentUIDBucket
}

func newDNSRecentRing(perUIDMax int, ttl time.Duration, uidMax int) *dnsRecentRing {
	if perUIDMax <= 0 {
		perUIDMax = dnsRecentPerUIDMax
	}
	if ttl <= 0 {
		ttl = dnsRecentTTL
	}
	if uidMax <= 0 {
		uidMax = dnsRecentUIDMax
	}
	return &dnsRecentRing{
		perUIDMax: perUIDMax,
		ttl:       ttl,
		uidMax:    uidMax,
		buckets:   make(map[uint32]*dnsRecentUIDBucket),
	}
}

func (r *dnsRecentRing) add(uid uint32, s DNSPacketSummary) {
	if r == nil || uid == 0 {
		return
	}
	now := s.When
	if now.IsZero() {
		now = time.Now()
		s.When = now
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.evictExpiredLocked(now)
	if len(r.buckets) >= r.uidMax {
		r.evictOldestUIDLocked()
	}

	b := r.buckets[uid]
	if b == nil {
		b = &dnsRecentUIDBucket{entries: make([]DNSPacketSummary, r.perUIDMax)}
		r.buckets[uid] = b
	}
	b.entries[b.next] = s
	b.next = (b.next + 1) % len(b.entries)
	if b.size < len(b.entries) {
		b.size++
	}
	b.seenAt = now
}

func (r *dnsRecentRing) snapshot(uid uint32, now time.Time) []DNSPacketSummary {
	if r == nil || uid == 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.evictExpiredLocked(now)
	b := r.buckets[uid]
	if b == nil || b.size == 0 {
		return nil
	}

	out := make([]DNSPacketSummary, 0, b.size)
	start := (b.next - b.size + len(b.entries)) % len(b.entries)
	for i := 0; i < b.size; i++ {
		idx := (start + i) % len(b.entries)
		it := b.entries[idx]
		if now.Sub(it.When) > r.ttl {
			continue
		}
		out = append(out, it)
	}
	return out
}

func (r *dnsRecentRing) evictExpiredLocked(now time.Time) {
	for uid, b := range r.buckets {
		if b == nil {
			delete(r.buckets, uid)
			continue
		}
		if b.size == 0 || now.Sub(b.seenAt) > r.ttl {
			delete(r.buckets, uid)
		}
	}
}

func (r *dnsRecentRing) evictOldestUIDLocked() {
	if len(r.buckets) == 0 {
		return
	}
	var (
		haveOldest bool
		oldUID     uint32
		oldSeen    time.Time
	)
	for uid, b := range r.buckets {
		if b == nil {
			delete(r.buckets, uid)
			continue
		}
		if !haveOldest || b.seenAt.Before(oldSeen) {
			haveOldest = true
			oldUID = uid
			oldSeen = b.seenAt
		}
	}
	if haveOldest {
		delete(r.buckets, oldUID)
	}
}

func dnsSummaryFromRaw(re rawEvent) DNSPacketSummary {
	s := DNSPacketSummary{
		When:       re.when,
		Src:        ipToString(re.src),
		Dst:        ipToString(re.dst),
		QName:      re.dnsQName,
		QType:      re.dnsQType,
		QTypeKnown: re.dnsQTypeKnown,
		RCode:      re.dnsRCode,
		RCodeKnown: re.dnsRCodeKnown,
	}
	return s
}

func formatDNSPretriggerLines(pre []DNSPacketSummary) []string {
	if len(pre) == 0 {
		return []string{"# no pretrigger samples available"}
	}
	rows := append([]DNSPacketSummary(nil), pre...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].When.Before(rows[j].When) })
	out := make([]string, 0, len(rows))
	for _, s := range rows {
		qtype := "?"
		if s.QTypeKnown {
			if t, ok := dns.TypeToString[s.QType]; ok {
				qtype = t
			} else {
				qtype = fmt.Sprintf("TYPE%d", s.QType)
			}
		}
		rcode := "?"
		if s.RCodeKnown {
			if r, ok := dns.RcodeToString[int(s.RCode)]; ok {
				rcode = r
			} else {
				rcode = fmt.Sprintf("RCODE%d", s.RCode)
			}
		}
		out = append(out,
			fmt.Sprintf("%s src=%s dst=%s qname=%q qtype=%s rcode=%s",
				s.When.Format(time.RFC3339Nano), s.Src, s.Dst, s.QName, qtype, rcode),
		)
	}
	return out
}

func ipToString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
