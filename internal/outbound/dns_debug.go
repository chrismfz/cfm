package outbound

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"

	nflog "github.com/florianl/go-nflog/v2"
	"github.com/mdlayher/netlink"
	"github.com/miekg/dns"
)

const (
	dnsDebugTable      = "cfm_dnsdebug"
	dnsDebugChain      = "output"
	dnsDebugUIDSet     = "active_uids"
	dnsDebugNFLOGGroup = uint16(40123)

	dnsDebugMaxBytes      = 256 * 1024
	dnsDebugRetentionMax  = 128
	dnsDebugRetentionAge  = 24 * time.Hour
	dnsDebugCleanupJitter = 10 * time.Second
)

type dnsDebugKey struct {
	uid uint32
	gid uint32
}

type dnsDebugSession struct {
	key      dnsDebugKey
	started  time.Time
	expires  time.Time
	file     *os.File
	path     string
	lines    int
	bytes    int
	truncMsg bool
}

// DNSDebugCapture manages temporary per-uid DNS packet capture for outbound
// DNS verdicts. It installs nft hooks that mirror traffic into a dedicated
// NFLOG group and writes bounded forensic logs.
type DNSDebugCapture struct {
	rt Runtime

	mu                 sync.Mutex
	sessions           map[dnsDebugKey]*dnsDebugSession
	unmatchedPacketLog int
}

func NewDNSDebugCapture(rt Runtime) *DNSDebugCapture {
	return &DNSDebugCapture{rt: rt, sessions: make(map[dnsDebugKey]*dnsDebugSession)}
}

func (d *DNSDebugCapture) Start(ctx context.Context) {
	if d == nil || !d.rt.DNSDebugEnabled {
		return
	}
	if err := d.ensureNFT(); err != nil {
		logging.Logf("[outbound-dns-debug] nft init failed: %v", err)
		return
	}
	go d.runConsumer(ctx)
	go func() {
		<-ctx.Done()
		d.shutdown()
	}()
}

// Trigger arms (or skips) a temporary uid-specific DNS capture window.
func (d *DNSDebugCapture) Trigger(uid, gid uint32, when time.Time) {
	if d == nil || !d.rt.DNSDebugEnabled {
		return
	}
	if uid == 0 {
		return
	}
	if when.IsZero() {
		when = time.Now()
	}

	key := dnsDebugKey{uid: uid, gid: gid}
	cooldownUntil := when.Add(d.rt.DNSDebugDuration + dnsDebugCleanupJitter)

	d.mu.Lock()
	if cur := d.sessions[key]; cur != nil {
		if time.Now().Before(cur.expires.Add(dnsDebugCleanupJitter)) {
			d.mu.Unlock()
			return
		}
		d.closeSessionLocked(key)
	}
	path, f, err := d.openLog(gid, when)
	if err != nil {
		d.mu.Unlock()
		logging.Logf("[outbound-dns-debug] open log failed uid=%d gid=%d: %v", uid, gid, err)
		return
	}
	d.sessions[key] = &dnsDebugSession{
		key:     key,
		started: when,
		expires: cooldownUntil,
		file:    f,
		path:    path,
	}
	d.mu.Unlock()

	if err := d.addUID(uid, d.rt.DNSDebugDuration); err != nil {
		logging.Logf("[outbound-dns-debug] nft add uid failed uid=%d: %v", uid, err)
	}
	d.pruneRetention()
}

func (d *DNSDebugCapture) runConsumer(ctx context.Context) {
	nf, err := nflog.Open(&nflog.Config{Group: dnsDebugNFLOGGroup, Copymode: nflog.CopyPacket})
	if err != nil {
		logging.Logf("[outbound-dns-debug] nflog open failed group=%d: %v", dnsDebugNFLOGGroup, err)
		return
	}
	defer nf.Close()
	_ = nf.Con.SetReadBuffer(256 * 1024)
	_ = nf.SetOption(netlink.NoENOBUFS, true)

	cb := func(a nflog.Attribute) int {
		if a.Payload == nil || len(*a.Payload) == 0 || a.UID == nil {
			return 0
		}
		uid := *a.UID
		gid := uint32(0)
		if a.GID != nil {
			gid = *a.GID
		}
		msg, ok := parseDNSFromPacket(*a.Payload)
		if !ok {
			return 0
		}
		d.writeSample(uid, gid, msg)
		return 0
	}
	if err := nf.Register(ctx, cb); err != nil {
		logging.Logf("[outbound-dns-debug] nflog register failed: %v", err)
	}
}

func (d *DNSDebugCapture) writeSample(uid, gid uint32, msg dnsDebugMsg) {
	key := dnsDebugKey{uid: uid, gid: gid}
	now := time.Now()

	d.mu.Lock()
	s := d.sessions[key]
	if s == nil {
		key, s = d.lookupUIDFallbackLocked(uid)
	}
	if s == nil {
		d.unmatchedPacketLog++
		if d.unmatchedPacketLog == 1 || d.unmatchedPacketLog%100 == 0 {
			logging.Logf("[outbound-dns-debug] packet seen but no active session matched uid=%d gid=%d unmatched_total=%d active_sessions=%d", uid, gid, d.unmatchedPacketLog, len(d.sessions))
		}
		d.mu.Unlock()
		return
	}
	if now.After(s.expires) {
		d.closeSessionLocked(key)
		d.mu.Unlock()
		return
	}

	if s.lines >= d.rt.DNSDebugSampleCount || s.bytes >= dnsDebugMaxBytes {
		if !s.truncMsg {
			n, _ := fmt.Fprintf(s.file, "%s limit reached lines=%d bytes=%d\n", now.Format(time.RFC3339Nano), s.lines, s.bytes)
			s.bytes += n
			s.truncMsg = true
		}
		d.mu.Unlock()
		return
	}
	line := fmt.Sprintf("%s uid=%d gid=%d proto=%s src=%s dst=%s qname=%q qtype=%s rcode=%s\n",
		now.Format(time.RFC3339Nano), uid, gid, msg.proto, msg.src, msg.dst, msg.qname, dns.TypeToString[msg.qtype], dns.RcodeToString[msg.rcode])
	n, err := s.file.WriteString(line)
	if err == nil {
		s.lines++
		s.bytes += n
	}
	d.mu.Unlock()
}

func (d *DNSDebugCapture) lookupUIDFallbackLocked(uid uint32) (dnsDebugKey, *dnsDebugSession) {
	var (
		found   bool
		chosenK dnsDebugKey
		chosenS *dnsDebugSession
	)
	for k, s := range d.sessions {
		if s == nil || k.uid != uid {
			continue
		}
		if !found || s.started.After(chosenS.started) || (s.started.Equal(chosenS.started) && k.gid < chosenK.gid) {
			found = true
			chosenK = k
			chosenS = s
		}
	}
	return chosenK, chosenS
}

func (d *DNSDebugCapture) openLog(gid uint32, when time.Time) (string, *os.File, error) {
	dir := d.rt.DNSDebugDir
	if dir == "" {
		dir = "/var/log/cfm/outbound"
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", nil, err
	}
	name := fmt.Sprintf("%d-dns-%d.log", gid, when.Unix())
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return "", nil, err
	}
	_, _ = fmt.Fprintf(f, "# cfm outbound dns debug capture gid=%d started=%s duration=%s sample_limit=%d\n", gid, when.Format(time.RFC3339Nano), d.rt.DNSDebugDuration, d.rt.DNSDebugSampleCount)
	return path, f, nil
}

func (d *DNSDebugCapture) ensureNFT() error {
	_ = d.cleanupNFT()
	cmds := [][]string{
		{"add", "table", "inet", dnsDebugTable},
		{"add", "set", "inet", dnsDebugTable, dnsDebugUIDSet, "{", "type", "uid", ";", "flags", "timeout", ";", "}"},
		{"add", "chain", "inet", dnsDebugTable, dnsDebugChain, "{", "type", "filter", "hook", "output", "priority", "-50", ";", "policy", "accept", ";", "}"},
		{"add", "rule", "inet", dnsDebugTable, dnsDebugChain, "meta", "skuid", "@" + dnsDebugUIDSet, "udp", "dport", "53", "nflog", "group", strconv.Itoa(int(dnsDebugNFLOGGroup))},
		{"add", "rule", "inet", dnsDebugTable, dnsDebugChain, "meta", "skuid", "@" + dnsDebugUIDSet, "tcp", "dport", "53", "nflog", "group", strconv.Itoa(int(dnsDebugNFLOGGroup))},
	}
	for _, c := range cmds {
		if out, err := exec.Command("nft", c...).CombinedOutput(); err != nil {
			return fmt.Errorf("nft %s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (d *DNSDebugCapture) addUID(uid uint32, dur time.Duration) error {
	if dur <= 0 {
		dur = 30 * time.Second
	}
	cmd := []string{"add", "element", "inet", dnsDebugTable, dnsDebugUIDSet, "{", strconv.FormatUint(uint64(uid), 10), "timeout", dur.String(), "}"}
	if out, err := exec.Command("nft", cmd...).CombinedOutput(); err != nil {
		// best effort idempotency: retry by replacing element timeout.
		deleteCmd := []string{"delete", "element", "inet", dnsDebugTable, dnsDebugUIDSet, "{", strconv.FormatUint(uint64(uid), 10), "}"}
		_, _ = exec.Command("nft", deleteCmd...).CombinedOutput()
		if out2, err2 := exec.Command("nft", cmd...).CombinedOutput(); err2 != nil {
			return fmt.Errorf("%v: %s / retry: %v: %s", err, strings.TrimSpace(string(out)), err2, strings.TrimSpace(string(out2)))
		}
	}
	return nil
}

func (d *DNSDebugCapture) pruneRetention() {
	dir := d.rt.DNSDebugDir
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type item struct {
		path string
		mod  time.Time
	}
	items := make([]item, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") || !strings.Contains(e.Name(), "-dns-") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if time.Since(fi.ModTime()) > dnsDebugRetentionAge {
			_ = os.Remove(p)
			continue
		}
		items = append(items, item{path: p, mod: fi.ModTime()})
	}
	if len(items) <= dnsDebugRetentionMax {
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mod.After(items[j].mod) })
	for _, it := range items[dnsDebugRetentionMax:] {
		_ = os.Remove(it.path)
	}
}

func (d *DNSDebugCapture) closeSessionLocked(k dnsDebugKey) {
	s := d.sessions[k]
	if s == nil {
		return
	}
	_ = s.file.Close()
	delete(d.sessions, k)
}

func (d *DNSDebugCapture) shutdown() {
	d.mu.Lock()
	for k := range d.sessions {
		d.closeSessionLocked(k)
	}
	d.mu.Unlock()
	_ = d.cleanupNFT()
}

func (d *DNSDebugCapture) cleanupNFT() error {
	_, _ = exec.Command("nft", "flush", "table", "inet", dnsDebugTable).CombinedOutput()
	if out, err := exec.Command("nft", "delete", "table", "inet", dnsDebugTable).CombinedOutput(); err != nil {
		s := string(out)
		if strings.Contains(s, "No such file") || strings.Contains(s, "No such table") {
			return nil
		}
		return fmt.Errorf("nft delete table: %v: %s", err, strings.TrimSpace(s))
	}
	return nil
}

type dnsDebugMsg struct {
	proto    string
	src, dst string
	qname    string
	qtype    uint16
	rcode    int
}

func parseDNSFromPacket(p []byte) (dnsDebugMsg, bool) {
	var m dnsDebugMsg
	if len(p) < 1 {
		return m, false
	}
	var l4 []byte
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return m, false
		}
		ihl := int(p[0]&0x0F) * 4
		if len(p) < ihl+8 {
			return m, false
		}
		proto := p[9]
		m.src = net.IPv4(p[12], p[13], p[14], p[15]).String()
		m.dst = net.IPv4(p[16], p[17], p[18], p[19]).String()
		l4 = p[ihl:]
		if proto == 17 {
			m.proto = "udp"
			if len(l4) < 8 {
				return m, false
			}
			l4 = l4[8:]
		} else if proto == 6 {
			m.proto = "tcp"
			if len(l4) < 20 {
				return m, false
			}
			off := int((l4[12] >> 4) * 4)
			if len(l4) < off+2 {
				return m, false
			}
			// TCP DNS has 2-byte length prefix.
			l4 = l4[off:]
			if len(l4) < 2 {
				return m, false
			}
			dlen := int(binary.BigEndian.Uint16(l4[:2]))
			if dlen <= 0 || len(l4) < 2+dlen {
				return m, false
			}
			l4 = l4[2 : 2+dlen]
		} else {
			return m, false
		}
	case 6:
		if len(p) < 40 {
			return m, false
		}
		proto := p[6]
		m.src = net.IP(p[8:24]).String()
		m.dst = net.IP(p[24:40]).String()
		l4 = p[40:]
		if proto == 17 {
			m.proto = "udp"
			if len(l4) < 8 {
				return m, false
			}
			l4 = l4[8:]
		} else if proto == 6 {
			m.proto = "tcp"
			if len(l4) < 20 {
				return m, false
			}
			off := int((l4[12] >> 4) * 4)
			if len(l4) < off+2 {
				return m, false
			}
			l4 = l4[off:]
			if len(l4) < 2 {
				return m, false
			}
			dlen := int(binary.BigEndian.Uint16(l4[:2]))
			if dlen <= 0 || len(l4) < 2+dlen {
				return m, false
			}
			l4 = l4[2 : 2+dlen]
		} else {
			return m, false
		}
	default:
		return m, false
	}
	var dm dns.Msg
	if err := dm.Unpack(l4); err != nil {
		return m, false
	}
	if len(dm.Question) > 0 {
		m.qname = dm.Question[0].Name
		m.qtype = dm.Question[0].Qtype
	}
	m.rcode = dm.Rcode
	return m, true
}
