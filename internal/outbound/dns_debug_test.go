package outbound

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newDNSDebugTestCapture(t *testing.T) (*DNSDebugCapture, string) {
	t.Helper()
	dir := t.TempDir()
	rt := Runtime{
		DNSDebugEnabled:     true,
		DNSDebugSampleCount: 10,
		DNSDebugDuration:    30 * time.Second,
		DNSDebugDir:         dir,
	}
	return NewDNSDebugCapture(rt), dir
}

func createSession(t *testing.T, d *DNSDebugCapture, uid, gid uint32, started time.Time, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatalf("open test log: %v", err)
	}
	k := dnsDebugKey{uid: uid, gid: gid}
	d.sessions[k] = &dnsDebugSession{
		key:     k,
		started: started,
		expires: started.Add(time.Minute),
		file:    f,
		path:    path,
	}
	t.Cleanup(func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.closeSessionLocked(k)
	})
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	return string(b)
}

func TestDNSDebugWriteSample_UIDFallbackWhenCallbackGIDMissing(t *testing.T) {
	d, dir := newDNSDebugTestCapture(t)
	uid := uint32(501)
	triggerGID := uint32(111)
	logPath := filepath.Join(dir, "trigger.log")
	createSession(t, d, uid, triggerGID, time.Now(), logPath)

	d.writeSample(uid, 0, dnsDebugMsg{proto: "udp", src: "1.1.1.1", dst: "8.8.8.8", qname: "example.org.", qtype: 1, rcode: 0})

	got := readFile(t, logPath)
	if !strings.Contains(got, "uid=501") {
		t.Fatalf("expected fallback write for uid, got %q", got)
	}
}

func TestDNSDebugWriteSample_ExactUIDGIDMatch(t *testing.T) {
	d, dir := newDNSDebugTestCapture(t)
	uid := uint32(601)
	gid := uint32(222)
	logPath := filepath.Join(dir, "exact.log")
	createSession(t, d, uid, gid, time.Now(), logPath)

	d.writeSample(uid, gid, dnsDebugMsg{proto: "udp", src: "1.1.1.1", dst: "8.8.8.8", qname: "example.net.", qtype: 1, rcode: 0})

	got := readFile(t, logPath)
	if !strings.Contains(got, "uid=601 gid=222") {
		t.Fatalf("expected exact uid/gid write, got %q", got)
	}
}

func TestDNSDebugWriteSample_ConcurrentDifferentGIDsSameUID(t *testing.T) {
	d, dir := newDNSDebugTestCapture(t)
	uid := uint32(701)
	gidA := uint32(3001)
	gidB := uint32(3002)
	pathA := filepath.Join(dir, "gid-a.log")
	pathB := filepath.Join(dir, "gid-b.log")
	createSession(t, d, uid, gidA, time.Now(), pathA)
	createSession(t, d, uid, gidB, time.Now(), pathB)

	d.writeSample(uid, gidA, dnsDebugMsg{proto: "udp", src: "1.1.1.1", dst: "8.8.8.8", qname: "a.example.", qtype: 1, rcode: 0})
	d.writeSample(uid, gidB, dnsDebugMsg{proto: "udp", src: "1.1.1.1", dst: "8.8.8.8", qname: "b.example.", qtype: 1, rcode: 0})

	contentA := readFile(t, pathA)
	contentB := readFile(t, pathB)
	if !strings.Contains(contentA, "gid=3001") {
		t.Fatalf("expected gid A log entry, got %q", contentA)
	}
	if !strings.Contains(contentB, "gid=3002") {
		t.Fatalf("expected gid B log entry, got %q", contentB)
	}
}

func TestParseDNSFromPacket_UDPIPv4RealisticPayload(t *testing.T) {
	dm := newDNSResponseMsg(t, "udp.example.")
	dnsPayload, err := dm.Pack()
	if err != nil {
		t.Fatalf("pack dns msg: %v", err)
	}
	packet := buildIPv4UDPPacket(dnsPayload)

	msg, ok := parseDNSFromPacket(packet)
	if !ok {
		t.Fatalf("expected udp parse success; payload_len=%d packet_len=%d", len(dnsPayload), len(packet))
	}
	if msg.proto != "udp" || msg.qname != "udp.example." || msg.qtype != dns.TypeA {
		t.Fatalf("unexpected udp parse result: %+v", msg)
	}
}

func TestParseDNSFromPacket_TCPIPv4RealisticPayload(t *testing.T) {
	dm := newDNSResponseMsg(t, "tcp.example.")
	dnsPayload, err := dm.Pack()
	if err != nil {
		t.Fatalf("pack dns msg: %v", err)
	}
	packet := buildIPv4TCPPacket(dnsPayload)

	msg, ok := parseDNSFromPacket(packet)
	if !ok {
		t.Fatalf("expected tcp parse success; payload_len=%d packet_len=%d", len(dnsPayload), len(packet))
	}
	if msg.proto != "tcp" || msg.qname != "tcp.example." || msg.qtype != dns.TypeA {
		t.Fatalf("unexpected tcp parse result: %+v", msg)
	}
}

func newDNSResponseMsg(t *testing.T, qname string) *dns.Msg {
	t.Helper()
	dm := &dns.Msg{}
	dm.SetReply(&dns.Msg{
		MsgHdr: dns.MsgHdr{Id: 1234, RecursionDesired: true},
		Question: []dns.Question{
			{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	})
	dm.Authoritative = true
	dm.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(1, 2, 3, 4),
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{strings.Repeat("x", 180)},
		},
	}
	return dm
}

func buildIPv4UDPPacket(dnsPayload []byte) []byte {
	ipHeaderLen := 20
	udpHeaderLen := 8
	packet := make([]byte, ipHeaderLen+udpHeaderLen+len(dnsPayload))
	packet[0] = 0x45
	packet[9] = 17 // UDP
	copy(packet[12:16], []byte{10, 0, 0, 5})
	copy(packet[16:20], []byte{8, 8, 8, 8})
	udp := packet[ipHeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], 53000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHeaderLen+len(dnsPayload)))
	copy(packet[ipHeaderLen+udpHeaderLen:], dnsPayload)
	return packet
}

func buildIPv4TCPPacket(dnsPayload []byte) []byte {
	ipHeaderLen := 20
	tcpHeaderLen := 20
	packet := make([]byte, ipHeaderLen+tcpHeaderLen+2+len(dnsPayload))
	packet[0] = 0x45
	packet[9] = 6 // TCP
	copy(packet[12:16], []byte{10, 0, 0, 5})
	copy(packet[16:20], []byte{1, 1, 1, 1})
	tcp := packet[ipHeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 53001)
	binary.BigEndian.PutUint16(tcp[2:4], 53)
	tcp[12] = byte((tcpHeaderLen / 4) << 4) // data offset
	dnsStart := ipHeaderLen + tcpHeaderLen
	binary.BigEndian.PutUint16(packet[dnsStart:dnsStart+2], uint16(len(dnsPayload)))
	copy(packet[dnsStart+2:], dnsPayload)
	return packet
}
