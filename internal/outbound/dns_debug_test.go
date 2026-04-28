package outbound

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
