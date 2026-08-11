package mailtraffic

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/mailmeter"
)

func TestDomainOf(t *testing.T) {
	cases := map[string]string{
		"support@ordermusic.gr": "ordermusic.gr",
		"Info@AxidWear.com":     "axidwear.com", // domain lowercased defensively
		"evafeiadis":            mailmeter.HostWide,
		mailmeter.HostWide:      mailmeter.HostWide,
		"@nodomain":             mailmeter.HostWide, // no local part → no usable domain
		"trailing@":             mailmeter.HostWide, // empty domain
	}
	for in, want := range cases {
		if got := domainOf(in); got != want {
			t.Errorf("domainOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// The tailer starts at EOF on first sight (no history rescan), then reads only
// newly-appended lines on subsequent polls.
func TestCollectorTailsAppendsFromEOF(t *testing.T) {
	st := openTemp(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "exim_mainlog")
	writeFile(t, log, eximLine("support@ordermusic.gr")+eximLine("support@ordermusic.gr"))

	c := newCollector(st)
	now := time.Unix(1_700_000_000, 0)

	// First poll: establishes position at EOF, so the two pre-existing lines are
	// NOT counted (we don't rescan history on startup).
	c.pollFile(now, log, mailmeter.ParseEximLine, mailmeter.ParseEximDelivery)
	sum, _ := st.trafficSummaryAt(now, 24, nil, 10)
	if find(sum.TopOutboundSenders, "support@ordermusic.gr") != -1 {
		t.Fatalf("pre-existing history must not be counted: %+v", sum.TopOutboundSenders)
	}

	// Append three new lines, poll again: only the appends count.
	appendFile(t, log, eximLine("support@ordermusic.gr")+eximLine("support@ordermusic.gr")+eximLine("info@axidwear.com"))
	c.pollFile(now, log, mailmeter.ParseEximLine, mailmeter.ParseEximDelivery)
	sum, _ = st.trafficSummaryAt(now, 24, nil, 10)
	if got := find(sum.TopOutboundSenders, "support@ordermusic.gr"); got != 2 {
		t.Fatalf("appended support lines = %d, want 2", got)
	}
	if got := find(sum.TopOutboundSenders, "info@axidwear.com"); got != 1 {
		t.Fatalf("appended info line = %d, want 1", got)
	}
}

// A rotation (new inode) resets the offset to 0 so the fresh file is read from
// the start, not skipped as if already consumed.
func TestCollectorHandlesRotation(t *testing.T) {
	st := openTemp(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "exim_mainlog")
	writeFile(t, log, eximLine("a@x.gr"))
	c := newCollector(st)
	now := time.Unix(1_700_000_000, 0)
	c.pollFile(now, log, mailmeter.ParseEximLine, mailmeter.ParseEximDelivery) // establish position at EOF

	// Rotate the way logrotate `create` does: build the replacement as a sibling
	// (so it gets a distinct inode while the old file still holds its own), then
	// rename it over the path. Renaming over avoids the tmpfs inode-reuse that a
	// remove+recreate can hit, making the inode change deterministic.
	rotated := filepath.Join(dir, "exim_mainlog.rotated")
	writeFile(t, rotated, eximLine("b@x.gr")+eximLine("b@x.gr"))
	if err := os.Rename(rotated, log); err != nil {
		t.Fatal(err)
	}
	c.pollFile(now, log, mailmeter.ParseEximLine, mailmeter.ParseEximDelivery)

	sum, _ := st.trafficSummaryAt(now, 24, nil, 10)
	if got := find(sum.TopOutboundSenders, "b@x.gr"); got != 2 {
		t.Fatalf("post-rotation lines = %d, want 2 (rotation not detected?)", got)
	}
}

// Truncation (copytruncate: same inode, smaller size) also resets to 0.
func TestCollectorHandlesTruncate(t *testing.T) {
	st := openTemp(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "exim_mainlog")
	writeFile(t, log, eximLine("a@x.gr")+eximLine("a@x.gr")+eximLine("a@x.gr"))
	c := newCollector(st)
	now := time.Unix(1_700_000_000, 0)
	c.pollFile(now, log, mailmeter.ParseEximLine, mailmeter.ParseEximDelivery) // position at EOF

	// Truncate in place and write one fresh line.
	writeFile(t, log, eximLine("c@x.gr"))
	c.pollFile(now, log, mailmeter.ParseEximLine, mailmeter.ParseEximDelivery)

	sum, _ := st.trafficSummaryAt(now, 24, nil, 10)
	if got := find(sum.TopOutboundSenders, "c@x.gr"); got != 1 {
		t.Fatalf("post-truncate line = %d, want 1", got)
	}
}

func TestEnableShutdownLifecycle(t *testing.T) {
	if SharedStore() != nil {
		t.Skip("mailtraffic already enabled in this process")
	}
	if err := Enable(filepath.Join(t.TempDir(), "mt.db")); err != nil {
		t.Fatal(err)
	}
	if SharedStore() == nil {
		t.Fatal("SharedStore nil after Enable")
	}
	Shutdown()
	if SharedStore() != nil {
		t.Fatal("SharedStore non-nil after Shutdown")
	}
}

// ---- helpers ----

func eximLine(user string) string {
	return "2026-08-07 12:00:00 1abc-def-01 <= " + user +
		" H=(h) [10.0.0.5]:5 P=esmtpa A=dovecot_login:" + user + " S=1\n"
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}
