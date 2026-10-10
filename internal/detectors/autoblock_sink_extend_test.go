package detectors

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/detectors/core"
	"cfm/internal/edgeban"
	"cfm/internal/firewall"
)

// sinkSetFake models one block set shared by every section: AddBlock replaces
// the element (as both backends do), AddBlockBatch only adds or extends.
type sinkSetFake struct {
	firewall.Backend
	left    map[string]time.Duration // 0 = permanent
	reports []int                    // ReportBlock TTLs (seconds)
}

func (f *sinkSetFake) AddBlock(ip net.IP, _ string, ttl *time.Duration) error {
	f.left[ip.String()] = 0
	if ttl != nil {
		f.left[ip.String()] = *ttl
	}
	return nil
}

// ReportBlock (the fleet report after a block) does nothing here.
func (f *sinkSetFake) ReportBlock(_, _, _, _ string, ttl int) error {
	f.reports = append(f.reports, ttl)
	return nil
}

func (f *sinkSetFake) AddBlockBatch(entries []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	var cur []firewall.SetElementTimed
	for ip, d := range f.left {
		cur = append(cur, firewall.SetElementTimed{Elem: ip, Expires: d})
	}
	v4, _, skipped := firewall.SplitBlockEntries(entries)
	plan := firewall.PlanBlockBatch(v4, cur)
	r := firewall.BlockBatchResult{Skipped: skipped, Kept: plan.Kept}
	for _, w := range plan.Writes {
		r.Added++
		f.left[w.IP.String()] = w.TTL
	}
	return r, nil
}

// A webdetector 1h block of a scanner waf_security had banned for 7d must not
// cut the ban to an hour (mars, 2026-10-09: the exec backend replaced the
// element and the 7d ban expired after an hour).
func TestSectionSinkTTLBlockNeverShortens(t *testing.T) {
	fw := &sinkSetFake{left: map[string]time.Duration{}}
	waf := &sectionSink{section: "waf_security", pol: blockPolicy{Mode: "ttl", TTL: 7 * 24 * time.Hour}, fw: fw, inner: &capturingSink{}}
	web := &sectionSink{section: "webdetector", pol: blockPolicy{Mode: "ttl", TTL: time.Hour}, fw: fw, inner: &capturingSink{}}

	ip := "34.153.214.160"
	waf.Publish(core.Alert{When: time.Now(), Kind: "WAF/PHP_WRAPPER", Key: ip})
	if got := fw.left[ip]; got != 7*24*time.Hour {
		t.Fatalf("after the WAF ban: %v left, want 7d (blocks: %v)", got, fw.left)
	}
	web.Publish(core.Alert{When: time.Now(), Kind: "WEB/403/BOT", Key: ip})
	if got := fw.left[ip]; got != 7*24*time.Hour {
		t.Fatalf("after a 1h webdetector block: %v left, want the 7d ban kept", got)
	}
	// The kept ban is marked, and each section still reports its own ban to
	// the fleet as before (the 7d one may have been local-only).
	webOut := web.inner.(*capturingSink).got
	if len(webOut) != 1 || webOut[0].Extra["block_kept"] != "longer" || webOut[0].Extra["blocked"] != "yes" {
		t.Fatalf("webdetector outcome: %+v, want blocked=yes block_kept=longer", webOut)
	}
	if len(fw.reports) != 2 || fw.reports[0] != 7*24*3600 || fw.reports[1] != 3600 {
		t.Fatalf("ReportBlock TTLs %v, want each section's own (7d, then 1h)", fw.reports)
	}
}

// The detector log line shows a kept ban.
func TestOutcomeBlockedShowsKeptBan(t *testing.T) {
	cases := []struct {
		extra map[string]string
		want  string
	}{
		{map[string]string{"blocked": "yes", "block_mode": "ttl", "ttl": "1h0m0s", "block_kept": "longer"}, "Yes (ttl=1h0m0s; longer ban kept)"},
		{map[string]string{"blocked": "yes", "block_mode": "ttl", "block_kept": "longer"}, "Yes (ttl; longer ban kept)"},
		{map[string]string{"blocked": "yes", "block_mode": "ttl", "ttl": "1h0m0s"}, "Yes (ttl=1h0m0s)"},
		{map[string]string{"blocked": "yes", "block_mode": "permanent"}, "Yes (permanent)"},
		{nil, "No"},
	}
	for _, c := range cases {
		if got := outcomeBlocked(c.extra); got != c.want {
			t.Errorf("outcomeBlocked(%v) = %q, want %q", c.extra, got, c.want)
		}
	}
}

// A web section's ban also goes to the edge ban store (a client behind a
// trusted proxy never meets the nft drop); a mail/SSH section's and a
// dry run's do not.
func TestSectionSinkEdgeBan(t *testing.T) {
	store := edgeban.New(filepath.Join(t.TempDir(), "edgeban.json"))
	edgeban.SetDefault(store)
	t.Cleanup(func() { edgeban.SetDefault(nil) })

	fw := &sinkSetFake{left: map[string]time.Duration{}}
	pub := func(section, mode string, ip string) {
		s := &sectionSink{section: section, pol: blockPolicy{Mode: mode, TTL: 6 * time.Hour}, fw: fw, inner: &capturingSink{}}
		s.Publish(core.Alert{When: time.Now(), Kind: "X/Y", Key: ip})
	}
	pub("waf_security", "ttl", "34.153.214.160")
	pub("ssh_auth", "ttl", "198.51.100.22")
	pub("webdetector", "dryrun", "198.51.100.23")
	pub("challenge_cookie_discard", "permanent", "198.51.100.24")

	var blocks []firewall.SetElementTimed
	for ip := range fw.left {
		blocks = append(blocks, firewall.SetElementTimed{Elem: ip})
	}
	store.Reconcile(edgeban.Snapshot{Blocks: blocks, ReadAt: time.Now().Add(time.Second)})
	for ip, want := range map[string]bool{
		"34.153.214.160": true,  // web section
		"198.51.100.22":  false, // ssh: nft only
		"198.51.100.23":  false, // dry run: nothing
		"198.51.100.24":  true,  // web section, permanent
	} {
		if got, _ := store.Banned(ip); got != want {
			t.Errorf("%s edge-banned=%v, want %v", ip, got, want)
		}
	}
}
