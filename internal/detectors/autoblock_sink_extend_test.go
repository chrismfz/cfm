package detectors

import (
	"net"
	"testing"
	"time"

	"cfm/internal/detectors/core"
	"cfm/internal/firewall"
)

// sinkSetFake models one block set shared by every section: AddBlock replaces
// the element (as both backends do), AddBlockBatch only adds or extends.
type sinkSetFake struct {
	firewall.Backend
	left map[string]time.Duration // 0 = permanent
}

func (f *sinkSetFake) AddBlock(ip net.IP, _ string, ttl *time.Duration) error {
	f.left[ip.String()] = 0
	if ttl != nil {
		f.left[ip.String()] = *ttl
	}
	return nil
}

// ReportBlock (the fleet report after a block) does nothing here.
func (f *sinkSetFake) ReportBlock(string, string, string, string, int) error { return nil }

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
}
