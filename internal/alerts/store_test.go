package alerts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T, maxAge time.Duration, maxRows int) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "alerts.db"), maxAge, maxRows)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func seed(t *testing.T, s *Store, now time.Time) {
	t.Helper()
	rows := []Record{
		{TsUnix: now.Add(-3 * time.Hour).Unix(), Kind: "WAF/SQLI", IP: "31.217.169.106", Country: "Athens, Greece", CountryISO: "GR",
			ASN: "AS6799 OTEnet S.A.", Reason: "WAF/SQLI", Severity: "warn", Delivery: DeliveryNotified,
			Samples: []string{`[waf] reason=WAF_SQLI rule=210 method=get host=shop.example.gr uri=/?id=1'`}, Extra: map[string]string{"mode": "ttl"}, TTLSec: 900},
		{TsUnix: now.Add(-2 * time.Hour).Unix(), Kind: "WAF/SQLI", IP: "79.103.201.90", CountryISO: "GR", ASN: "AS1241 Nova Telecommunications",
			Reason: "WAF/SQLI", Severity: "warning", Delivery: DeliveryDeduped},
		{TsUnix: now.Add(-1 * time.Hour).Unix(), Kind: "MODSEC/403", IP: "168.144.246.79", CountryISO: "SG", ASN: "AS14061 DigitalOcean, LLC",
			Reason: "MODSEC/403", Delivery: DeliveryNotifierOff,
			Samples: []string{`ModSecurity: Access denied [hostname "ar.mindwiseapps.com"] [uri "/license.txt"]`}},
		{TsUnix: now.Add(-30 * time.Minute).Unix(), Kind: "MYSQL/CONN_LIMIT", Reason: "conn_limit user=spitaki_wp total=49 max=40",
			Severity: "critical", Delivery: DeliveryNoChannels, Extra: map[string]string{"host": "localhost"}},
		{TsUnix: now.Add(-48 * time.Hour).Unix(), Kind: "outbound_abuse", IP: "203.0.113.9", Delivery: DeliveryNotified},
	}
	for _, r := range rows {
		s.Add(r)
	}
	s.Flush()
}

func TestListFilters(t *testing.T) {
	s := openTestStore(t, 0, 0)
	now := time.Now()
	seed(t, s, now)
	day := Filter{From: now.Add(-24 * time.Hour)}

	cases := []struct {
		name string
		f    Filter
		want []string // kinds, newest first
	}{
		{"window", day, []string{"MYSQL/CONN_LIMIT", "MODSEC/403", "WAF/SQLI", "WAF/SQLI"}},
		{"category", Filter{From: day.From, Categories: []string{"waf"}}, []string{"WAF/SQLI", "WAF/SQLI"}},
		{"country iso", Filter{From: day.From, Country: "gr"}, []string{"WAF/SQLI", "WAF/SQLI"}},
		{"country name", Filter{From: day.From, Country: "Greece"}, []string{"WAF/SQLI"}},
		{"asn number", Filter{From: day.From, ASN: "AS1241"}, []string{"WAF/SQLI"}},
		{"asn name", Filter{From: day.From, ASN: "digitalocean"}, []string{"MODSEC/403"}},
		{"severity floor", Filter{From: day.From, MinSeverity: "warning"}, []string{"MYSQL/CONN_LIMIT", "WAF/SQLI", "WAF/SQLI"}},
		{"delivery", Filter{From: day.From, Deliveries: []string{DeliveryNotifierOff, DeliveryNoChannels}}, []string{"MYSQL/CONN_LIMIT", "MODSEC/403"}},
		{"vhost from waf sample", Filter{From: day.From, Vhost: "shop.example.gr"}, []string{"WAF/SQLI"}},
		{"vhost from modsec sample", Filter{From: day.From, Vhost: "AR.mindwiseapps.com"}, []string{"MODSEC/403"}},
		{"free text in samples", Filter{From: day.From, Query: "license.txt"}, []string{"MODSEC/403"}},
		{"free text wildcard is literal", Filter{From: day.From, Query: "%"}, nil},
		{"mode", Filter{From: day.From, Mode: "ttl"}, []string{"WAF/SQLI"}},
		{"older rows", Filter{}, []string{"MYSQL/CONN_LIMIT", "MODSEC/403", "WAF/SQLI", "WAF/SQLI", "outbound_abuse"}},
		{"cursor", Filter{Before: &Cursor{TsUnix: now.Add(-2 * time.Hour).Unix(), ID: 99}}, []string{"WAF/SQLI", "WAF/SQLI", "outbound_abuse"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, err := s.List(tc.f, 50)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, r := range page.Rows {
				got = append(got, r.Kind)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestListRowFieldsAndPaging(t *testing.T) {
	s := openTestStore(t, 0, 0)
	now := time.Now()
	seed(t, s, now)

	page, err := s.List(Filter{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !page.HasMore || page.NextCursor == "" || len(page.Rows) != 2 {
		t.Fatalf("first page: %+v", page)
	}
	var seen []string
	for _, r := range page.Rows {
		seen = append(seen, r.Kind)
	}
	cursor, err := ParseCursor(page.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	page, err = s.List(Filter{Before: &cursor}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if page.HasMore || len(page.Rows) != 3 {
		t.Fatalf("second page: %+v", page)
	}
	for _, r := range page.Rows {
		seen = append(seen, r.Kind)
	}
	if len(seen) != 5 {
		t.Fatalf("paging lost rows: %v", seen)
	}

	waf, err := s.List(Filter{IP: "31.217.169.106"}, 1)
	if err != nil || len(waf.Rows) != 1 {
		t.Fatalf("by ip: %v %+v", err, waf)
	}
	r := waf.Rows[0]
	if r.Category != "WAF" || r.Severity != "warning" || r.ASNNum != 6799 || r.Vhost != "shop.example.gr" ||
		r.Mode != "ttl" || len(r.Samples) != 1 || r.Extra["mode"] != "ttl" || r.Time == "" || r.Host == "" {
		t.Fatalf("row fields: %+v", r)
	}

	mysql, _ := s.List(Filter{Categories: []string{"MYSQL"}}, 1)
	if got := mysql.Rows[0].Vhost; got != "" {
		t.Fatalf("a MySQL client host is not a vhost, got %q", got)
	}
}

func TestSummarize(t *testing.T) {
	s := openTestStore(t, 0, 0)
	now := time.Now()
	seed(t, s, now)
	day := Filter{From: now.Add(-24 * time.Hour)}

	sum, err := s.Summarize(day, []string{"country", "kind"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 4 || sum.DistinctIPs != 3 {
		t.Fatalf("totals: %+v", sum)
	}
	top := sum.Groups[0]
	if top.Key["country"] != "GR" || top.Key["kind"] != "WAF/SQLI" || top.Count != 2 || top.DistinctIPs != 2 || top.Label != "Athens, Greece" {
		t.Fatalf("top group: %+v", top)
	}

	asn, err := s.Summarize(Filter{From: day.From, Country: "GR"}, []string{"asn"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(asn.Groups) != 2 || asn.Groups[0].Label == "" {
		t.Fatalf("asn groups: %+v", asn.Groups)
	}

	byHour, err := s.Summarize(day, []string{"hour"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !byHour.Truncated || len(byHour.Groups) != 1 || !strings.HasSuffix(byHour.Groups[0].Key["hour"], ":00:00Z") {
		t.Fatalf("hour buckets: %+v", byHour)
	}

	if _, err := s.Summarize(day, []string{"password"}, 10); !errors.Is(err, ErrBadGroupBy) {
		t.Fatalf("unknown group_by: %v", err)
	}
	if _, err := s.Summarize(day, []string{"kind", "ip", "asn", "vhost"}, 10); !errors.Is(err, ErrBadGroupBy) {
		t.Fatalf("four dimensions: %v", err)
	}
	dims := []string{" KIND "}
	if _, err := s.Summarize(day, dims, 10); err != nil || dims[0] != " KIND " {
		t.Fatalf("Summarize changed the caller's group_by: %q %v", dims[0], err)
	}
}

func TestPrune(t *testing.T) {
	s := openTestStore(t, 24*time.Hour, 3)
	now := time.Now()
	seed(t, s, now)
	n, err := s.Prune(now)
	if err != nil {
		t.Fatal(err)
	}
	// the 48h-old row goes by age, then one more by the 3-row cap
	if n != 2 {
		t.Fatalf("pruned %d, want 2", n)
	}
	page, _ := s.List(Filter{}, 10)
	if len(page.Rows) != 3 || page.Rows[2].Kind != "WAF/SQLI" || page.Rows[2].IP != "79.103.201.90" {
		t.Fatalf("kept the wrong rows: %+v", page.Rows)
	}
	st, err := s.Stats()
	if err != nil || st.Rows != 3 || st.Written != 5 {
		t.Fatalf("stats: %v %+v", err, st)
	}
}

func TestDefaultStoreIsOptional(t *testing.T) {
	prev := SetDefault(nil)
	defer SetDefault(prev)
	Add(Record{Kind: "WAF/SQLI"}) // must not panic with no store
	s := openTestStore(t, 0, 0)
	SetDefault(s)
	Add(Record{Kind: "SSH/AUTHFAIL", IP: "198.51.100.7"})
	s.Flush()
	page, _ := s.List(Filter{}, 10)
	if len(page.Rows) != 1 || page.Rows[0].Category != "SSH" {
		t.Fatalf("rows: %+v", page.Rows)
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"WAF/AUTH_BURST": "WAF", "WEB/403WAF": "WEB", "outbound_abuse": "OUTBOUND", "lsm_detect_summary": "LSM",
		"autoblock": "AUTOBLOCK", "": "OTHER", "PORTSCAN": "PORTSCAN",
	}
	for kind, want := range cases {
		if got := CategoryOf(kind); got != want {
			t.Errorf("CategoryOf(%q) = %q, want %q", kind, got, want)
		}
	}
	for in, want := range map[string]int64{"AS14061 DigitalOcean, LLC": 14061, "as6799": 6799, "6799": 6799, "Unmanaged Ltd": 0, "": 0} {
		if got := ParseASN(in); got != want {
			t.Errorf("ParseASN(%q) = %d, want %d", in, got, want)
		}
	}
	long := strings.Repeat("α", 3000) // 2 bytes each
	r := normalize(Record{Kind: "WAF/SQLI", Samples: []string{long, "b", "c", "d", "e", "f", "g"}, Reason: long})
	if len(r.Samples) != maxSamples || len(r.Samples[0]) > maxSampleBytes || len(r.Reason) > maxFieldBytes {
		t.Fatalf("not bounded: %d samples, %d sample bytes, %d reason bytes", len(r.Samples), len(r.Samples[0]), len(r.Reason))
	}
	if !strings.HasSuffix(r.Reason, "α") {
		t.Fatal("clip split a UTF-8 sequence")
	}
}

func TestOverview(t *testing.T) {
	s := openTestStore(t, 0, 0)
	now := time.Now()
	seed(t, s, now)
	ov, err := s.Overview(Filter{From: now.Add(-24 * time.Hour), Categories: []string{"WAF"}})
	if err != nil {
		t.Fatal(err)
	}
	// tallies follow the category filter; the chip counts ignore it
	if ov.Total != 2 || ov.DistinctIPs != 2 || ov.NotNotified != 1 {
		t.Fatalf("tallies: %+v", ov)
	}
	if ov.TopKind == nil || ov.TopKind.Key["kind"] != "WAF/SQLI" || ov.TopCountry == nil || ov.TopCountry.Key["country"] != "GR" {
		t.Fatalf("tops: %+v %+v", ov.TopKind, ov.TopCountry)
	}
	cats := map[string]int64{}
	for _, g := range ov.Categories {
		cats[g.Key["category"]] = g.Count
	}
	if cats["WAF"] != 2 || cats["MODSEC"] != 1 || cats["MYSQL"] != 1 {
		t.Fatalf("categories: %v", cats)
	}
}

// The store holds every tenant's events: none of its files may be readable by
// other local users, whatever the process umask.
func TestFilesArePrivate(t *testing.T) {
	old := setUmask(0o022)
	defer setUmask(old)
	path := filepath.Join(t.TempDir(), "alerts.db")
	s, err := Open(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.Add(Record{Kind: "WAF/SQLI", IP: "198.51.100.1"})
	s.Flush()
	defer s.Close()
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s is %o, want no group/other access", filepath.Base(p), perm)
		}
	}
}

func TestShutdownFlushesQueuedRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.db")
	s, err := Open(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	prev := SetDefault(s)
	defer SetDefault(prev)
	for i := 0; i < 50; i++ {
		Add(Record{Kind: "PORTSCAN", IP: "203.0.113.9"})
	}
	Shutdown()
	if Default() != nil {
		t.Fatal("Shutdown left the store installed")
	}
	again, err := Open(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	st, err := again.Stats()
	if err != nil || st.Rows != 50 {
		t.Fatalf("rows after shutdown: %v %+v", err, st)
	}
}

func TestPruneInChunks(t *testing.T) {
	prev := pruneChunk
	pruneChunk = 2
	defer func() { pruneChunk = prev }()
	s := openTestStore(t, time.Hour, 3)
	now := time.Now()
	for i := 0; i < 7; i++ { // 7 expired rows: chunks of 2, 2, 2, 1
		s.Add(Record{TsUnix: now.Add(-2 * time.Hour).Unix(), Kind: "PORTSCAN"})
	}
	for i := 0; i < 8; i++ { // 8 fresh rows, cap 3: 5 more go
		s.Add(Record{TsUnix: now.Add(-time.Minute).Unix(), Kind: "WAF/SQLI", IP: fmt.Sprintf("198.51.100.%d", i)})
	}
	s.Flush()
	n, err := s.Prune(now)
	if err != nil || n != 12 {
		t.Fatalf("pruned %d (%v), want 12", n, err)
	}
	page, _ := s.List(Filter{}, 10)
	if len(page.Rows) != 3 || page.Rows[0].IP != "198.51.100.7" {
		t.Fatalf("kept: %+v", page.Rows)
	}
}

// "-" selects the rows with no value: the group a Summarize returns with an
// empty key, so drilling into it narrows to exactly that group.
func TestNoneFilters(t *testing.T) {
	s := openTestStore(t, 0, 0)
	now := time.Now()
	seed(t, s, now)
	day := now.Add(-24 * time.Hour)
	for name, f := range map[string]Filter{
		"ip":      {From: day, IP: None},
		"country": {From: day, Country: None},
		"asn":     {From: day, ASN: None},
	} {
		page, err := s.List(f, 10)
		if err != nil || len(page.Rows) != 1 || page.Rows[0].Kind != "MYSQL/CONN_LIMIT" {
			t.Errorf("%s=-: %v %+v", name, err, page.Rows)
		}
	}
	page, _ := s.List(Filter{From: day, Vhost: None}, 10)
	if len(page.Rows) != 2 {
		t.Errorf("vhost=-: %d rows, want 2", len(page.Rows))
	}
}
