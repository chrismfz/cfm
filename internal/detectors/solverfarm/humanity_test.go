package solverfarm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	core "cfm/internal/detectors/core"
)

func (h *harness) solveHS(host, ip, fp, cc string, hs *core.Humanity) {
	h.d.Enqueue(core.InputEvent{When: h.clock, Scope: host, SrcIP: ip, UserAgent: chromeUA,
		Fingerprint: fp, CountryISO: cc, Humanity: hs, Source: "challenge"})
}

func scored(score int, tells string) *core.Humanity {
	return &core.Humanity{Scored: true, Score: score, Tells: tells}
}

func captureFindings(t *testing.T) *[]Finding {
	t.Helper()
	var got []Finding
	SetFindingSink(func(f Finding) { got = append(got, f) })
	t.Cleanup(func() { SetFindingSink(nil) })
	return &got
}

// The buckets: a missing reading is unscored, NEVER 0 (hs 0 is a real score,
// "scored clean"); a no-payload verify is none (the solve line's hs=-) unless
// a UA-borne opener scored it, which the line then shows as a number.
func TestHumanityBucketOf(t *testing.T) {
	cases := []struct {
		name string
		in   *core.Humanity
		want string
	}{
		{"nil reading is unscored, not 0", nil, "unscored"},
		{"not scored is unscored even with a zero score", &core.Humanity{Scored: false}, "unscored"},
		{"not scored ignores a stray score", &core.Humanity{Scored: false, Score: 140}, "unscored"},
		{"no payload is none", &core.Humanity{Scored: true, NoPayload: true}, "none"},
		{"no payload but a UA opener scored it", &core.Humanity{Scored: true, NoPayload: true, Score: 80}, "60-99"},
		{"scored clean", scored(0, ""), "0"},
		{"1", scored(1, "x"), "1-59"},
		{"59", scored(59, "x"), "1-59"},
		{"60", scored(60, "x"), "60-99"},
		{"99", scored(99, "x"), "60-99"},
		{"100", scored(100, "x"), "100+"},
		{"140", scored(140, "x"), "100+"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hsBucketNames[bucketOf(c.in)]; got != c.want {
				t.Errorf("bucket = %q, want %q", got, c.want)
			}
		})
	}
	if tellsOf(&core.Humanity{Scored: false, Tells: "webdriver"}) != "" {
		t.Error("an unscored reading must carry no tells")
	}
}

// topKeys: count descending, ties broken by key, capped at n — so a summary
// reads the same on every pass despite random map order.
func TestHumanityTopKeysDeterministic(t *testing.T) {
	m := map[string]int{"US": 3, "GR": 9, "DE": 3, "BR": 3, "AR": 1, "FR": 3, "NL": 2}
	want := []KeyCount{{"GR", 9}, {"BR", 3}, {"DE", 3}, {"FR", 3}, {"US", 3}}
	for i := 0; i < 50; i++ {
		if got := topKeys(m, 5); !reflect.DeepEqual(got, want) {
			t.Fatalf("topKeys = %v, want %v", got, want)
		}
	}
	if topKeys(nil, 5) != nil {
		t.Error("empty map must give nil")
	}
}

// Each track summarises the cluster it is ABOUT: the fp tracks only the
// flagged fingerprint's solves on the vhost, subnet_spread the whole vhost.
func TestHumanitySummaryClusterSelection(t *testing.T) {
	t.Run("fp_concentration: only the flagged fingerprint", func(t *testing.T) {
		got := captureFindings(t)
		h := newHarness(t, Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6})
		h.d.countryFn = ipCountry
		for i := 0; i < 10; i++ {
			// Half carry their own country (preferred), half fall back to countryFn.
			cc := ""
			if i%2 == 0 {
				cc = "gr"
			}
			hs := scored(0, "")
			if i >= 7 {
				hs = scored(120, "sw_renderer,no_input")
			}
			h.solveHS("techking.example", fmt.Sprintf("203.0.%d.1", i), "c28caa00", cc, hs)
		}
		// A different, benign fingerprint on the same vhost: must not be counted.
		for i := 0; i < 4; i++ {
			h.solveHS("techking.example", fmt.Sprintf("198.51.%d.9", i), "77a50fbb", "US", scored(70, "mac_hw_lie"))
		}
		if a := h.run(t); len(a) != 1 {
			t.Fatalf("alerts=%d, want 1", len(a))
		}
		hum := (*got)[0].Humanity
		if hum == nil {
			t.Fatal("finding carries no humanity summary")
		}
		if hum.Cluster != "fp_concentration" || hum.Fingerprint != "c28caa00" || hum.N != 10 || hum.Truncated {
			t.Fatalf("summary = %+v, want fp_concentration / c28caa00 / n=10 / not truncated", hum)
		}
		wantB := map[string]int{"none": 0, "unscored": 0, "0": 7, "1-59": 0, "60-99": 0, "100+": 3}
		if !reflect.DeepEqual(hum.Buckets, wantB) {
			t.Errorf("buckets = %v, want %v (the benign fp's 60-99 must not leak in)", hum.Buckets, wantB)
		}
		if !reflect.DeepEqual(hum.Tells, []KeyCount{{"sw_renderer,no_input", 3}}) {
			t.Errorf("tells = %v", hum.Tells)
		}
		if len(hum.Countries) == 0 || hum.Countries[0] != (KeyCount{"GR", 5}) {
			t.Errorf("countries = %v, want GR ×5 first (the event's own country, upper-cased)", hum.Countries)
		}
		for _, c := range hum.Countries {
			if c.Key == "US" {
				t.Errorf("the benign fp's country leaked into the summary: %v", hum.Countries)
			}
		}
	})

	t.Run("subnet_spread: every solve on the vhost", func(t *testing.T) {
		got := captureFindings(t)
		h := newHarness(t, Config{})
		for i := 0; i < 40; i++ {
			var hs *core.Humanity // unscored: the rung was off
			if i < 10 {
				hs = &core.Humanity{Scored: true, NoPayload: true}
			}
			h.solveHS("shop.example.com", fmt.Sprintf("203.0.%d.1", i), "", "BR", hs)
		}
		if a := h.run(t); len(a) != 1 {
			t.Fatalf("alerts=%d, want 1", len(a))
		}
		hum := (*got)[0].Humanity
		if hum == nil || hum.Cluster != "subnet_spread" || hum.Fingerprint != "" || hum.N != 40 {
			t.Fatalf("summary = %+v, want subnet_spread / no fp / n=40", hum)
		}
		if hum.Buckets["none"] != 10 || hum.Buckets["unscored"] != 30 || hum.Buckets["0"] != 0 {
			t.Errorf("buckets = %v, want none 10 / unscored 30 / 0 zero", hum.Buckets)
		}
	})

	t.Run("cross_host: the fp's solves on THIS vhost only", func(t *testing.T) {
		got := captureFindings(t)
		h := newHarness(t, xhCfg())
		h.d.countryFn = xhCountry
		hosts := []string{"a.shop", "b.shop", "c.shop", "d.shop", "e.shop", "f.shop"}
		for hi, host := range hosts {
			for s := 0; s < 6; s++ {
				hs := scored(0, "")
				if host == "a.shop" {
					hs = scored(140, "webdriver")
				}
				h.solveHS(host, fmt.Sprintf("10.%d.%d.1", hi+1, s), "95070673", "", hs)
			}
		}
		// A minority fingerprint on a.shop (2 of 8 solves, share 25%): not the
		// convicted cluster.
		h.solveHS("a.shop", "192.0.2.1", "deadbeef", "GR", scored(0, ""))
		h.solveHS("a.shop", "192.0.2.2", "deadbeef", "GR", scored(0, ""))
		if a := h.run(t); len(a) != len(hosts) {
			t.Fatalf("alerts=%d, want %d", len(a), len(hosts))
		}
		var fa *Finding
		for i := range *got {
			if (*got)[i].Host == "a.shop" {
				fa = &(*got)[i]
			}
		}
		if fa == nil || fa.Humanity == nil {
			t.Fatal("no a.shop finding / humanity")
		}
		hum := fa.Humanity
		if hum.Cluster != "cross_host" || hum.Fingerprint != "95070673" || hum.N != 6 || hum.Window != h.d.cfg.XHWindow {
			t.Fatalf("summary = %+v, want cross_host / 95070673 / n=6 (this vhost only) / XHWindow", hum)
		}
		if hum.Buckets["100+"] != 6 || hum.Buckets["0"] != 0 {
			t.Errorf("buckets = %v, want 100+ ×6 (other vhosts' and the minority fp's hs 0 excluded)", hum.Buckets)
		}
		for _, c := range hum.Countries {
			if c.Key == "GR" {
				t.Errorf("minority fp's country leaked: %v", hum.Countries)
			}
		}
	})
}

// The evidence cap marks a summary truncated: its counts are of a sample.
func TestHumanitySummaryTruncation(t *testing.T) {
	got := captureFindings(t)
	h := newHarness(t, Config{MaxTrackedPerHost: 50})
	h.farmBurst("shop.example.com", 200, func(int) string { return chromeUA })
	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("alerts=%d, want 1", len(alerts))
	}
	hum := (*got)[0].Humanity
	if hum == nil || !hum.Truncated || hum.N != 50 {
		t.Fatalf("summary = %+v, want truncated with n=50 (the sampled records)", hum)
	}
	line := ""
	for _, s := range alerts[0].Samples {
		if strings.HasPrefix(s, "[challenge] humanity of") {
			line = s
		}
	}
	if !strings.Contains(line, "evidence cap hit") {
		t.Errorf("alert text does not say the summary is a sample: %q", line)
	}

	// Below the cap: not truncated.
	got2 := captureFindings(t)
	h2 := newHarness(t, Config{})
	h2.farmBurst("shop.example.com", 40, func(int) string { return chromeUA })
	h2.run(t)
	if hum := (*got2)[0].Humanity; hum == nil || hum.Truncated {
		t.Errorf("summary = %+v, want not truncated", hum)
	}
}

// The summary rides the alert text, the Finding and (webdetector) the history
// row; the text names the cluster, buckets, tells and country shares.
func TestHumanityLineInAlert(t *testing.T) {
	h := newHarness(t, Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6})
	h.d.countryFn = ipCountry
	for i := 0; i < 10; i++ {
		hs := scored(0, "")
		if i < 2 {
			hs = scored(80, "mobile_hw_lie")
		}
		h.solveHS("x.example", fmt.Sprintf("203.0.%d.1", i), "c28caa00", "GR", hs)
	}
	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("alerts=%d", len(alerts))
	}
	want := `[challenge] humanity of fp c28caa00 on this vhost (fp_concentration, 3m0s, n=10): hs 0 ×8, 60-99 ×2; tells: "mobile_hw_lie" ×2; countries: GR 100%`
	for _, s := range alerts[0].Samples {
		if s == want {
			return
		}
	}
	t.Errorf("humanity line missing; want %q in %v", want, alerts[0].Samples)
}

// Evidence only: the same traffic with and without humanity readings yields
// the same alerts (every Extra key, the count, the tracks) and the same
// findings but for the Humanity field — on every track.
func TestHumanityChangesNoDecision(t *testing.T) {
	type scenario struct {
		name    string
		cfg     Config
		country func(string) string
		feed    func(h *harness, withHS bool)
	}
	hsFor := func(i int, with bool) *core.Humanity {
		if !with {
			return nil
		}
		return scored(i*17%150, "webdriver")
	}
	scenarios := []scenario{
		{"subnet_spread", Config{}, nil, func(h *harness, with bool) {
			for i := 0; i < 40; i++ {
				h.solveHS("s.example", fmt.Sprintf("203.0.%d.1", i), "", "", hsFor(i, with))
			}
		}},
		{"fp_concentration", Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6}, ipCountry, func(h *harness, with bool) {
			for i := 0; i < 12; i++ {
				cc := ""
				if with {
					cc = "GR" // an event country must not move the fp track's country count
				}
				h.solveHS("f.example", fmt.Sprintf("203.0.%d.1", i), "c28caa00", cc, hsFor(i, with))
			}
		}},
		{"below threshold stays silent", Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6}, ipCountry, func(h *harness, with bool) {
			for i := 0; i < 5; i++ {
				h.solveHS("q.example", fmt.Sprintf("203.0.%d.1", i), "c28caa00", "", hsFor(i, with))
			}
		}},
		{"cross_host", xhCfg(), xhCountry, func(h *harness, with bool) {
			for hi := 0; hi < 6; hi++ {
				for s := 0; s < 6; s++ {
					cc := ""
					if with {
						cc = "GR"
					}
					h.solveHS(fmt.Sprintf("h%d.shop", hi), fmt.Sprintf("10.%d.%d.1", hi+1, s), "95070673", cc, hsFor(s, with))
				}
			}
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			run := func(with bool) ([]core.Alert, []Finding) {
				got := captureFindings(t)
				h := newHarness(t, sc.cfg)
				h.d.countryFn = sc.country
				sc.feed(h, with)
				return h.run(t), *got
			}
			a0, f0 := run(false)
			a1, f1 := run(true)
			if len(a0) != len(a1) || len(f0) != len(f1) {
				t.Fatalf("alerts %d vs %d, findings %d vs %d", len(a0), len(a1), len(f0), len(f1))
			}
			byKey := func(as []core.Alert) map[string]core.Alert {
				m := map[string]core.Alert{}
				for _, a := range as {
					m[a.Key] = a
				}
				return m
			}
			m0, m1 := byKey(a0), byKey(a1)
			for k, x := range m0 {
				y := m1[k]
				if x.Count != y.Count || !reflect.DeepEqual(x.Extra, y.Extra) {
					t.Errorf("%s: alert differs:\n without %d %v\n with    %d %v", k, x.Count, x.Extra, y.Count, y.Extra)
				}
			}
			fByHost := func(fs []Finding) map[string]Finding {
				m := map[string]Finding{}
				for _, f := range fs {
					f.Humanity = nil
					f.IPs = nil // a random sample (map order); covered by DistinctIPs
					m[f.Host] = f
				}
				return m
			}
			if !reflect.DeepEqual(fByHost(f0), fByHost(f1)) {
				t.Errorf("findings differ beyond Humanity:\n without %+v\n with    %+v", f0, f1)
			}
		})
	}
}
