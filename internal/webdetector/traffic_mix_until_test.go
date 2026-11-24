package webdetector

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

// A window ending at `until` counts exactly the buckets and minutes before it:
// the hour 09:00-10:00 holds what was logged from 09:00:00 to 09:59:59, and
// reads the same however many times (and whenever) it is asked.
func TestTrafficMix_SnapshotUntilIsExact(t *testing.T) {
	s := newTrafficMixStore()
	end := time.Now().Add(-3 * time.Hour).Truncate(time.Hour) // a finished hour's end
	start := end.Add(-time.Hour)
	feed := func(at time.Time, n int) {
		for i := 0; i < n; i++ {
			tmFeed(s, tmOrigin("198.51.100.1", "a.gr", "GET", "/", "somebot/1", 200, 0.5), at)
		}
	}
	feed(start.Add(-time.Second), 7)   // 08:59:59: the hour before
	feed(start, 2)                     // 09:00:00: inside
	feed(start.Add(30*time.Minute), 3) // inside
	feed(end.Add(-time.Second), 5)     // 09:59:59: inside (the last minute)
	feed(end, 11)                      // 10:00:00: the next hour
	feed(end.Add(4*time.Minute), 13)   // the next hour

	m := s.SnapshotUntil(end, time.Hour, "", false, 10, 10, TrafficMixSortOrigin)
	if m.Since != start.Unix() || m.Until != end.Unix() || m.WindowSec != 3600 {
		t.Fatalf("span = %d..%d (%d s), want %d..%d (3600 s)", m.Since, m.Until, m.WindowSec, start.Unix(), end.Unix())
	}
	if m.Total.Requests != 10 {
		t.Fatalf("requests in the hour = %d, want 10 (2+3+5; not the 7 before, not the 24 after)", m.Total.Requests)
	}
	if len(m.Series) != 12 || m.Series[0].T != start.Unix() || m.Series[11].T != end.Unix()-300 {
		t.Fatalf("series = %d points %d..%d, want the 12 buckets of the hour", len(m.Series), m.Series[0].T, m.Series[len(m.Series)-1].T)
	}
	bot := tmClassOf(m, "bot")
	if bot.RPSPeak != 5.0/60 || bot.PeakAt != end.Unix()-60 {
		t.Fatalf("peak = %v at %d, want 5/60 at the hour's last minute %d (the next hour's 11 must not count)", bot.RPSPeak, bot.PeakAt, end.Unix()-60)
	}
	again := s.SnapshotUntil(end, time.Hour, "", false, 10, 10, TrafficMixSortOrigin)
	if again.Total.Requests != m.Total.Requests {
		t.Fatal("the same hour read twice differs")
	}
	// The open-ended view still ends inside its last bucket.
	if open := s.SnapshotSorted(end.Add(5*time.Minute), time.Hour, "", false, 10, 10, ""); open.Total.Requests != 3+5+11+13 {
		t.Fatalf("open window = %d", open.Total.Requests)
	}
}

func TestTrafficMix_UntilParam(t *testing.T) {
	e := &Engine{}
	now := time.Now().Unix()
	aligned := now - now%300 - 600
	for q, want := range map[string]int{
		fmt.Sprint(aligned):           200,
		fmt.Sprint(aligned + 7):       400, // not a boundary
		fmt.Sprint(aligned + 3600):    400, // the future
		fmt.Sprint(aligned - 25*3600): 400, // past the ring
		"yesterday":                   400,
	} {
		rr := httptest.NewRecorder()
		e.handleTrafficMix(rr, manualIPReq(CtxRoleAdmin, "/api/v1/webdet/traffic-mix?window=1h&until="+q, ""))
		if rr.Code != want {
			t.Errorf("until=%s: %d, want %d (%s)", q, rr.Code, want, rr.Body.String())
		}
	}
}
