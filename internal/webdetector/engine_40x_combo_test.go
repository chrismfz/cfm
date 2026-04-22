package webdetector

import (
	"strings"
	"testing"
	"time"
)

func has40xComboReason(reasons []string) bool {
	for _, reason := range reasons {
		if strings.HasPrefix(reason, "40x_combo") {
			return true
		}
	}
	return false
}

func ipHas40xComboReason(rows []IPSignals, ip string) bool {
	for _, r := range rows {
		if r.IP == ip {
			return has40xComboReason(r.Reasons)
		}
	}
	return false
}

func TestIP40xCombo_Static404403Ignored(t *testing.T) {
	e := NewEngine(Config{
		Every:                 1 * time.Second,
		Window:                2 * time.Minute,
		IP40xComboCount:       4,
		IP40xComboUniquePaths: 1,
	})

	now := float64(time.Now().Unix())
	for i := 0; i < 3; i++ {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "10.0.0.1",
			Host:   "example.com",
			Method: "get",
			URI:    "/assets/missing.css?ver=1",
			Status: 404,
			UA:     "ua",
		}, "raw")
	}
	for i := 0; i < 3; i++ {
		e.ingest(LogRec{
			TS:     now + float64(10+i),
			IP:     "10.0.0.1",
			Host:   "example.com",
			Method: "get",
			URI:    "/assets/forbidden.js",
			Status: 403,
			UA:     "ua",
		}, "raw")
	}

	rows := e.IPShort(0)
	if ipHas40xComboReason(rows, "10.0.0.1") {
		t.Fatalf("did not expect 40x_combo for repeated static assets; rows=%+v", rows)
	}
}

func TestIP40xCombo_NonStatic403404Counts(t *testing.T) {
	e := NewEngine(Config{
		Every:                 1 * time.Second,
		Window:                2 * time.Minute,
		IP40xComboCount:       4,
		IP40xComboUniquePaths: 2,
	})

	now := float64(time.Now().Unix())
	uris := []struct {
		uri    string
		status int
	}{
		{"/admin", 403},
		{"/private", 403},
		{"/missing-a", 404},
		{"/missing-b", 404},
	}
	for i, u := range uris {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "10.0.0.2",
			Host:   "example.com",
			Method: "get",
			URI:    u.uri,
			Status: u.status,
			UA:     "ua",
		}, "raw")
	}

	rows := e.IPShort(0)
	if !ipHas40xComboReason(rows, "10.0.0.2") {
		t.Fatalf("expected 40x_combo for non-static 403/404 mix; rows=%+v", rows)
	}
}

func TestIP40xCombo_IgnorePrefixesStillApplied(t *testing.T) {
	e := NewEngine(Config{
		Every:                 1 * time.Second,
		Window:                2 * time.Minute,
		IP40xComboCount:       4,
		IP40xComboUniquePaths: 1,
		Ignore40xPrefixes:     []string{"/ignored"},
	})

	now := float64(time.Now().Unix())
	for i := 0; i < 5; i++ {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "10.0.0.3",
			Host:   "example.com",
			Method: "get",
			URI:    "/ignored/secret",
			Status: 404,
			UA:     "ua",
		}, "raw")
	}

	rows := e.IPShort(0)
	if ipHas40xComboReason(rows, "10.0.0.3") {
		t.Fatalf("did not expect 40x_combo for ignored prefix paths; rows=%+v", rows)
	}
}
