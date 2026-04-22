package webdetector

import (
	"strings"
	"testing"
	"time"
)

func TestIP404Flood_StaticAsset404Ignored(t *testing.T) {
	e := NewEngine(Config{
		Every:      1 * time.Second,
		Window:     2 * time.Minute,
		IP404Count: 3,
	})

	now := float64(time.Now().Unix())
	for i := 0; i < 5; i++ {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "1.2.3.4",
			Host:   "example.com",
			Method: "get",
			URI:    "/missing.css?x=1",
			Status: 404,
			UA:     "ua",
		}, "raw")
	}

	rows := e.IPShort(0)
	if len(rows) == 0 {
		t.Fatalf("expected at least one IP row")
	}
	for _, r := range rows {
		if r.IP != "1.2.3.4" {
			continue
		}
		for _, reason := range r.Reasons {
			if strings.HasPrefix(reason, "404_flood") {
				t.Fatalf("did not expect 404_flood for static asset misses, got reasons=%v", r.Reasons)
			}
		}
	}
}

func TestIP404Flood_NonStatic404StillCounts(t *testing.T) {
	e := NewEngine(Config{
		Every:      1 * time.Second,
		Window:     2 * time.Minute,
		IP404Count: 3,
	})

	now := float64(time.Now().Unix())
	for i := 0; i < 3; i++ {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "5.6.7.8",
			Host:   "example.com",
			Method: "get",
			URI:    "/missing-admin-endpoint",
			Status: 404,
			UA:     "ua",
		}, "raw")
	}

	rows := e.IPShort(0)
	found := false
	for _, r := range rows {
		if r.IP != "5.6.7.8" {
			continue
		}
		for _, reason := range r.Reasons {
			if strings.HasPrefix(reason, "404_flood") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("expected 404_flood for non-static missing endpoint")
	}
}

