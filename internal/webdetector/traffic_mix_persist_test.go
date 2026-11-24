package webdetector

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// feedTitan puts a little of every class into s, now and 3 hours ago (an
// older bucket, compacted once a newer one starts).
func feedTitan(s *trafficMixStore, now time.Time) {
	for _, at := range []time.Time{now.Add(-3 * time.Hour), now} {
		tmFeed(s, tmOrigin("57.141.20.1", "shop.gr", "GET", "/p/1", tmMeta, 200, 0.4), at)
		tmFeed(s, tmOrigin("198.51.100.7", "shop.gr", "GET", "/x", "python-requests/2.31", 200, 0.2), at)
		tmFeed(s, tmOrigin("203.0.113.9", "blog.gr", "GET", "/", tmChrome152, 200, 0.1), at)
		for i := 0; i < tmAutomationDynPerMin+2; i++ {
			tmFeed(s, tmOrigin("203.0.113.66", "shop.gr", "GET", "/c?f="+string(rune('a'+i)), tmChrome152, 200, 1), at.Add(time.Duration(i)*time.Second))
		}
	}
}

// A saved and reloaded mix answers every question as the original did.
func TestTrafficMixPersist_RoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Minute).Add(-2 * time.Minute)
	src := newTrafficMixStore()
	feedTitan(src, now)
	path := filepath.Join(t.TempDir(), "traffic_mix.json.gz")
	if err := src.saveTo(path, now); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v %v, want 0600 (client IPs inside)", fi.Mode(), err)
	}

	dst := newTrafficMixStore()
	n, err := dst.loadFrom(path, now)
	if err != nil || n == 0 {
		t.Fatalf("load: n=%d err=%v", n, err)
	}
	for _, w := range []time.Duration{time.Hour, 24 * time.Hour} {
		want := src.Snapshot(now, w, "", false, 50, 50)
		got := dst.Snapshot(now, w, "", false, 50, 50)
		if !reflect.DeepEqual(want, got) {
			wj, _ := json.Marshal(want)
			gj, _ := json.Marshal(got)
			t.Fatalf("window %s differs after a reload:\nwant %s\n got %s", w, wj, gj)
		}
	}
	if tmClassOf(dst.Snapshot(now, time.Hour, "", false, 10, 10), "automation").Requests == 0 {
		t.Fatal("the automation reading did not survive")
	}
}

// After a restart the daemon counts the current bucket again from zero: the
// saved counts are ADDED to it (requests before and after the stop), never
// replaced or doubled.
func TestTrafficMixPersist_MergesIntoALiveBucket(t *testing.T) {
	now := time.Now().Truncate(time.Minute).Add(-2 * time.Minute)
	before := newTrafficMixStore()
	tmFeed(before, tmOrigin("57.141.20.1", "shop.gr", "GET", "/a", tmMeta, 200, 0.5), now)
	tmFeed(before, tmOrigin("57.141.20.2", "shop.gr", "GET", "/b", tmMeta, 200, 0.5), now)
	path := filepath.Join(t.TempDir(), "m.json.gz")
	if err := before.saveTo(path, now); err != nil {
		t.Fatal(err)
	}

	after := newTrafficMixStore() // the restarted daemon...
	tmFeed(after, tmOrigin("57.141.20.3", "shop.gr", "GET", "/c", tmMeta, 200, 0.5), now.Add(5*time.Second))
	if _, err := after.loadFrom(path, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	c := tmClassOf(after.Snapshot(now.Add(6*time.Second), time.Hour, "", false, 10, 10), "crawler")
	if c.Requests != 3 || c.OriginSec != 1.5 {
		t.Fatalf("crawler after the merge = %d req / %.1f s, want 3 / 1.5", c.Requests, c.OriginSec)
	}
}

func TestTrafficMixPersist_DropsWhatIsTooOldAndRefusesForeignFiles(t *testing.T) {
	now := time.Now().Truncate(time.Minute).Add(-2 * time.Minute)
	src := newTrafficMixStore()
	feedTitan(src, now)
	dir := t.TempDir()
	path := filepath.Join(dir, "m.json.gz")
	if err := src.saveTo(path, now); err != nil {
		t.Fatal(err)
	}
	// Loaded 23 h later: only the buckets still inside the ring come back
	// (the 3-hours-before-now ones are 26 h old then).
	later := now.Add(23 * time.Hour)
	dst := newTrafficMixStore()
	if _, err := dst.loadFrom(path, later); err != nil {
		t.Fatal(err)
	}
	m := dst.Snapshot(later, 24*time.Hour, "", false, 10, 10)
	if tmClassOf(src.Snapshot(now, time.Hour, "", false, 10, 10), "automation").Requests == 0 {
		t.Fatal("fixture: no automation in the source")
	}
	if m.Total.Requests != int64(3+tmAutomationDynPerMin+2) {
		t.Fatalf("requests 23 h later = %d, want only the newer copy's %d", m.Total.Requests, 3+tmAutomationDynPerMin+2)
	}

	if n, err := newTrafficMixStore().loadFrom(filepath.Join(dir, "absent.json.gz"), now); err != nil || n != 0 {
		t.Fatalf("a missing file is a first start, not an error: n=%d err=%v", n, err)
	}
	bad := filepath.Join(dir, "bad.json.gz")
	if err := os.WriteFile(bad, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newTrafficMixStore().loadFrom(bad, now); err == nil {
		t.Fatal("a corrupt file loaded")
	}
	other := filepath.Join(dir, "v2.json.gz")
	fh, _ := os.Create(other)
	zw := gzip.NewWriter(fh)
	_ = json.NewEncoder(zw).Encode(tmFile{Version: tmFileVersion + 1})
	zw.Close()
	fh.Close()
	if _, err := newTrafficMixStore().loadFrom(other, now); err == nil {
		t.Fatal("a file of another version loaded")
	}
}

// The daemon's default path is never written by the suite: the tests above use
// their own temp paths, and this one only checks the default stays the live
// state dir (a moved default would land the file outside the package's dir).
func TestTrafficMixPersist_DefaultPath(t *testing.T) {
	if TrafficMixPath != "/var/lib/cfm/traffic_mix.json.gz" {
		t.Fatalf("TrafficMixPath = %q", TrafficMixPath)
	}
}
