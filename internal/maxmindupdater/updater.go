package maxmindupdater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Enabled         bool
	AccountID       string
	LicenseKey      string
	Editions        []string
	Dir             string
	CheckEvery      time.Duration
	MinAgeBetweenDL time.Duration
	HTTPTimeout     time.Duration
	Permalinks      map[string]string
	IPLocateURLs    map[string]string
	SourceMode      string // optional: "auto" (default), "maxmind", "iplocate"
}

// persisted state to avoid needless downloads
type state struct {
	LastChecked    time.Time            `json:"last_checked"`
	LastDownloaded map[string]time.Time `json:"last_downloaded"`
	LastRemoteDate map[string]time.Time `json:"last_remote_date"`
	ETags          map[string]string    `json:"etags,omitempty"`
}

var (
	dispDate = regexp.MustCompile(`_(\d{8})\.`) // e.g., GeoLite2-City_20250925.tar.gz
)

type Updater struct {
	cfg   Config
	httpc *http.Client
	mu    sync.Mutex
}

func New(cfg Config) *Updater {
	if cfg.Dir == "" {
		cfg.Dir = "/var/lib/cfm/maxmind"
	}
	if cfg.CheckEvery == 0 {
		cfg.CheckEvery = 24 * time.Hour
	}
	if cfg.MinAgeBetweenDL == 0 {
		cfg.MinAgeBetweenDL = 72 * time.Hour
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}

	if cfg.Permalinks == nil {
		cfg.Permalinks = map[string]string{
			"GeoLite2-ASN":  "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz",
			"GeoLite2-City": "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
		}
	}
	if cfg.IPLocateURLs == nil {
		cfg.IPLocateURLs = map[string]string{
			"GeoLite2-ASN":     "https://github.com/iplocate/ip-address-databases/raw/refs/heads/main/ip-to-asn/ip-to-asn.mmdb",
			"GeoLite2-City":    "https://github.com/iplocate/ip-address-databases/raw/refs/heads/main/ip-to-country/ip-to-country.mmdb",
			"GeoLite2-Country": "https://github.com/iplocate/ip-address-databases/raw/refs/heads/main/ip-to-country/ip-to-country.mmdb",
		}
	}

	return &Updater{
		cfg: cfg,
		httpc: &http.Client{
			Timeout: cfg.HTTPTimeout,
			// Default CheckRedirect follows up to 10 redirects – good for R2
		},
	}
}

func (u *Updater) useMaxMindSource() bool {
	switch strings.ToLower(strings.TrimSpace(u.cfg.SourceMode)) {
	case "maxmind":
		return true
	case "iplocate":
		return false
	default:
		return u.cfg.AccountID != "" && u.cfg.LicenseKey != ""
	}
}

func (u *Updater) sourceURL(edition string) string {
	if u.useMaxMindSource() {
		return u.cfg.Permalinks[edition]
	}
	return u.cfg.IPLocateURLs[edition]
}

func (u *Updater) Run(ctx context.Context, logf func(string, ...any)) error {
	if !u.cfg.Enabled {
		return nil
	}
	if err := os.MkdirAll(u.cfg.Dir, 0o755); err != nil {
		return err
	}

	ticker := time.NewTicker(u.cfg.CheckEvery)
	defer ticker.Stop()

	// run once at start
	u.checkOnce(ctx, logf)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			u.checkOnce(ctx, logf)
		}
	}
}

func (u *Updater) checkOnce(ctx context.Context, logf func(string, ...any)) {
	u.mu.Lock()
	defer u.mu.Unlock()

	st, _ := u.loadState()
	if st == nil {
		st = &state{
			LastDownloaded: map[string]time.Time{},
			LastRemoteDate: map[string]time.Time{},
			ETags:          map[string]string{},
		}
	}

	for _, ed := range u.cfg.Editions {
		url := u.sourceURL(ed)
		if url == "" {
			logf("[maxmind] no source URL for edition %s; skipping", ed)
			continue
		}

		remoteDate, etag, err := u.head(ctx, url)
		if err != nil {
			logf("[maxmind] HEAD %s failed for %s: %v", url, ed, err)
			continue
		}

		st.LastChecked = time.Now()
		if !remoteDate.IsZero() {
			st.LastRemoteDate[ed] = remoteDate
		}
		if etag != "" {
			st.ETags[ed] = etag
		}

		// decide if we should download
		lastDL := st.LastDownloaded[ed]
		minAgeOK := time.Since(lastDL) >= u.cfg.MinAgeBetweenDL
		newer := remoteDate.IsZero() || remoteDate.After(lastDL)

		if !minAgeOK || !newer {
			// Nothing to do
			continue
		}

		logf("[maxmind] updating %s (lastDL=%v, remoteDate=%v)", ed, lastDL, remoteDate)
		if err := u.downloadAndInstall(ctx, url, ed); err != nil {
			logf("[maxmind] download/install failed for %s: %v", ed, err)
			continue
		}
		st.LastDownloaded[ed] = time.Now()
	}

	if err := u.saveState(st); err != nil {
		logf("[maxmind] save state error: %v", err)
	}
}

func (u *Updater) head(ctx context.Context, url string) (time.Time, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return time.Time{}, "", err
	}
	if u.useMaxMindSource() {
		req.SetBasicAuth(u.cfg.AccountID, u.cfg.LicenseKey)
	}
	resp, err := u.httpc.Do(req)
	if err != nil {
		return time.Time{}, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Time{}, "", fmt.Errorf("status %d", resp.StatusCode)
	}

	// Prefer Last-Modified; fall back to filename date in Content-Disposition
	var remoteDate time.Time
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			remoteDate = t
		}
	}
	if remoteDate.IsZero() {
		if cd := resp.Header.Get("Content-Disposition"); cd != "" {
			if m := dispDate.FindStringSubmatch(cd); len(m) == 2 {
				if t, err := time.Parse("20060102", m[1]); err == nil {
					remoteDate = t
				}
			}
		}
	}

	etag := resp.Header.Get("ETag")
	return remoteDate, etag, nil
}

func (u *Updater) downloadAndInstall(ctx context.Context, url, edition string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	if u.useMaxMindSource() {
		req.SetBasicAuth(u.cfg.AccountID, u.cfg.LicenseKey)
	}
	resp, err := u.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	outBase := canonicalOutputName(edition)
	outPath := filepath.Join(u.cfg.Dir, outBase)

	if isTarGZResponse(resp, url) {
		return extractFromTarGZ(resp.Body, u.cfg.Dir, outBase, outPath, edition)
	}
	return streamToAtomicFile(resp.Body, u.cfg.Dir, outBase, outPath)
}

func canonicalOutputName(edition string) string {
	switch edition {
	case "GeoLite2-ASN":
		return "GeoLite2-ASN.mmdb"
	case "GeoLite2-City", "GeoLite2-Country":
		return "GeoLite2-City.mmdb"
	default:
		return edition + ".mmdb"
	}
}

func isTarGZResponse(resp *http.Response, sourceURL string) bool {
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "gzip") {
		return true
	}
	if cd := strings.ToLower(resp.Header.Get("Content-Disposition")); strings.Contains(cd, ".tar.gz") {
		return true
	}
	return strings.Contains(strings.ToLower(sourceURL), ".tar.gz")
}

func extractFromTarGZ(r io.Reader, dir, outBase, outPath, edition string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if hdr.FileInfo().IsDir() || !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}
		return streamToAtomicFile(tr, dir, outBase, outPath)
	}
	return fmt.Errorf("no .mmdb found in archive for %s", edition)
}

func streamToAtomicFile(r io.Reader, dir, outBase, outPath string) error {
	tmp, err := os.CreateTemp(dir, outBase+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := io.Copy(tmp, r); err != nil {
		cerr := tmp.Close()
		rerr := os.Remove(tmpPath)
		return errors.Join(err, cerr, rerr)
	}
	if err := tmp.Chmod(0o644); err != nil { /* non-fatal */
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		if rerr := os.Remove(tmpPath); rerr != nil {
			return errors.Join(err, rerr)
		}
		return err
	}
	return nil
}

func (u *Updater) statePath() string { return filepath.Join(u.cfg.Dir, ".state.json") }

func (u *Updater) loadState() (*state, error) {
	b, err := os.ReadFile(u.statePath())
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.LastDownloaded == nil {
		s.LastDownloaded = map[string]time.Time{}
	}
	if s.LastRemoteDate == nil {
		s.LastRemoteDate = map[string]time.Time{}
	}
	if s.ETags == nil {
		s.ETags = map[string]string{}
	}
	return &s, nil
}

func (u *Updater) saveState(s *state) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := u.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, u.statePath())
}
