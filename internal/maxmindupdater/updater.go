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
}

// persisted state to avoid needless downloads
type state struct {
    LastChecked    time.Time                       `json:"last_checked"`
    LastDownloaded map[string]time.Time            `json:"last_downloaded"`
    LastRemoteDate map[string]time.Time            `json:"last_remote_date"`
    ETags          map[string]string               `json:"etags,omitempty"`
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
    if cfg.Dir == "" { cfg.Dir = "/var/lib/cfm/maxmind" }
    if cfg.CheckEvery == 0 { cfg.CheckEvery = 24 * time.Hour }
    if cfg.MinAgeBetweenDL == 0 { cfg.MinAgeBetweenDL = 72 * time.Hour }
    if cfg.HTTPTimeout == 0 { cfg.HTTPTimeout = 30 * time.Second }
    if cfg.Permalinks == nil {
        cfg.Permalinks = map[string]string{
            "GeoLite2-ASN":  "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz",
            "GeoLite2-City": "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
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

func (u *Updater) Run(ctx context.Context, logf func(string, ...any)) error {
    if !u.cfg.Enabled { return nil }
    if err := os.MkdirAll(u.cfg.Dir, 0o755); err != nil { return err }

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
        url := u.cfg.Permalinks[ed]
        if url == "" {
            logf("[maxmind] no permalink for edition %s; skipping", ed)
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
    req.SetBasicAuth(u.cfg.AccountID, u.cfg.LicenseKey)
    resp, err := u.httpc.Do(req)
    if err != nil { return time.Time{}, "", err }
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

    req.SetBasicAuth(u.cfg.AccountID, u.cfg.LicenseKey)
    resp, err := u.httpc.Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    if resp.StatusCode >= 400 {
        return fmt.Errorf("status %d", resp.StatusCode)
    }

    // Stream through gzip -> tar, extract first .mmdb
    gr, err := gzip.NewReader(resp.Body)
    if err != nil { return err }
    defer gr.Close()

    tr := tar.NewReader(gr)

    var tmpPath string
    outBase := edition + ".mmdb"
    outPath := filepath.Join(u.cfg.Dir, outBase)

    for {
        hdr, err := tr.Next()
        if errors.Is(err, io.EOF) { break }
        if err != nil { return err }
        if hdr.FileInfo().IsDir() { continue }
        if !strings.HasSuffix(hdr.Name, ".mmdb") { continue }

        // Write to temp then atomic rename
        tmp, err := os.CreateTemp(u.cfg.Dir, outBase+".tmp-*")
        if err != nil { return err }
        tmpPath = tmp.Name()

        if _, err := io.Copy(tmp, tr); err != nil {
            // Make best effort to close and remove; join errors if any.
            cerr := tmp.Close()
            rerr := os.Remove(tmpPath)
            return errors.Join(err, cerr, rerr)
        }
        if err := tmp.Chmod(0o644); err != nil { /* non-fatal */ }
        if err := tmp.Close(); err != nil {
            // Ensure temp file is not left behind on close failure.
            _ = os.Remove(tmpPath)
            return err
        }
        // Atomic swap
        if err := os.Rename(tmpPath, outPath); err != nil {
            // Try to remove the temp file; if that also fails, join errors.
            if rerr := os.Remove(tmpPath); rerr != nil {
                return errors.Join(err, rerr)
            }
            return err
        }
        // Extract first .mmdb only
        return nil
    }

    return fmt.Errorf("no .mmdb found in archive for %s", edition)
}

func (u *Updater) statePath() string { return filepath.Join(u.cfg.Dir, ".state.json") }

func (u *Updater) loadState() (*state, error) {
    b, err := os.ReadFile(u.statePath())
    if err != nil { return nil, err }
    var s state
    if err := json.Unmarshal(b, &s); err != nil { return nil, err }
    if s.LastDownloaded == nil { s.LastDownloaded = map[string]time.Time{} }
    if s.LastRemoteDate == nil { s.LastRemoteDate = map[string]time.Time{} }
    if s.ETags == nil { s.ETags = map[string]string{} }
    return &s, nil
}

func (u *Updater) saveState(s *state) error {
    b, err := json.MarshalIndent(s, "", "  ")
    if err != nil {
        return err
    }
    tmp := u.statePath() + ".tmp"
    if err := os.WriteFile(tmp, b, 0o644); err != nil { return err }
    return os.Rename(tmp, u.statePath())
}
