// internal/webdetector/analyze.go
// offline log analyzer

package webdetector

import (
    "bufio"
    "fmt"
    "os"
    "sort"
    "time"
    "strings"
    "net"
    "strconv"
    "path/filepath"
    "io"

)

const (
    // Μόνο IPs με τουλάχιστον N requests θα μπουν στο breakdown / enrichment.
    analyzeHostMinCount = 2

    // Προστασία: ακόμα κι αν υπάρχουν χιλιάδες IPs, κάνε enrich μόνο στα top N.
    analyzeHostMaxIPs = 500
)


// AnalyzeIPResult είναι offline ανάλυση μιας IP απευθείας από το log.
type AnalyzeIPResult struct {
    IP       string  `json:"ip"`
    TotalReq int     `json:"total_req"`
    VhostCnt []TopKV `json:"vhosts"`

    FirstTS float64 `json:"first_ts"`
    LastTS  float64 `json:"last_ts"`
}

// AnalyzeHostResult: μπορούμε να το χρησιμοποιήσουμε στο επόμενο βήμα.
type AnalyzeHostResult struct {
    Host     string  `json:"host"`
    TotalReq int     `json:"total_req"`
    IPCnt    []TopKV `json:"ips"`

    FirstTS float64 `json:"first_ts"`
    LastTS  float64 `json:"last_ts"`
    EnrichedIPs []map[string]string `json:"enriched_ips,omitempty"`

}

// AnalyzeIP σκανάρει το πλήρες TSV log και βρίσκει όλα τα hits αυτής της IP.
// maxLines <= 0 σημαίνει "διάβασε όλο το αρχείο".
func (e *Engine) AnalyzeIP(ip string, maxLines int64) (AnalyzeIPResult, error) {
    res := AnalyzeIPResult{IP: ip}

    var (
        lineCount int64
        firstSet  bool
    )

    vhostCounts := make(map[string]int)

    err := e.scanOfflineLines(maxLines, func(line string) bool {
        lineCount++
        rec, ok := e.adapter.Parse(line)

        if !ok {
            return true
        }
        if rec.IP != ip {
            return true
        }

        // aggregate
        res.TotalReq++
        if rec.Host != "" {
            vhostCounts[rec.Host]++
        }

        // κρατάμε min/max TS
        if !firstSet {
            res.FirstTS = rec.TS
            res.LastTS = rec.TS
            firstSet = true
        } else {
            if rec.TS < res.FirstTS {
                res.FirstTS = rec.TS
            }
            if rec.TS > res.LastTS {
                res.LastTS = rec.TS
            }
        }

        return true
    })
    if err != nil {
        return res, err
    }

    // Μετατροπή vhostCounts → []TopKV (ταξινομημένα desc)
    kvs := make([]TopKV, 0, len(vhostCounts))
    for h, c := range vhostCounts {
        kvs = append(kvs, TopKV{Key: h, Count: c})
    }
    sort.Slice(kvs, func(i, j int) bool { return kvs[i].Count > kvs[j].Count })

    res.VhostCnt = kvs
    return res, nil
}


// AnalyzeHost σκανάρει το πλήρες TSV log και βρίσκει όλα τα hits αυτού του vhost.
// maxLines <= 0 σημαίνει "διάβασε όλο το αρχείο".
func (e *Engine) AnalyzeHost(host string, maxLines int64) (AnalyzeHostResult, error) {
    h := strings.ToLower(strings.TrimSpace(host))

    res := AnalyzeHostResult{Host: h}

    var (
        lineCount int64
        firstSet  bool
    )

    ipCounts := make(map[string]int)


    err := e.scanOfflineLines(maxLines, func(line string) bool {
        lineCount++
        rec, ok := e.adapter.Parse(line)


        if !ok {
            return true
        }
        if rec.Host != h {
            return true
        }

        res.TotalReq++
        if rec.IP != "" {
            ipCounts[rec.IP]++
        }

        // κρατάμε min/max TS
        if !firstSet {
            res.FirstTS = rec.TS
            res.LastTS = rec.TS
            firstSet = true
        } else {
            if rec.TS < res.FirstTS {
                res.FirstTS = rec.TS
            }
            if rec.TS > res.LastTS {
                res.LastTS = rec.TS
            }
        }
        return true
    })
    if err != nil {
        return res, err
    }



 // Μετατροπή ipCounts → []TopKV (ταξινομημένα desc),
    // αλλά αγνοούμε IPs με πολύ λίγα hits (π.χ. μόνο 1).
    kvs := make([]TopKV, 0, len(ipCounts))
    for ip, c := range ipCounts {
        if c < analyzeHostMinCount {
            // Σουρεαλιστικά πολλές IPs με 1 hit → skip για να μην κάνουμε enrich.
            continue
        }
        kvs = append(kvs, TopKV{Key: ip, Count: c})
    }

    // Αν μετά το φιλτράρισμα δεν έμεινε τίποτα, τελειώσαμε.
    if len(kvs) == 0 {
        res.IPCnt = nil
        return res, nil
    }

    sort.Slice(kvs, func(i, j int) bool { return kvs[i].Count > kvs[j].Count })

    // Προστασία: enrichment μόνο στα top N IPs.
    if len(kvs) > analyzeHostMaxIPs {
        kvs = kvs[:analyzeHostMaxIPs]
    }

    res.IPCnt = kvs

    // Enrich μόνο τις φιλτραρισμένες + sliced IPs.
    if e.enr != nil {
        enriched := make([]map[string]string, 0, len(kvs))
        for _, kv := range kvs {
            ipStr := kv.Key
            if net.ParseIP(ipStr) == nil {
                continue
            }

            info := map[string]string{
                "ip":    ipStr,
                "count": strconv.Itoa(kv.Count),
            }

            geo := e.enr.Lookup(ipStr)
            if geo.PTR != "" {
                info["ptr"] = geo.PTR
            }
            if geo.ASN != 0 {
                info["asn"] = strconv.FormatUint(uint64(geo.ASN), 10)
            }
            if geo.ASNName != "" {
                info["asn_name"] = geo.ASNName
            }
            if geo.Country != "" {
                info["country"] = geo.Country
            }

            enriched = append(enriched, info)
        }

        if len(enriched) > 0 {
            res.EnrichedIPs = enriched
        }
    }

    return res, nil
}




// scanOfflineLines iterates through the configured log source for offline analysis.
// It feeds each line to fn(line). If fn returns false, scanning stops early.
// maxLines <= 0 means unlimited.
func (e *Engine) scanOfflineLines(maxLines int64, fn func(line string) bool) error {
    mode := strings.ToLower(strings.TrimSpace(e.cfg.Mode))
    if mode == "" {
        mode = "file"
    }

    // MODE=file: scan LogPath
    if mode == "file" {
        logPath := e.cfg.LogPath
        if logPath == "" {
            return fmt.Errorf("no LOG_PATH configured for webdetector")
        }
        f, err := os.Open(logPath)
        if err != nil {
            return err
        }
        defer f.Close()

        sc := bufio.NewScanner(f)
        var n int64
        for sc.Scan() {
            if maxLines > 0 && n >= maxLines {
                break
            }
            n++
            if !fn(sc.Text()) {
                break
            }
        }
        return sc.Err()
   }

    // MODE=folder: walk LogDir and scan each file
    if mode == "folder" {
        dir := e.cfg.LogDir
        if dir == "" {
            return fmt.Errorf("no LOG_DIR configured for webdetector")
        }
        st, err := os.Stat(dir)
        if err != nil {
            return err
        }
        if !st.IsDir() {
            return fmt.Errorf("LOG_DIR is not a directory: %s", dir)
        }

        glob := e.cfg.Glob
        if glob == "" {
            glob = "*.log"
        }

        var n int64
        walkFn := func(path string, de os.DirEntry, err error) error {
            if err != nil {
                return nil
            }
            if de.IsDir() {
                if !e.cfg.Recursive && path != dir {
                    return filepath.SkipDir
                }
                return nil
            }

            base := filepath.Base(path)
            lb := strings.ToLower(base)
            if strings.HasSuffix(lb, ".gz") || strings.HasSuffix(lb, ".bz2") || strings.HasSuffix(lb, ".zip") {
                return nil
            }
            if ok, _ := filepath.Match(glob, base); !ok {
                return nil
            }

            fi, serr := os.Stat(path)
            if serr != nil || !fi.Mode().IsRegular() {
                return nil
            }

            f, oerr := os.Open(path)
            if oerr != nil {
                return nil
            }
            defer f.Close()

            host := hostFromPath(path)
            sc := bufio.NewScanner(f)
            for sc.Scan() {
                if maxLines > 0 && n >= maxLines {
                    return io.EOF
                }
                n++
                // mimic DirTailer prefix so adapter can recover Host
                line := "@host=" + host + "\t" + sc.Text()
                if !fn(line) {
                    return io.EOF
                }
            }
            return nil
        }

        err = filepath.WalkDir(dir, walkFn)
        if err == io.EOF {
            return nil
        }
        return err
    }

    return fmt.Errorf("unsupported MODE=%q for offline scan", mode)
}

// hostFromPath extracts vhost from per-domain log filename.
// Mirrors the logic used in DirTailer.
func hostFromPath(path string) string {
    base := filepath.Base(path)
    base = strings.TrimSuffix(base, ".log")
    base = strings.TrimSuffix(base, ".access")
    base = strings.TrimSuffix(base, ".bytes")
    base = strings.TrimSuffix(base, ".error")
    if ext := filepath.Ext(base); ext != "" {
        base = strings.TrimSuffix(base, ext)
    }
    return strings.ToLower(base)
}




// helper για να δείξουμε ανθρώπινα timestamps στο CLI, αν χρειαστεί
func formatAnalyzeRange(firstTS, lastTS float64) (string, string) {
    if firstTS == 0 && lastTS == 0 {
        return "-", "-"
    }
    f := tsToTime(firstTS).Format(time.RFC3339)
    l := tsToTime(lastTS).Format(time.RFC3339)
    return f, l
}
