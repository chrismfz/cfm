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
}

// AnalyzeIP σκανάρει το πλήρες TSV log και βρίσκει όλα τα hits αυτής της IP.
// maxLines <= 0 σημαίνει "διάβασε όλο το αρχείο".
func (e *Engine) AnalyzeIP(ip string, maxLines int64) (AnalyzeIPResult, error) {
    res := AnalyzeIPResult{IP: ip}
    logPath := e.cfg.LogPath
    if logPath == "" {
        return res, fmt.Errorf("no LogPath configured for webdetector")
    }

    f, err := os.Open(logPath)
    if err != nil {
        return res, err
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    var (
        lineCount int64
        firstSet  bool
    )

    vhostCounts := make(map[string]int)

    for scanner.Scan() {
        if maxLines > 0 && lineCount >= maxLines {
            break
        }
        lineCount++

        line := scanner.Text()
        rec, ok := parseTSV(line)
        if !ok {
            continue
        }
        if rec.IP != ip {
            continue
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
    }

    if err := scanner.Err(); err != nil {
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
    logPath := e.cfg.LogPath
    if logPath == "" {
        return res, fmt.Errorf("no LogPath configured for webdetector")
    }

    f, err := os.Open(logPath)
    if err != nil {
        return res, err
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    var (
        lineCount int64
        firstSet  bool
    )

    ipCounts := make(map[string]int)

    for scanner.Scan() {
        if maxLines > 0 && lineCount >= maxLines {
            break
        }
        lineCount++

        line := scanner.Text()
        rec, ok := parseTSV(line)
        if !ok {
            continue
        }
        if rec.Host != h {
            continue
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
    }

    if err := scanner.Err(); err != nil {
        return res, err
    }

    // Μετατροπή ipCounts → []TopKV (ταξινομημένα desc)
    kvs := make([]TopKV, 0, len(ipCounts))
    for ip, c := range ipCounts {
        kvs = append(kvs, TopKV{Key: ip, Count: c})
    }
    sort.Slice(kvs, func(i, j int) bool { return kvs[i].Count > kvs[j].Count })

    res.IPCnt = kvs
    return res, nil
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
