// internal/logging/logging.go
package logging

import (
    "cfm/internal/config"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

var (
    logFile    *os.File
    apiLogFile *os.File
    detectorLogFile *os.File

    once sync.Once
    cfg  *config.LoggingConfig
)

// Init πρέπει να καλεστεί από main με την config
func Init(c *config.LoggingConfig) {
    cfg = c
    once.Do(func() {
        // κύριο log
        if cfg.File != "" {
            if f, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
                logFile = f
            } else {
                fmt.Printf("failed to open log file %s: %v\n", cfg.File, err)
            }
        }

        // API log
        apiPath := cfg.APIFile
        if apiPath == "" && cfg.File != "" {
            base := cfg.File
            ext := filepath.Ext(base)
            if ext == "" {
                apiPath = base + ".api"
            } else {
                apiPath = strings.TrimSuffix(base, ext) + ".api" + ext
            }
        }
        if apiPath != "" {
            if f, err := os.OpenFile(apiPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
                apiLogFile = f
            } else {
                fmt.Printf("failed to open api log file %s: %v\n", apiPath, err)
            }
        }







        // DETECTOR log
        detectorPath := cfg.DETECTORFile
        if detectorPath == "" && cfg.File != "" {
            base := cfg.File
            ext := filepath.Ext(base)
            if ext == "" {
                detectorPath = base + ".detector"
            } else {
                detectorPath = strings.TrimSuffix(base, ext) + ".detector" + ext
            }
        }
        if detectorPath != "" {
            if f, err := os.OpenFile(detectorPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
                detectorLogFile = f
            } else {
                fmt.Printf("failed to open detector log file %s: %v\n", detectorPath, err)
            }
        }
    })

}






func Logf(format string, args ...interface{}) {
    ts := time.Now().Format("2006-01-02 15:04:05")
    msg := fmt.Sprintf(format, args...)
    line := fmt.Sprintf("%s %s\n", ts, msg)

    if cfg == nil || cfg.Stdout {
        fmt.Print(line)
    }
    if logFile != nil {
        _, _ = logFile.WriteString(line)
    }
}

// NEW: ξεχωριστό κανάλι για API logs
func LogfAPI(format string, args ...interface{}) {
    ts := time.Now().Format("2006-01-02 15:04:05")
    msg := fmt.Sprintf(format, args...)
    line := fmt.Sprintf("%s %s\n", ts, msg)

    if cfg == nil || cfg.APIStdout {
        fmt.Print(line)
    }
    if apiLogFile != nil {
        _, _ = apiLogFile.WriteString(line)
    } else if logFile != nil { // fallback: αν δεν άνοιξε API log, γράψε στο κύριο
        _, _ = logFile.WriteString(line)
    }
}




// NEW: ξεχωριστό κανάλι για Detector Logs
func LogfDETECTOR(format string, args ...interface{}) {
    ts := time.Now().Format("2006-01-02 15:04:05")
    msg := fmt.Sprintf(format, args...)
    line := fmt.Sprintf("%s %s\n", ts, msg)

    if cfg == nil || cfg.DETECTORStdout {
        fmt.Print(line)
    }
    if detectorLogFile != nil {
        _, _ = detectorLogFile.WriteString(line)
    } else if logFile != nil { // fallback: αν δεν άνοιξε API log, γράψε στο κύριο
        _, _ = logFile.WriteString(line)
    }
}

