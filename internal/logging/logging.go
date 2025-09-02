package logging

import (
    "cfm/internal/config"
    "fmt"
    "os"
    "sync"
    "time"
)

var (
    logFile *os.File
    once    sync.Once
    cfg     *config.LoggingConfig
)

// Init πρέπει να καλεστεί από main με την config
func Init(c *config.LoggingConfig) {
    cfg = c
    once.Do(func() {
        if cfg.File != "" {
            f, err := os.OpenFile(cfg.File,
                os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
            if err == nil {
                logFile = f
            } else {
                fmt.Printf("failed to open log file %s: %v\n", cfg.File, err)
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
