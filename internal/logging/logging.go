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
    smtpLogFile *os.File
    challengesLogFile *os.File
    once sync.Once
    cfg  *config.LoggingConfig

)

var debugEnabled = os.Getenv("CFM_DEBUG") == "1"
func DebugEnabled() bool { return debugEnabled }


// Init πρέπει να καλεστεί από main με την config
func Init(c *config.LoggingConfig) {
    cfg = c
    once.Do(func() {
        // κύριο log
        if cfg.File != "" {
            if f, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
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
            if f, err := os.OpenFile(apiPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
                apiLogFile = f
            } else {
                fmt.Printf("failed to open api log file %s: %v\n", apiPath, err)
            }
        }


        // SMTP log (cfm.smtp.log). If SMTPFile empty, derive from main log path.
        smtpPath := cfg.SMTPFile
        if smtpPath == "" && cfg.File != "" {
            base := cfg.File
            ext := filepath.Ext(base)
            if ext == "" {
                smtpPath = base + ".smtp"
            } else {
                smtpPath = strings.TrimSuffix(base, ext) + ".smtp" + ext
            }
        }
        if smtpPath != "" {
            if f, err := os.OpenFile(smtpPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
                smtpLogFile = f
            } else {
                fmt.Printf("failed to open smtp log file %s: %v\n", smtpPath, err)
            }
        }


// CHALLENGES log
challengesPath := cfg.CHALLENGESFile
if challengesPath == "" && cfg.File != "" {
    base := cfg.File
    ext := filepath.Ext(base)
    if ext == "" {
        challengesPath = base + ".challenges"
    } else {
        challengesPath = strings.TrimSuffix(base, ext) + ".challenges" + ext
    }
}
if challengesPath != "" {
    if f, err := os.OpenFile(challengesPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
        challengesLogFile = f
    } else {
        fmt.Printf("failed to open challenges log file %s: %v\n", challengesPath, err)
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
            if f, err := os.OpenFile(detectorPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
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





// NEW: ξεχωριστό κανάλι για Challenges Logs (web challenges, captcha/js challenge, etc.)
func LogfCHALLENGES(format string, args ...interface{}) {
    ts := time.Now().Format("2006-01-02 15:04:05")
    msg := fmt.Sprintf(format, args...)
    line := fmt.Sprintf("%s %s\n", ts, msg)

    if cfg == nil || cfg.CHALLENGESStdout {
        fmt.Print(line)
    }
    if challengesLogFile != nil {
        _, _ = challengesLogFile.WriteString(line)
    } else if logFile != nil { // fallback
        _, _ = logFile.WriteString(line)
    }
}






func LogfSMTP(format string, args ...interface{}) {
    ts := time.Now().Format("2006-01-02 15:04:05")
    line := fmt.Sprintf("%s %s\n", ts, fmt.Sprintf(format, args...))
    if smtpLogFile != nil { _, _ = smtpLogFile.WriteString(line) }
    if cfg == nil || cfg.SMTPStdout { fmt.Print(line) }
}
