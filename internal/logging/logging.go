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
	logFile           *os.File
	apiLogFile        *os.File
	detectorLogFile   *os.File
	smtpLogFile       *os.File
	challengesLogFile *os.File
	wafLogFile *os.File
	mysqlLogFile      *os.File // mysql enforcer
	socketLogFile     *os.File
	once              sync.Once
	cfg               *config.LoggingConfig
	clamLogFile       *os.File
	lsmLogFile        *os.File // cfm-lsm DETECT + lifecycle lines
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

		// CLAM log
		clamPath := cfg.CLAMFile
		if clamPath == "" && cfg.File != "" {
			base := cfg.File
			ext := filepath.Ext(base)
			if ext == "" {
				clamPath = base + ".clam"
			} else {
				clamPath = strings.TrimSuffix(base, ext) + ".clam" + ext
			}
		}
		if clamPath == "" {
			clamPath = "/var/log/cfm/cfm.clam.log"
		}
		if f, err := os.OpenFile(clamPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
			clamLogFile = f
		} else {
			fmt.Printf("failed to open clam log file %s: %v\n", clamPath, err)
		}

		// LSM log (/var/log/cfm/lsm.log). Honours LSM_LOG_FILE if set
		// in cfm.conf; otherwise defaults to /var/log/cfm/lsm.log so
		// operators get cfm-lsm DETECT + lifecycle lines in a dedicated
		// file rather than mixed into the main cfm.log. Same opening
		// rules as the other per-subsystem sinks: O_APPEND|O_CREATE,
		// failure falls back transparently to logFile (cfm.log) so a
		// permissions hiccup doesn't drop events.
		lsmPath := cfg.LSMFile
		if lsmPath == "" {
			lsmPath = "/var/log/cfm/lsm.log"
		}
		if f, err := os.OpenFile(lsmPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
			lsmLogFile = f
		} else {
			fmt.Printf("failed to open lsm log file %s: %v\n", lsmPath, err)
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

		// SOCKET bridge log
		socketPath := cfg.SOCKETFile
		if socketPath == "" && cfg.File != "" {
			base := cfg.File
			ext := filepath.Ext(base)
			if ext == "" {
				socketPath = base + ".socket"
			} else {
				socketPath = strings.TrimSuffix(base, ext) + ".socket" + ext
			}
		}
		if socketPath != "" {
			if f, err := os.OpenFile(socketPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
				socketLogFile = f
			} else {
				fmt.Printf("failed to open socket log file %s: %v\n", socketPath, err)
			}
		}
		if challengesPath != "" {
			if f, err := os.OpenFile(challengesPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
				challengesLogFile = f
			} else {
				fmt.Printf("failed to open challenges log file %s: %v\n", challengesPath, err)
			}
		}

		// WAF log
		wafPath := cfg.WAFFile
		if wafPath == "" && cfg.File != "" {
			base := cfg.File
			ext := filepath.Ext(base)
			if ext == "" {
				wafPath = base + ".waf"
			} else {
				wafPath = strings.TrimSuffix(base, ext) + ".waf" + ext
			}
		}
		if wafPath == "" {
			wafPath = "/var/log/cfm/cfm.waf.log"
		}
		if f, err := os.OpenFile(wafPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
			wafLogFile = f
		} else {
			fmt.Printf("failed to open waf log file %s: %v\n", wafPath, err)
		}

		// MYSQL GOVERNOR log
		mysqlPath := cfg.MYSQLFile
		if mysqlPath == "" && cfg.File != "" {
			base := cfg.File
			ext := filepath.Ext(base)
			if ext == "" {
				mysqlPath = base + ".mysql"
			} else {
				mysqlPath = strings.TrimSuffix(base, ext) + ".mysql" + ext
			}
		}
		if mysqlPath != "" {
			if f, err := os.OpenFile(mysqlPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
				mysqlLogFile = f
			} else {
				fmt.Printf("failed to open mysql log file %s: %v\n", mysqlPath, err)
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
	} else if logFile != nil {
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
	} else if logFile != nil {
		_, _ = logFile.WriteString(line)
	}
}

// NEW: ξεχωριστό κανάλι για Challenges Logs
func LogfCHALLENGES(format string, args ...interface{}) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s %s\n", ts, msg)

	if cfg == nil || cfg.CHALLENGESStdout {
		fmt.Print(line)
	}
	if challengesLogFile != nil {
		_, _ = challengesLogFile.WriteString(line)
	} else if logFile != nil {
		_, _ = logFile.WriteString(line)
	}
}

// NEW: ξεχωριστό κανάλι για WAF Logs
func LogfWAF(format string, args ...interface{}) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s %s\n", ts, msg)

	if cfg == nil || cfg.WAFStdout {
		fmt.Print(line)
	}
	if wafLogFile != nil {
		_, _ = wafLogFile.WriteString(line)
	} else if logFile != nil {
		_, _ = logFile.WriteString(line)
	}
}


func LogfSMTP(format string, args ...interface{}) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("%s %s\n", ts, fmt.Sprintf(format, args...))
	if smtpLogFile != nil {
		_, _ = smtpLogFile.WriteString(line)
	}
	if cfg == nil || cfg.SMTPStdout {
		fmt.Print(line)
	}
}

// LogfMYSQLGOVERNOR writes governor events to cfm.mysql.log.
func LogfMYSQLGOVERNOR(format string, args ...interface{}) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s %s\n", ts, msg)

	if cfg == nil || cfg.MYSQLStdout {
		fmt.Print(line)
	}
	if mysqlLogFile != nil {
		_, _ = mysqlLogFile.WriteString(line)
	} else if logFile != nil {
		_, _ = logFile.WriteString(line)
	}
}

// CLAM LOGGING
func LogfCLAM(format string, args ...interface{}) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s %s\n", ts, msg)

	if cfg == nil || cfg.CLAMStdout {
		fmt.Print(line)
	}
	if clamLogFile != nil {
		_, _ = clamLogFile.WriteString(line)
	} else if logFile != nil {
		_, _ = logFile.WriteString(line)
	}
}

// LogfLSM writes cfm-lsm DETECT + lifecycle events to the dedicated
// lsm log (default /var/log/cfm/lsm.log; configurable via LSM_LOG_FILE
// in cfm.conf). Falls back to the main cfm.log when the dedicated file
// could not be opened — so a permissions hiccup never drops events.
//
// kmsg emission is independent (see internal/lsm/kmsg.go) so an
// operator who routes /dev/kmsg via rsyslog still gets the same lines.
func LogfLSM(format string, args ...interface{}) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s %s\n", ts, msg)

	if cfg == nil || cfg.LSMStdout {
		fmt.Print(line)
	}
	if lsmLogFile != nil {
		_, _ = lsmLogFile.WriteString(line)
	} else if logFile != nil {
		_, _ = logFile.WriteString(line)
	}
}

func LogfSOCKET(format string, args ...interface{}) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s %s\n", ts, msg)

	if cfg == nil || cfg.SOCKETStdout {
		fmt.Print(line)
	}
	if socketLogFile != nil {
		_, _ = socketLogFile.WriteString(line)
	} else if logFile != nil {
		_, _ = logFile.WriteString(line)
	}
}
