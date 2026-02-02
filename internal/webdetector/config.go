// internal/webdetector/config.go
package webdetector

import "time"

// Config is the full configuration for the webdetector engine.
// It is built from [webdetector] in cfm.conf by the detector register.
type Config struct {
	// Log ingestion
	Mode     string        // "file" (for now)
	LogPath  string        // TSV log path
	Every    time.Duration // detector tick interval
	Window   time.Duration // short-window horizon (sliding)
	Cooldown time.Duration // reserved for future alert gating
	SampleLimit int        // max sample lines per host for drilldown

	// Enrichment
	UseEnrich  bool
	UsePTR     bool
	EnrichDirs []string

	// Long-window scoring
	LongFactor int     // how many short windows ~= long horizon (e.g. 10)
	MinScore   float64 // minimum suspicious score

	// API
	APIListen string // "127.0.0.1:9070" etc.


	// IP threshold detectors (CSF-like)
	IP404Count int
	IP403Count int

	// 40x combo detector (403+404) with optional unique-path gating.
	IP40xComboCount       int
	IP40xComboUniquePaths int
	Ignore40xPrefixes     []string // optional: "/.well-known/", "/robots.txt", ...

	AgentList  []string      // substrings (lowercased)
	AgentCount int

	// Malicious path probes (webshell/env/uploader/etc)
	MalPathList  []string // substrings or paths (lowercased)
	MalPathFile  string   // optional file with one entry per line
	MalPathCount int

}

// FillDefaults ensures sane defaults if some fields are zero.
func (c *Config) FillDefaults() {
	if c.Every <= 0 {
		c.Every = 5 * time.Second
	}
	if c.Window <= 0 {
		c.Window = 120 * time.Second
	}
	if c.Cooldown <= 0 {
		c.Cooldown = 10 * time.Minute
	}
	if c.SampleLimit <= 0 {
		c.SampleLimit = 20
	}
	if c.LongFactor <= 0 {
		c.LongFactor = 10
	}
	if c.MinScore <= 0 {
		c.MinScore = 0.60
	}
	if c.APIListen == "" {
		c.APIListen = "127.0.0.1:9070"
	}

// Sensible defaults for the 40x combo detector (window defaults to 120s).
if c.IP40xComboCount > 0 {
    if c.IP40xComboUniquePaths <= 0 {
        c.IP40xComboUniquePaths = 20
    }
    if len(c.Ignore40xPrefixes) == 0 {
        c.Ignore40xPrefixes = []string{"/.well-known/", "/robots.txt", "/favicon.ico", "/sitemap", "/apple-touch-icon", "/manifest.json"}
    }
}


}

// LongHorizon returns the long-window horizon duration.
func (c Config) LongHorizon() time.Duration {
	return time.Duration(c.LongFactor) * c.Window
}

