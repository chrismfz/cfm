// Package phpinventory discovers the PHP builds installed on a host — across
// cPanel EA4, CloudLinux alt-php, DirectAdmin CustomBuild, LiteSpeed lsphp and
// system PHP — and reports, per build, its version, thread-safety, and whether
// the Snuffleupagus (or a conflicting Imunify) PHP extension is loaded.
//
// This is the read-only P0 of the PHP-runtime-defense roadmap
// (docs/roadmaps/php-runtime-defense.md): pure visibility, touches no config,
// safe to run fleet-wide. It sizes the build matrix any later SP work must
// target, and surfaces the one thing that is actionable today — a build with
// BOTH Snuffleupagus and Imunify's extension loaded (they hook the same layer;
// running both is the coexistence hazard the roadmap calls out).
package phpinventory

import (
	"bufio"
	"context"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// spModuleName is the exact `php -m` name of the Snuffleupagus extension.
const spModuleName = "snuffleupagus"

// proactiveModuleHints are substrings for Imunify's PHP-runtime extension.
// Confirmed on a live cPanel+CloudLinux host (ea-php 8.1/8.2/8.3, 2026-07-23):
// `php -m` reports the module as exactly "i360" (i360.so in the modules dir,
// i360.ini in php.d, globally loaded). The broader hints stay as a backstop.
var proactiveModuleHints = []string{"i360", "imunify", "proactive"}

// probeTimeout bounds each `php -v`/`php -m` exec so a hung binary can't stall
// the whole inventory.
const probeTimeout = 5 * time.Second

// Build is one discovered PHP binary and what we learned probing it.
type Build struct {
	Path         string `json:"path"`
	Flavor       string `json:"flavor"` // ea4 | alt-php | directadmin | litespeed | remi | system
	Version      string `json:"version,omitempty"`
	ZTS          bool   `json:"zts"`
	HasSP        bool   `json:"has_sp"`
	HasProactive bool   `json:"has_proactive"`
	ModuleCount  int    `json:"module_count"`
	Err          string `json:"error,omitempty"`
}

// Report is the full inventory for a host.
type Report struct {
	Builds   []Build  `json:"builds"`
	Warnings []string `json:"warnings,omitempty"`
}

// probe pairs a binary glob with the flavour it implies. No leading slash so a
// Scanner.Root prefix can be joined for testing.
type probe struct{ glob, flavor string }

var defaultProbes = []probe{
	{"opt/cpanel/ea-php*/root/usr/bin/php", "ea4"},
	{"opt/alt/php*/usr/bin/php", "alt-php"},
	{"usr/local/php*/bin/php", "directadmin"},
	{"usr/local/lsws/lsphp*/bin/php", "litespeed"},
	{"usr/local/lsws/lsphp*/bin/lsphp", "litespeed"},
	{"opt/remi/php*/root/usr/bin/php", "remi"},
	{"usr/bin/php", "system"},
	{"usr/local/bin/php", "system"},
}

// Scanner discovers and probes PHP builds. Root and Run are injectable so the
// discovery + parsing can be unit-tested without real PHP on the host.
type Scanner struct {
	// Root is prepended to every probe glob ("" ⇒ "/" via filepath.Join).
	Root string
	// Probes overrides the default binary globs (nil ⇒ defaultProbes).
	Probes []probe
	// Run executes a discovered binary; defaults to a bounded exec.
	Run func(bin string, args ...string) (string, error)
}

// DefaultScanner scans the real filesystem with a bounded exec.
func DefaultScanner() *Scanner { return &Scanner{Run: execPHP} }

func execPHP(bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).Output()
	return string(out), err
}

// Scan discovers every PHP build and returns the inventory. Best-effort: a
// build that fails to probe is still listed with its Err set.
func (s *Scanner) Scan() Report {
	run := s.Run
	if run == nil {
		run = execPHP
	}
	probes := s.Probes
	if probes == nil {
		probes = defaultProbes
	}

	var builds []Build
	seen := map[string]bool{}
	for _, p := range probes {
		matches, _ := filepath.Glob(filepath.Join(s.Root, p.glob))
		sort.Strings(matches)
		for _, path := range matches {
			if seen[path] {
				continue
			}
			seen[path] = true
			builds = append(builds, probeBuild(run, path, p.flavor))
		}
	}

	rep := Report{Builds: builds}
	for _, b := range builds {
		switch {
		case b.Err != "":
			rep.Warnings = append(rep.Warnings, "probe failed for "+b.Path+": "+b.Err)
		case b.HasSP && b.HasProactive:
			// The one thing actionable today: two extensions hooking the same
			// PHP layer. Do not run both.
			rep.Warnings = append(rep.Warnings,
				"conflict: snuffleupagus AND an Imunify extension both loaded in "+b.Path+" — do not run both")
		}
	}
	return rep
}

var versionRe = regexp.MustCompile(`^PHP\s+(\S+)`)

func probeBuild(run func(string, ...string) (string, error), path, flavor string) Build {
	b := Build{Path: path, Flavor: flavor}

	v, err := run(path, "-v")
	if err != nil {
		b.Err = err.Error()
		return b
	}
	if m := versionRe.FindStringSubmatch(strings.TrimSpace(v)); m != nil {
		b.Version = m[1]
	}
	// The -v banner tags the build "(ZTS)" or "(NTS)".
	b.ZTS = strings.Contains(v, "(ZTS)")

	mods, err := run(path, "-m")
	if err != nil {
		b.Err = err.Error()
		return b
	}
	b.HasSP, b.HasProactive, b.ModuleCount = parseModules(mods)
	return b
}

// parseModules reads `php -m` output: one module per line, with `[PHP Modules]`
// / `[Zend Modules]` section headers to skip.
func parseModules(out string) (hasSP, hasProactive bool, count int) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		count++
		low := strings.ToLower(line)
		if low == spModuleName {
			hasSP = true
		}
		for _, hint := range proactiveModuleHints {
			if strings.Contains(low, hint) {
				hasProactive = true
				break
			}
		}
	}
	return hasSP, hasProactive, count
}
