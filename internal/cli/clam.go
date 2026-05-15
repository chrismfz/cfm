package cli

import (
	"bufio"
	"cfm/internal/clam"
	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func RunClam(args []string, cfgDir string) int {
	if len(args) == 0 {
		printClamHelp()
		return 2
	}

	cfg, err := loadClamConfig(cfgDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "clam: load config: %v\n", err)
		return 1
	}

	// Important: CLI path must init logging too, otherwise cfm.clam.log
	// is never opened and LogfCLAM falls back elsewhere.
	logging.Init(&cfg.Logging)

	client := clam.New(clam.Config{
		Enabled:    cfg.Clam.Enabled,
		Network:    cfg.Clam.Network,
		Address:    cfg.Clam.Address,
		Timeout:    cfg.Clam.Timeout,
		MaxWorkers: cfg.Clam.MaxWorkers,
		QueueSize:  cfg.Clam.QueueSize,
	})

	cmd := strings.ToLower(strings.TrimSpace(args[0]))
	switch cmd {
	case "help", "-h", "--help":
		printClamHelp()
		return 0

	case "status":
		return runClamStatus(client, cfg, cfgDir)

	case "enable":
		return runClamToggle(cfgDir, "CLAMD_ENABLED", true)
	case "disable":
		return runClamToggle(cfgDir, "CLAMD_ENABLED", false)

	case "hook":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: cfm clam hook {enable|disable|status}")
			return 2
		}
		switch strings.ToLower(strings.TrimSpace(args[1])) {
		case "enable":
			return runClamToggle(cfgDir, "CLAMD_NGINX_HOOK_ENABLED", true)
		case "disable":
			return runClamToggle(cfgDir, "CLAMD_NGINX_HOOK_ENABLED", false)
		case "status":
			return runClamHookStatus(cfg)
		default:
			fmt.Fprintf(os.Stderr, "clam hook: unknown subcommand: %s\n", args[1])
			return 2
		}

	case "ping":
		if err := client.Ping(); err != nil {
			fmt.Fprintf(os.Stderr, "clam ping failed: %v\n", err)
			logging.LogfCLAM("[clam_cli] action=ping result=error err=%q", err)
			return 1
		}
		fmt.Println("PONG")
		logging.LogfCLAM("[clam_cli] action=ping result=ok")
		return 0

	case "version":
		v, err := client.Version()
		if err != nil {
			fmt.Fprintf(os.Stderr, "clam version failed: %v\n", err)
			logging.LogfCLAM("[clam_cli] action=version result=error err=%q", err)
			return 1
		}
		fmt.Println(v)
		logging.LogfCLAM("[clam_cli] action=version result=ok version=%q", v)
		return 0

	case "scan":
		return runClamScan(client, cfg, args[1:])

	default:
		fmt.Fprintf(os.Stderr, "clam: unknown subcommand: %s\n\n", cmd)
		printClamHelp()
		return 2
	}
}



func runClamScan(client *clam.Client, cfg *cfgpkg.Config, args []string) int {
	fs := flag.NewFlagSet("clam scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	recursive := fs.Bool("recursive", true, "recurse into directories")
	quietClean := fs.Bool("quiet-clean", false, "suppress clean OK lines")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: cfm clam scan [--recursive=true] [--quiet-clean] <file-or-dir>")
		return 2
	}
	target := strings.TrimSpace(rest[0])
	if target == "" {
		fmt.Fprintln(os.Stderr, "clam scan: empty target")
		return 2
	}

	if !client.Enabled() {
		fmt.Fprintf(os.Stderr, "clam scan: disabled (CLAMD_ENABLED=%v, CLAMD address=%q)\n",
			cfg.Clam.Enabled, cfg.Clam.Address)
		return 2
	}

	fi, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "clam scan: stat %s: %v\n", target, err)
		return 1
	}

	var infected int

	if !fi.IsDir() {
		r, err := client.ScanFile(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "clam scan error: %v\n", err)
			logging.LogfCLAM("[clam_cli] path=%s result=error err=%q", target, err)
			return 1
		}
		printClamResult(r, *quietClean)
		logClamResult(r)
		if r.Infected {
			infected++
		}
	} else {
		if !*recursive {
			fmt.Fprintln(os.Stderr, "clam scan: target is directory; pass --recursive=true or scan a file")
			return 2
		}
		results, err := client.ScanPath(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "clam scan error: %v\n", err)
			logging.LogfCLAM("[clam_cli] path=%s result=error err=%q", target, err)
			return 1
		}
		for i := range results {
			printClamResult(&results[i], *quietClean)
			logClamResult(&results[i])
			if results[i].Infected {
				infected++
			}
		}
	}

	if infected > 0 {
		return 10
	}
	return 0
}

func printClamResult(r *clam.Result, quietClean bool) {
	switch {
	case r == nil:
		return
	case r.Infected:
		fmt.Printf("INFECTED\t%s\t%s\n", r.Path, r.Signature)
	case strings.HasSuffix(r.Raw, " OK"):
		if !quietClean {
			fmt.Printf("OK\t%s\n", r.Path)
		}
	default:
		fmt.Printf("ERROR\t%s\t%s\n", r.Path, r.Raw)
	}
}

func logClamResult(r *clam.Result) {
	if r == nil {
		return
	}
	switch {
	case r.Infected:
		logging.LogfCLAM("[clam_cli] path=%s result=infected sig=%q raw=%q", r.Path, r.Signature, r.Raw)
	case strings.HasSuffix(r.Raw, " OK"):
		logging.LogfCLAM("[clam_cli] path=%s result=clean raw=%q", r.Path, r.Raw)
	default:
		logging.LogfCLAM("[clam_cli] path=%s result=error raw=%q", r.Path, r.Raw)
	}
}

func loadClamConfig(cfgDir string) (*cfgpkg.Config, error) {
	var cfg cfgpkg.Config

	if cfgDir == "" {
		cfg.SetDefaults()
		return &cfg, nil
	}

	b, err := os.ReadFile(filepath.Join(cfgDir, "cfm.conf"))
	if err != nil {
		return nil, err
	}
	return LoadConfigWithAPIOverride(cfgDir, b)
}

func printClamHelp() {
	fmt.Println("Usage:")
	fmt.Println("  cfm clam status")
	fmt.Println("  cfm clam enable             # CLAMD_ENABLED=true  in cfm.conf")
	fmt.Println("  cfm clam disable            # CLAMD_ENABLED=false in cfm.conf")
	fmt.Println("  cfm clam hook enable        # CLAMD_NGINX_HOOK_ENABLED=true  (Lua upload interception)")
	fmt.Println("  cfm clam hook disable       # CLAMD_NGINX_HOOK_ENABLED=false")
	fmt.Println("  cfm clam hook status")
	fmt.Println("  cfm clam ping")
	fmt.Println("  cfm clam version")
	fmt.Println("  cfm clam scan <file>")
	fmt.Println("  cfm clam scan <dir>")
	fmt.Println("  cfm clam scan --quiet-clean <file-or-dir>")
}

// runClamToggle persists key=value into <cfgDir>/cfm.conf. The cfm
// daemon's existing fsnotify watcher on cfm.conf picks up the change
// and triggers the reload path that re-renders cfm_clamav_config.lua;
// no SIGHUP needed.
func runClamToggle(cfgDir, key string, enabled bool) int {
	if cfgDir == "" {
		fmt.Fprintln(os.Stderr, "clam: no cfm.conf path resolved (use --config or set CFM_CONFIG_DIR)")
		return 1
	}
	val := "false"
	if enabled {
		val = "true"
	}
	confPath := filepath.Join(cfgDir, "cfm.conf")
	if err := UpsertConfKey(confPath, key, val); err != nil {
		fmt.Fprintf(os.Stderr, "clam toggle: %v\n", err)
		logging.LogfCLAM("[clam_cli] action=toggle key=%s value=%s result=error err=%q", key, val, err)
		return 1
	}
	fmt.Printf("OK\t%s=%s in %s\n", key, val, confPath)
	logging.LogfCLAM("[clam_cli] action=toggle key=%s value=%s result=ok path=%s", key, val, confPath)
	return 0
}

func runClamHookStatus(cfg *cfgpkg.Config) int {
	deployed, deployedKnown := readDeployedClamavHookEnabled()
	fmt.Printf("nginx hook (CLAMD_NGINX_HOOK_ENABLED): %v\n", cfg.Clam.NginxHookEnabled)
	fmt.Printf("master pipeline (CLAMD_ENABLED):       %v\n", cfg.Clam.Enabled)
	switch {
	case !deployedKnown:
		fmt.Println("deployed lua state:                    unknown (cfm_clamav_config.lua missing)")
	default:
		fmt.Printf("deployed lua state (effective hook):   %v\n", deployed)
	}
	if cfg.Clam.Enabled && cfg.Clam.NginxHookEnabled && deployedKnown && !deployed {
		fmt.Println()
		fmt.Println("note: cfm.conf says hook should be on, but the deployed Lua file disagrees;")
		fmt.Println("      the daemon may not have reloaded since the last cfm.conf change.")
	}
	return 0
}

// runClamStatus prints a one-page operator overview without making
// the CLI talk to the daemon. Sources:
//   - cfm.conf for desired pipeline + hook state
//   - the deployed cfm_clamav_config.lua for what Angie actually sees
//   - clamd ping for reachability
//   - the infected/ dir + cfm.clam.log for recent infections (so admins
//     don't have to grep logs themselves)
func runClamStatus(client *clam.Client, cfg *cfgpkg.Config, cfgDir string) int {
	fmt.Println("== cfm clam status ==")
	fmt.Printf("config dir:   %s\n", cfgDir)

	fmt.Println()
	fmt.Println("-- pipeline --")
	fmt.Printf("CLAMD_ENABLED:            %v\n", cfg.Clam.Enabled)
	fmt.Printf("CLAMD_NGINX_HOOK_ENABLED: %v\n", cfg.Clam.NginxHookEnabled)
	if deployed, ok := readDeployedClamavHookEnabled(); ok {
		fmt.Printf("deployed lua hook:        %v\n", deployed)
	} else {
		fmt.Println("deployed lua hook:        unknown (cfm_clamav_config.lua missing)")
	}
	fmt.Printf("network:                  %s\n", cfg.Clam.Network)
	fmt.Printf("address:                  %s\n", cfg.Clam.Address)
	fmt.Printf("timeout:                  %s\n", cfg.Clam.Timeout)
	fmt.Printf("workers / queue:          %d / %d\n", cfg.Clam.MaxWorkers, cfg.Clam.QueueSize)
	fmt.Printf("pending dir:              %s\n", cfg.Clam.PendingDir)
	fmt.Printf("infected dir:             %s\n", cfg.Clam.InfectedDir)

	fmt.Println()
	fmt.Println("-- clamd reachability --")
	if !client.Enabled() {
		fmt.Println("ping: skipped (CLAMD_ENABLED=false)")
	} else if err := client.Ping(); err != nil {
		fmt.Printf("ping: FAIL (%v)\n", err)
	} else {
		fmt.Println("ping: OK")
		if v, err := client.Version(); err == nil {
			fmt.Printf("version: %s\n", v)
		}
	}

	fmt.Println()
	fmt.Println("-- spool dirs --")
	if pending, mode, owner, err := dirSummary(cfg.Clam.PendingDir); err == nil {
		fmt.Printf("%-12s %d file(s)  %s %s\n", "pending:", pending, mode, owner)
	} else {
		fmt.Printf("pending:     n/a (%v)\n", err)
	}
	if infected, mode, owner, err := dirSummary(cfg.Clam.InfectedDir); err == nil {
		fmt.Printf("%-12s %d file(s)  %s %s\n", "infected:", infected, mode, owner)
	} else {
		fmt.Printf("infected:    n/a (%v)\n", err)
	}

	fmt.Println()
	fmt.Println("-- recent infections (newest first) --")
	files := listInfected(cfg.Clam.InfectedDir, 10)
	if len(files) == 0 {
		fmt.Println("(none retained on disk)")
	} else {
		for _, e := range files {
			fmt.Printf("%s  %8d  %s\n",
				e.mtime.Format("2006-01-02 15:04:05"),
				e.size,
				filepath.Base(e.path))
		}
	}

	fmt.Println()
	fmt.Println("-- last INFECTED log lines --")
	logPath := strings.TrimSpace(cfg.Logging.CLAMFile)
	if logPath == "" {
		logPath = "/var/log/cfm/cfm.clam.log"
	}
	lines, err := tailGrepInfected(logPath, 5)
	switch {
	case err != nil:
		fmt.Printf("(log read error: %v)\n", err)
	case len(lines) == 0:
		fmt.Printf("(no INFECTED hits in %s)\n", logPath)
	default:
		for _, ln := range lines {
			fmt.Println(ln)
		}
	}
	return 0
}

// clamavHookSentinelRE matches the daemon-emitted header line
//
//	-- CFM_HOOK_ENABLED=true|false
//
// in /var/lib/cfm/lua/cfm_clamav_config.lua. The sentinel is the writer's
// contract with the CLI — independent of the Lua-table body that follows.
// Anchored at start-of-line, tolerant of surrounding whitespace; tab/space
// between the `--` and the key is allowed but no comment-text in between.
var clamavHookSentinelRE = regexp.MustCompile(`(?m)^--\s*CFM_HOOK_ENABLED=(true|false)\s*$`)

// readDeployedClamavHookEnabled parses the sentinel from the deployed lua
// config and returns (enabled, ok). ok=false means the file is missing,
// unreadable, or did not contain the sentinel — in which case the CLI
// surfaces "unknown" rather than guessing.
func readDeployedClamavHookEnabled() (bool, bool) {
	const luaPath = "/var/lib/cfm/lua/cfm_clamav_config.lua"
	b, err := os.ReadFile(luaPath) // #nosec G304 -- fixed daemon-managed path
	if err != nil {
		return false, false
	}
	m := clamavHookSentinelRE.FindSubmatch(b)
	if m == nil {
		return false, false
	}
	return string(m[1]) == "true", true
}

func dirSummary(dir string) (int, string, string, error) {
	if dir == "" {
		return 0, "", "", fmt.Errorf("dir not configured")
	}
	st, err := os.Stat(dir)
	if err != nil {
		return 0, "", "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, "", "", err
	}
	files := 0
	for _, e := range entries {
		if !e.IsDir() {
			files++
		}
	}
	return files, fmt.Sprintf("mode=%04o", st.Mode().Perm()), statOwnerString(st), nil
}

func statOwnerString(fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	uname := strconv.FormatUint(uint64(st.Uid), 10)
	gname := strconv.FormatUint(uint64(st.Gid), 10)
	if u, err := user.LookupId(uname); err == nil {
		uname = u.Username
	}
	if g, err := user.LookupGroupId(gname); err == nil {
		gname = g.Name
	}
	return fmt.Sprintf("owner=%s:%s", uname, gname)
}

type infectedEntry struct {
	path  string
	mtime time.Time
	size  int64
}

// listInfected returns the newest `max` files in dir, ordered by name
// descending (filenames begin with `upload_<unix-millis>_...`, so a
// lexicographic descending sort gives newest-first without an O(N) stat
// pass on the whole directory). Stat is done only on the top max
// entries, so the cost is bounded even when the dir holds many
// thousands of retained samples.
func listInfected(dir string, max int) []infectedEntry {
	if dir == "" || max <= 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) > max {
		names = names[:max]
	}
	out := make([]infectedEntry, 0, len(names))
	for _, name := range names {
		full := filepath.Join(dir, name)
		fi, err := os.Stat(full)
		if err != nil {
			continue
		}
		out = append(out, infectedEntry{path: full, mtime: fi.ModTime(), size: fi.Size()})
	}
	return out
}

// tailGrepInfected reads the clam log and returns up to max most-recent
// lines containing "result=INFECTED". Reads the whole file because clam
// logs are bounded; we don't need a fancy reverse reader for the sizes
// involved (logging rotates them).
//
// A missing log file is NOT an error: a fresh-install box that never
// had a clam event should look like "no events yet", not a read error.
func tailGrepInfected(path string, max int) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 -- caller-supplied admin path
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var matches []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "result=INFECTED") {
			matches = append(matches, line)
			if len(matches) > 1024 { // bounded ring
				matches = matches[len(matches)-1024:]
			}
		}
	}
	if err := sc.Err(); err != nil {
		return matches, err
	}
	if len(matches) > max {
		matches = matches[len(matches)-max:]
	}
	return matches, nil
}
