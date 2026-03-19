package cli

import (
	"cfm/internal/clam"
	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	fmt.Println("  cfm clam ping")
	fmt.Println("  cfm clam version")
	fmt.Println("  cfm clam scan <file>")
	fmt.Println("  cfm clam scan <dir>")
	fmt.Println("  cfm clam scan --quiet-clean <file-or-dir>")
}
