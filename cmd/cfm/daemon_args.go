package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"cfm/internal/clihelp"
)

type daemonOpts struct {
	interval time.Duration
	cfgDir   string
}

const daemonUsage = `usage: cfm daemon [--interval 20s] [-c CONFIG_DIR]
  Run the CFM daemon in the foreground (systemd runs it as cfm.service).`

// parseDaemonArgs reads `cfm daemon`'s flags. A help word prints the usage and
// any positional argument is refused (done=true): the flag package stopped at
// a positional "help", so `cfm daemon help` started a second daemon.
func parseDaemonArgs(args []string, stdout, stderr io.Writer) (daemonOpts, int, bool) {
	var o daemonOpts
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.DurationVar(&o.interval, "interval", 20*time.Second, "tick interval")
	fs.StringVar(&o.cfgDir, "c", "", "config directory (contains cfm.allow / cfm.deny)")
	err := clihelp.Parse(fs, args)
	switch {
	case err == nil:
		return o, 0, false
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprintln(stdout, daemonUsage)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		// (fs.Output was io.Discard while parsing, so the flag package's own
		// usage print went nowhere.)
		return o, 0, true
	default:
		fmt.Fprintf(stderr, "daemon: %v\n%s\n", err, daemonUsage)
		return o, 2, true
	}
}
