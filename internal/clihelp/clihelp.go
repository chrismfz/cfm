// Package clihelp is the ONE check for "does this cfm command line ask for
// usage?", shared by every `cfm` command and subcommand (internal/cli,
// internal/webdetector, cmd/cfm, kernsec, lsm, …).
//
// A help word (-h, --help, help) must print the command's usage and do
// nothing else. Before it, several commands never read their arguments, so
// `cfm reset --help` emptied table inet cfm, `cfm disable --help` deleted it,
// `cfm flush --help` freed every TTL ban, and `cfm webtop challenge add
// --help` armed a challenge for host "--help". A flag-package subcommand
// stopped parsing at a positional "help" and ran with its defaults
// (`cfm kernsec apply help`).
package clihelp

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// IsHelpArg reports whether one argument asks for usage.
func IsHelpArg(s string) bool {
	switch s {
	case "-h", "--help", "help":
		return true
	}
	return false
}

// First reports whether a command's first argument asks for usage.
func First(args []string) bool {
	return len(args) > 0 && IsHelpArg(args[0])
}

// Any reports whether any argument before a "--" asks for usage. Use it only
// for a command whose arguments are flags and fixed words: a free-text value
// ("-r help") would read as a help request.
func Any(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if IsHelpArg(a) {
			return true
		}
	}
	return false
}

// Sub reports whether a command line under a dispatcher asks for usage: -h
// or --help anywhere before a "--", or a bare "help" anywhere except as the
// value of the flag right before it (`--reason help` stays a reason). So
// `bots block --help`, `webtop challenge add example.com --help` (it armed
// the challenge) and `challenge-access remove 5 help` (it removed entry 5)
// all ask for usage.
func Sub(args []string) bool {
	for i, a := range args {
		if a == "--" {
			return false
		}
		if a == "-h" || a == "--help" {
			return true
		}
		if a == "help" && (i == 0 || !strings.HasPrefix(args[i-1], "-") || strings.Contains(args[i-1], "=")) {
			return true
		}
	}
	return false
}

// NoArgs guards a command that takes no argument at all. On a help word it
// prints usage to stdout and returns (0, true); on any other argument it
// prints an error and the usage to stderr and returns (2, true): an
// unexpected argument never runs the command. With no argument it returns
// (0, false) and the caller goes on.
//
//	if rc, done := clihelp.NoArgs("reset", resetUsage, args); done {
//		return rc
//	}
func NoArgs(name, usage string, args []string) (int, bool) {
	return NoArgsTo(os.Stdout, os.Stderr, name, usage, args)
}

// NoArgsTo is NoArgs with explicit writers.
func NoArgsTo(stdout, stderr io.Writer, name, usage string, args []string) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	if First(args) {
		fmt.Fprintln(stdout, usage)
		return 0, true
	}
	fmt.Fprintf(stderr, "%s: unexpected argument %q\n%s\n", name, args[0], usage)
	return 2, true
}

// ErrUnexpectedArgs is wrapped by Parse for a positional argument a
// flags-only command does not take.
var ErrUnexpectedArgs = errors.New("unexpected arguments")

// Parse parses a flags-only command's arguments and refuses what the flag
// package leaves over: it stops at the first non-flag, so `apply help` read
// as `apply` with every default. A help word anywhere is answered as fs.Parse
// answers -h: the flag set's usage is printed (to fs.Output()) and
// flag.ErrHelp returned. Any other positional is an error wrapping
// ErrUnexpectedArgs.
func Parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return nil
	}
	if Any(rest) {
		// What fs.Parse does for -h: print the usage, then ErrHelp.
		if fs.Usage != nil {
			fs.Usage()
		} else {
			fmt.Fprintf(fs.Output(), "Usage of %s:\n", fs.Name())
			fs.PrintDefaults()
		}
		return flag.ErrHelp
	}
	return fmt.Errorf("%w: %s", ErrUnexpectedArgs, strings.Join(rest, " "))
}
