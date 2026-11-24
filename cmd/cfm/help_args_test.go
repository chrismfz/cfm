package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// `cfm daemon help` started a second daemon (the flag parse stopped at
// "help"); every help word prints the usage and stops, any positional is
// refused, and the flags still parse.
func TestParseDaemonArgs(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}, {"-c", "/etc/cfm", "help"}} {
		var out, errb bytes.Buffer
		_, rc, stop := parseDaemonArgs(args, &out, &errb)
		if !stop || rc != 0 || !strings.Contains(out.String(), "usage: cfm daemon") {
			t.Errorf("%q: stop=%v rc=%d out=%q err=%q", args, stop, rc, out.String(), errb.String())
		}
	}
	var out, errb bytes.Buffer
	if _, rc, stop := parseDaemonArgs([]string{"now"}, &out, &errb); !stop || rc != 2 {
		t.Errorf("positional: stop=%v rc=%d", stop, rc)
	}
	o, _, stop := parseDaemonArgs([]string{"--interval", "5s", "-c", "/x"}, &out, &errb)
	if stop || o.interval != 5*time.Second || o.cfgDir != "/x" {
		t.Errorf("flags: stop=%v opts=%+v", stop, o)
	}
}

// Every `cfm auth` leaf is flags-only: `cfm auth session purge help` purged
// and `cfm auth log purge help` deleted audit entries (cobra hands a leaf's
// positionals to RunE, which ignored them). A help word prints the help, any
// other positional is refused, and a required flag does not hide the help.
func TestAuthRefusePositionals(t *testing.T) {
	ran := 0
	// A fresh tree per run: cobra keeps a parsed --help set between Executes.
	exec := func(args ...string) (error, string) {
		leaf := &cobra.Command{Use: "purge", RunE: func(*cobra.Command, []string) error { ran++; return nil }}
		var user string
		del := &cobra.Command{Use: "delete", RunE: func(*cobra.Command, []string) error { ran++; return nil }}
		del.Flags().StringVar(&user, "username", "", "")
		_ = del.MarkFlagRequired("username")
		group := &cobra.Command{Use: "session"}
		group.AddCommand(leaf, del)
		root := &cobra.Command{Use: "auth", SilenceUsage: true, SilenceErrors: true}
		root.AddCommand(group)
		authRefusePositionals(root)
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(args)
		err := root.Execute()
		return err, out.String()
	}
	for _, h := range []string{"help", "-h", "--help"} {
		for _, name := range []string{"purge", "delete"} {
			err, out := exec("session", name, h)
			if (err != nil && err != errAuthHelpShown) || !strings.Contains(out, "Usage:") {
				t.Errorf("session %s %s: err=%v out=%q", name, h, err, out)
			}
		}
	}
	if err, _ := exec("session", "purge", "now"); err == nil || err == errAuthHelpShown {
		t.Errorf("a positional was accepted: %v", err)
	}
	if ran != 0 {
		t.Fatalf("a leaf ran %d time(s) on help words / positionals", ran)
	}
	if err, _ := exec("session", "purge"); err != nil || ran != 1 {
		t.Fatalf("plain purge: err=%v ran=%d", err, ran)
	}
}
