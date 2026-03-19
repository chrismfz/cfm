package sslcollector

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

)

func RunCLI(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: cfm ssl <stats|scan|dump|refresh> [args] [--json]")
		os.Exit(2)
	}

	sub := args[0]
	fs := flag.NewFlagSet("ssl "+sub, flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	sockPath := fs.String("sock", "/var/run/sslcollector.sock", "sslcollector unix socket path")
	token := fs.String("token", "", "sslcollector socket token")
	noDaemonRefresh := fs.Bool("no-daemon-refresh", false, "do not trigger daemon refresh before command")
	cacheDir := fs.String("cache-dir", "/var/lib/cfm/sslcollector", "cache dir (metadata only)")
	_ = fs.Parse(args[1:])

	col := New(Config{
		Enabled:        true,
		CacheDir:       *cacheDir,
		StatEvery:      60 * time.Second,
		DiscoveryEvery: 6 * time.Hour,
		NegativeTTL:    30 * time.Second,
		MaxCertCache:   20000,
	})

	ctx := context.Background()


	type dumpView struct {
		Found       bool     `json:"found"`
		Source      Source   `json:"source,omitempty"`
		CertPath    string   `json:"cert,omitempty"`
		KeyPath     string   `json:"key,omitempty"`
		NotAfter    string   `json:"not_after,omitempty"`
		Fingerprint string   `json:"fingerprint,omitempty"`
		Names       []string `json:"names,omitempty"`
		Error       string   `json:"error,omitempty"`
	}

	type dualDump struct {
		Host   string   `json:"host"`
		Disk   dumpView `json:"disk"`
		Daemon dumpView `json:"daemon"`
		Status string   `json:"status"`
	}

	newSockClient := func() *http.Client {
		tr := &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", *sockPath)
			},
		}
		return &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		}
	}

	sockDo := func(method, path string) (*http.Response, error) {
		cli := newSockClient()
		req, err := http.NewRequest(method, "http://unix"+path, nil)
		if err != nil {
			return nil, err
		}
		req.Host = "localhost"
		if *token != "" {
			req.Header.Set("X-SSLCollector-Token", *token)
		}
		return cli.Do(req)
	}

	daemonRefresh := func() error {
		resp, err := sockDo(http.MethodPost, "/refresh")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return fmt.Errorf("daemon refresh: status=%d body=%q", resp.StatusCode, strings.TrimSpace(string(b)))
		}
		return nil
	}

	daemonDump := func(host string) (*Entry, error) {
		q := url.Values{}
		q.Set("host", host)
		resp, err := sockDo(http.MethodGet, "/dump?"+q.Encode())
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, errors.New("not found")
		}
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return nil, fmt.Errorf("daemon dump: status=%d body=%q", resp.StatusCode, strings.TrimSpace(string(b)))
		}
		var e Entry
		if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
			return nil, err
		}
		return &e, nil
	}

	bestEffortDaemonRefresh := func() {
		if *noDaemonRefresh {
			return
		}
		if err := daemonRefresh(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: daemon refresh skipped: %v\n", err)
		}
	}



	switch sub {
	case "scan", "refresh":
		bestEffortDaemonRefresh()
		if err := col.Refresh(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "refresh error:", err)
			os.Exit(1)
		}
		st := col.Stats()
		if *asJSON {
			out := map[string]any{
				"disk": st,
			}
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
			return
		}

		if sub == "refresh" {
			fmt.Println("daemon: refresh attempted (best-effort)")
		}


		fmt.Printf("ssl: pairs=%d exact_hosts=%d wildcards=%d files=%d src=%v\n",
			st.UniquePairs, st.ExactHosts, st.WildcardZones, st.KnownFiles, st.BySource)

	case "stats":
		bestEffortDaemonRefresh()


		bestEffortDaemonRefresh()
		_ = col.Refresh(ctx)
		st := col.Stats()
		if *asJSON {
			b, _ := json.MarshalIndent(st, "", "  ")
			fmt.Println(string(b))
			return
		}
		fmt.Printf("pairs=%d exact_hosts=%d wildcards=%d files=%d cached_tls=%d src=%v\n",
			st.UniquePairs, st.ExactHosts, st.WildcardZones, st.KnownFiles, st.CachedTLS, st.BySource)

	case "dump":
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "usage: cfm ssl dump <host> [--json]")
			os.Exit(2)
		}
		_ = col.Refresh(ctx)
		host := fs.Arg(0)

		out := dualDump{Host: host}

		if e, err := col.Dump(host); err == nil && e != nil {
			out.Disk = dumpView{
				Found:       true,
				Source:      e.Source,
				CertPath:    e.CertPath,
				KeyPath:     e.KeyPath,
				NotAfter:    e.NotAfter.Format(time.RFC3339),
				Fingerprint: e.Fingerprint,
				Names:       e.Names,
			}
		} else if err != nil {
			out.Disk.Error = err.Error()
		}

		if e, err := daemonDump(host); err == nil && e != nil {
			out.Daemon = dumpView{
				Found:       true,
				Source:      e.Source,
				CertPath:    e.CertPath,
				KeyPath:     e.KeyPath,
				NotAfter:    e.NotAfter.Format(time.RFC3339),
				Fingerprint: e.Fingerprint,
				Names:       e.Names,
			}
		} else if err != nil {
			out.Daemon.Error = err.Error()
		}

		switch {
		case out.Disk.Found && out.Daemon.Found:
			if out.Disk.Fingerprint == out.Daemon.Fingerprint &&
				out.Disk.CertPath == out.Daemon.CertPath &&
				out.Disk.KeyPath == out.Daemon.KeyPath {
				out.Status = "in-sync"
			} else {
				out.Status = "mismatch"
			}
		case out.Disk.Found && !out.Daemon.Found:
			out.Status = "disk-only"
		case !out.Disk.Found && out.Daemon.Found:
			out.Status = "daemon-only"
		default:
			out.Status = "not-found"
		}

		if *asJSON {
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
			return
		}


		fmt.Printf("host: %s\nstatus: %s\n\n", host, out.Status)

		fmt.Println("disk:")
		if out.Disk.Found {
			fmt.Printf("  found: yes\n  source: %s\n  cert: %s\n  key: %s\n  not_after: %s\n  fingerprint: %s\n  names: %v\n",
				out.Disk.Source, out.Disk.CertPath, out.Disk.KeyPath, out.Disk.NotAfter, out.Disk.Fingerprint, out.Disk.Names)
		} else {
			fmt.Printf("  found: no\n")
			if out.Disk.Error != "" {
				fmt.Printf("  error: %s\n", out.Disk.Error)
			}
		}

		fmt.Println("\ndaemon:")
		if out.Daemon.Found {
			fmt.Printf("  found: yes\n  source: %s\n  cert: %s\n  key: %s\n  not_after: %s\n  fingerprint: %s\n  names: %v\n",
				out.Daemon.Source, out.Daemon.CertPath, out.Daemon.KeyPath, out.Daemon.NotAfter, out.Daemon.Fingerprint, out.Daemon.Names)
		} else {
			fmt.Printf("  found: no\n")
			if out.Daemon.Error != "" {
				fmt.Printf("  error: %s\n", out.Daemon.Error)
			}
		}


	default:
		fmt.Fprintln(os.Stderr, "unknown ssl subcommand:", sub)
		fmt.Fprintln(os.Stderr, "usage: cfm ssl <stats|scan|dump|refresh> [--json]")
		os.Exit(2)
	}
}
