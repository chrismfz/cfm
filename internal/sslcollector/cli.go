package sslcollector

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func RunCLI(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: cfm ssl <stats|scan|dump|refresh> [args] [--json]")
		os.Exit(2)
	}

	sub := args[0]
	fs := flag.NewFlagSet("ssl "+sub, flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
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

	switch sub {
	case "scan", "refresh":
		if err := col.Refresh(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "refresh error:", err)
			os.Exit(1)
		}
		st := col.Stats()
		if *asJSON {
			b, _ := json.MarshalIndent(st, "", "  ")
			fmt.Println(string(b))
			return
		}
		fmt.Printf("ssl: pairs=%d exact_hosts=%d wildcards=%d files=%d src=%v\n",
			st.UniquePairs, st.ExactHosts, st.WildcardZones, st.KnownFiles, st.BySource)

	case "stats":
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

		e, err := col.Dump(host)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dump:", err)
			os.Exit(1)
		}

		if *asJSON {
			b, _ := json.MarshalIndent(e, "", "  ")
			fmt.Println(string(b))
			return
		}

		fmt.Printf("host: %s\nsource: %s\ncert: %s\nkey: %s\nnot_after: %s\nfingerprint: %s\nnames: %v\n",
			host,
			e.Source,
			e.CertPath,
			e.KeyPath,
			e.NotAfter.Format(time.RFC3339),
			e.Fingerprint,
			e.Names,
		)

	default:
		fmt.Fprintln(os.Stderr, "unknown ssl subcommand:", sub)
		fmt.Fprintln(os.Stderr, "usage: cfm ssl <stats|scan|dump|refresh> [--json]")
		os.Exit(2)
	}
}
