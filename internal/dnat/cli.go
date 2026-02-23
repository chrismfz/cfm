package dnat

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// We do NOT force firewall.Backend interface changes.
// We only require that the concrete backend supports these DNAT methods.
type Capable interface {
	DNATStatus(family, table string) (bool, error)
	DNATShow(family, table string) (string, error)
	DNATOn(family, table string, httpPort, httpsPort int) error
	DNATOff(family, table string) error
}

func getenvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// RunCLI implements:
//   cfm dnat        -> report (ON/OFF + rules if ON + explanation)
//   cfm dnat on     -> enable
//   cfm dnat off    -> disable
//
// Returns an exit code (0 ok, 1 error, 2 usage).
func RunCLI(args []string, backend any) int {
	dnat, ok := backend.(Capable)
	if !ok || dnat == nil {
		fmt.Fprintln(os.Stderr, "dnat: backend does not support DNAT")
		return 1
	}

	fs := flag.NewFlagSet("dnat", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	family := fs.String("family", "inet", "nftables family (default: inet)")
	table := fs.String("table", "cfm_redirect", "nftables table (default: cfm_redirect)")

	defHTTP := getenvInt("HTTP_PORT", 9080)
	defHTTPS := getenvInt("HTTPS_PORT", 9043)
	httpPort := fs.Int("http-port", defHTTP, "DNAT target port for tcp/80 (env HTTP_PORT)")
	httpsPort := fs.Int("https-port", defHTTPS, "DNAT target port for tcp+udp/443 (env HTTPS_PORT)")

	sub := "" // default = report
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		help()
		return 2
	}

	switch sub {
	case "on":
		if err := dnat.DNATOn(*family, *table, *httpPort, *httpsPort); err != nil {
			fmt.Fprintln(os.Stderr, "dnat on failed:", err)
			return 1
		}
		fmt.Printf("DNAT: ON  (tcp/80->:%d, tcp+udp/443->:%d)\n", *httpPort, *httpsPort)
		return 0

	case "off":
		if err := dnat.DNATOff(*family, *table); err != nil {
			fmt.Fprintln(os.Stderr, "dnat off failed:", err)
			return 1
		}
		fmt.Println("DNAT: OFF")
		return 0

	case "":
		// report
	default:
		fmt.Fprintln(os.Stderr, "dnat: unknown subcommand:", sub)
		help()
		return 2
	}

	enabled, err := dnat.DNATStatus(*family, *table)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dnat status failed:", err)
		return 1
	}

	fmt.Printf("DNAT table: %s %s\n", *family, *table)
	if enabled {
		fmt.Printf("State: ON  (tcp/80->:%d, tcp+udp/443->:%d)\n\n", *httpPort, *httpsPort)
		fmt.Println("Current rules:")
		s, err := dnat.DNATShow(*family, *table)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dnat show failed:", err)
			return 1
		}
		fmt.Print(s)
		if !strings.HasSuffix(s, "\n") {
			fmt.Println()
		}
	} else {
		fmt.Println("State: OFF")
	}

	fmt.Println()
	fmt.Println("Explanation:")
	fmt.Println("  - ON  : creates a NAT prerouting table that DNATs tcp/80 and tcp+udp/443 to OpenResty ports.")
	fmt.Println("  - OFF : deletes that DNAT table, returning traffic handling to the normal path.")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  cfm dnat on   [--http-port 9080] [--https-port 9043]")
	fmt.Println("  cfm dnat off")
	return 0
}

func help() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  cfm dnat        (show ON/OFF + rules + explanation)")
	fmt.Fprintln(os.Stderr, "  cfm dnat on     (enable DNAT)")
	fmt.Fprintln(os.Stderr, "  cfm dnat off    (disable DNAT)")
}
