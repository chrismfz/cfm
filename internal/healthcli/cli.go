package healthcli

import (
	"cfm/internal/clihttp"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

type snapshotResponse struct {
	SchemaVersion string       `json:"schema_version"`
	NodeID        string       `json:"node_id"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Snapshot      healthSample `json:"snapshot"`
}

type healthSample struct {
	NodeID      string    `json:"node_id"`
	Hostname    string    `json:"hostname"`
	CollectedAt time.Time `json:"collected_at"`
	Load1       float64   `json:"load1"`
	RamUsedPct  float64   `json:"ram_used_pct"`
	DiskRootPct float64   `json:"disk_root_pct"`
	DiskTmpPct  float64   `json:"disk_tmp_pct"`
	TempMaxC    float64   `json:"temp_max_c"`
	RxMbps      float64   `json:"rx_mbps"`
	TxMbps      float64   `json:"tx_mbps"`
}

func Run(baseURL string, args []string) error {
	if len(args) == 0 {
		return runSummary(baseURL)
	}

	switch args[0] {
	case "json":
		return runJSON(baseURL)
	case "live":
		if !isTTY() {
			return runSummary(baseURL)
		}
		return runLive(baseURL, args[1:])
	case "watch":
		return runWatch(baseURL, args[1:])
	case "help", "-h", "--help":
		printHelp()
		return nil
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func isTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  cfm health             # summary")
	fmt.Println("  cfm health json        # machine-readable snapshot")
	fmt.Println("  cfm health live        # live dashboard (TTY), auto-fallback to summary")
	fmt.Println("  cfm health watch [N]   # periodic text refresh every N seconds (default 5)")
}

func runSummary(baseURL string) error {
	snap, err := fetchSnapshot(baseURL)
	if err != nil {
		return err
	}
	printSummary(snap)
	return nil
}

func runJSON(baseURL string) error {
	res, err := getJSON(baseURL + "/api/v1/health/snapshot")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("health snapshot failed: status=%d body=%s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload any
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(b))
	return nil
}

func runLive(baseURL string, args []string) error {
	interval := parseInterval(args, 2*time.Second)
	for tick := 0; ; tick++ {
		snap, err := fetchSnapshot(baseURL)
		fmt.Print("\033[H\033[2J")
		fmt.Printf("cfm health live  tick=%d  interval=%s  %s\n\n", tick, interval, time.Now().Format("15:04:05"))
		if err != nil {
			fmt.Printf("error: %v\n", err)
		} else {
			printSummary(snap)
		}
		time.Sleep(interval)
	}
}

func runWatch(baseURL string, args []string) error {
	interval := parseInterval(args, 5*time.Second)
	fmt.Printf("[cfm health watch] interval=%s\n", interval)
	for {
		snap, err := fetchSnapshot(baseURL)
		if err != nil {
			fmt.Printf("[%s] error: %v\n", time.Now().Format(time.RFC3339), err)
		} else {
			printOneLine(snap)
		}
		time.Sleep(interval)
	}
}

func parseInterval(args []string, def time.Duration) time.Duration {
	if len(args) == 0 {
		return def
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Second
}

func printSummary(s snapshotResponse) {
	host := s.Snapshot.Hostname
	if host == "" {
		host = s.NodeID
	}
	fmt.Printf("Node: %s\n", host)
	fmt.Printf("Collected: %s\n", s.Snapshot.CollectedAt.Local().Format(time.RFC3339))
	fmt.Printf("Load1: %.2f\n", s.Snapshot.Load1)
	fmt.Printf("RAM: %.1f%%\n", s.Snapshot.RamUsedPct)
	fmt.Printf("Disk: / %.1f%%   /tmp %.1f%%\n", s.Snapshot.DiskRootPct, s.Snapshot.DiskTmpPct)
	fmt.Printf("Temp max: %.1f°C\n", s.Snapshot.TempMaxC)
	fmt.Printf("Net: RX %.2f Mbps   TX %.2f Mbps\n", s.Snapshot.RxMbps, s.Snapshot.TxMbps)
}

func printOneLine(s snapshotResponse) {
	host := s.Snapshot.Hostname
	if host == "" {
		host = s.NodeID
	}
	fmt.Printf("[%s] host=%s load=%.2f ram=%.1f%% disk(/)=%.1f%% temp=%.1fC rx=%.2f tx=%.2f\n",
		time.Now().Format("15:04:05"),
		host,
		s.Snapshot.Load1,
		s.Snapshot.RamUsedPct,
		s.Snapshot.DiskRootPct,
		s.Snapshot.TempMaxC,
		s.Snapshot.RxMbps,
		s.Snapshot.TxMbps,
	)
}

func fetchSnapshot(baseURL string) (snapshotResponse, error) {
	var out snapshotResponse
	res, err := getJSON(baseURL + "/api/v1/health/snapshot")
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return out, fmt.Errorf("health snapshot failed: status=%d body=%s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func getJSON(u string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return clihttp.Do(req)
}
