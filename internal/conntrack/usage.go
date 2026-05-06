package conntrack

import (
	"os"
	"strconv"
	"strings"
)

const (
	countPath = "/proc/sys/net/netfilter/nf_conntrack_count"
	maxPath   = "/proc/sys/net/netfilter/nf_conntrack_max"
)

// Usage describes current kernel conntrack table utilization.
type Usage struct {
	Count    int
	Max      int
	UsagePct float64
}

// ReadUsage reads the current Linux conntrack count and configured maximum.
func ReadUsage() (Usage, error) {
	count, err := readIntFile(countPath)
	if err != nil {
		return Usage{}, err
	}
	max, err := readIntFile(maxPath)
	if err != nil {
		return Usage{}, err
	}
	usage := Usage{Count: count, Max: max}
	if max > 0 {
		usage.UsagePct = float64(count) * 100 / float64(max)
	}
	return usage, nil
}

func readIntFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	return strconv.Atoi(s)
}
