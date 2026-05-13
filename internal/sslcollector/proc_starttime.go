package sslcollector

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// processStartTime returns the wall-clock time at which `pid` was
// created, derived from /proc/<pid>/stat field 22 (starttime, in clock
// ticks since boot) plus /proc/stat:btime (boot time in unix seconds).
// Timezone-free: avoids systemctl's `ActiveEnterTimestamp` parse which
// silently fails on named zones like EEST/MSK that aren't in Go's
// default tz abbreviation table.
func processStartTime(pid int) (time.Time, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return time.Time{}, err
	}
	// The `comm` field (2) is wrapped in parens and may itself contain
	// whitespace and parens, so we cannot just split on spaces. Find
	// the LAST ')' and split the remainder.
	s := string(data)
	rp := strings.LastIndexByte(s, ')')
	if rp < 0 || rp+1 >= len(s) {
		return time.Time{}, fmt.Errorf("malformed /proc/%d/stat: no closing paren", pid)
	}
	fields := strings.Fields(s[rp+1:])
	// After dropping fields 1 (pid) + 2 (comm), what remains starts at
	// field 3 (state). starttime is field 22 in the man-page numbering,
	// i.e. index (22-3)=19 in the post-paren slice.
	const starttimeIdx = 19
	if len(fields) <= starttimeIdx {
		return time.Time{}, fmt.Errorf("malformed /proc/%d/stat: only %d fields", pid, len(fields))
	}
	ticks, err := strconv.ParseUint(fields[starttimeIdx], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse starttime: %w", err)
	}
	boot, err := bootTime()
	if err != nil {
		return time.Time{}, err
	}
	// Linux clock-tick rate. _SC_CLK_TCK is 100 on every modern distro
	// kernel build CFM supports; hard-coding avoids a cgo dependency.
	const clkTck = 100
	secs := ticks / clkTck
	nsRemainder := (ticks % clkTck) * (uint64(time.Second) / clkTck)
	return boot.Add(time.Duration(secs)*time.Second + time.Duration(nsRemainder)), nil
}

var (
	bootTimeOnce   sync.Once
	bootTimeCached time.Time
	bootTimeErr    error
)

// bootTime returns the wall-clock instant the kernel finished booting,
// from /proc/stat:btime (unix seconds). Cached for the lifetime of the
// process — boot time never changes for a running kernel.
func bootTime() (time.Time, error) {
	bootTimeOnce.Do(func() {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			bootTimeErr = err
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "btime ") {
				continue
			}
			sec, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
			if err != nil {
				bootTimeErr = fmt.Errorf("parse btime: %w", err)
				return
			}
			bootTimeCached = time.Unix(sec, 0)
			return
		}
		bootTimeErr = fmt.Errorf("btime not found in /proc/stat")
	})
	return bootTimeCached, bootTimeErr
}
