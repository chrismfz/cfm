// Package logscan is the shared, bounded reader for a log file's ROTATED history
// (logrotate siblings, gzip-transparent). It exists so the several on-demand log
// tools that need "reach back past the last rotation" — the edge access/error/host
// scanners (internal/edgelog) and the CFM-own-log tail (internal/cfmlog) — share ONE
// implementation of sibling discovery + whole-file streaming rather than each keeping
// its own copy that can drift (CLAUDE.md §5).
//
// Cost discipline (same as the live tails it complements): nothing retained, gz is
// STREAMED through gzip.Reader (never decompressed whole into memory), and the caller
// passes a shared line BUDGET plus a context deadline so an operator asking for
// rotated reach can never trigger an unbounded multi-GB read.
package logscan

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxLineToken is the scanner's per-line ceiling: long URIs/UAs/JSON payloads are
// tolerated without aborting the scan (a line beyond this is truncated by the
// scanner, not fatal).
const MaxLineToken = 4 * 1024 * 1024

// ErrBudgetExceeded is returned by ScanWhole when the file still had lines while the
// shared countdown was already at zero — i.e. the scan was cut short by the budget,
// not by a clean EOF. Callers translate it into a truncation flag (never a failure:
// the file itself is fine). Distinguishing budget-cut from EOF matters even on the
// LAST scanned file, so "there is more, older data" is never silently dropped.
var ErrBudgetExceeded = errors.New("scan budget exceeded")

// RotatedSiblings returns the rotated variants of `live` (same directory, name
// starting with "<base>." or "<base>-": .1, .1.gz, -20260810.gz, …), MOST RECENTLY
// MODIFIED FIRST, capped at maxFiles. The second return is the TOTAL number of
// siblings found, so a caller can detect that the file cap silently hid some
// (found > len(paths)). The live file itself, empty files, and non-regular entries
// are excluded. A directory it can't read yields nothing (best-effort — the live
// result still stands).
func RotatedSiblings(live string, maxFiles int) ([]string, int) {
	dir := filepath.Dir(live)
	base := filepath.Base(live)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0
	}
	type fe struct {
		path string
		mod  time.Time
	}
	var out []fe
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == base {
			continue
		}
		if !strings.HasPrefix(name, base+".") && !strings.HasPrefix(name, base+"-") {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			continue
		}
		out = append(out, fe{filepath.Join(dir, name), info.ModTime()})
	}
	total := len(out)
	sort.SliceStable(out, func(i, j int) bool { return out[i].mod.After(out[j].mod) })
	if maxFiles >= 0 && len(out) > maxFiles {
		out = out[:maxFiles]
	}
	paths := make([]string, len(out))
	for i, e := range out {
		paths[i] = e.path
	}
	return paths, total
}

// ScanWhole streams a (possibly gzipped) file from the START, feeding each line to
// fn and decrementing the shared *budget. gz is detected by the ".gz" suffix and
// streamed through gzip.Reader. Returns ErrBudgetExceeded when the budget hits zero
// with lines remaining (a truncation signal, not a failure), the context error on
// deadline, an open/gzip error for an unreadable/corrupt file, or the scanner error.
// fn returning false stops the scan early (nil error).
func ScanWhole(ctx context.Context, path string, budget *int, fn func(line string) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLineToken)
	for sc.Scan() {
		if budget != nil && *budget <= 0 {
			// Budget spent but the file has MORE lines: this distinction
			// (budget-cut vs clean EOF) must reach the caller so truncation can be
			// flagged even on the last scanned file.
			return ErrBudgetExceeded
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if budget != nil {
			*budget--
		}
		if !fn(sc.Text()) {
			return nil
		}
	}
	return sc.Err()
}
