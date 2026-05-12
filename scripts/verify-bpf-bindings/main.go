// verify-bpf-bindings cross-checks the bpf2go-generated Go bindings
// in internal/lsm/cfmlsm_*_bpfel.go against the embedded ELF objects
// in internal/lsm/cfmlsm_*_bpfel.o. It exists because `go build`
// silently embeds whatever `.o` happens to be on disk; if a contributor
// edits cfmlsm.bpf.c, runs bpf2go to refresh the Go binding, but
// forgets to commit the regenerated .o, the resulting binary loads
// fine but fails at runtime with `field XYZ: unknown program xyz` the
// first time the loader walks the struct.
//
// This guard is wired into `make build` so that mismatched bytecode
// can never ship. Pure-Go: no clang dependency, runs in milliseconds.
//
// Exits 0 on success. On failure, prints every orphaned binding +
// .o file pair and a "run make bpf" hint, then exits 1.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

// bindingFile pairs a generated Go binding source with the ELF
// object it claims to describe. Both paths are repo-relative.
type bindingFile struct {
	goFile string
	elf    string
}

var bindings = []bindingFile{
	{
		goFile: "internal/lsm/cfmlsm_x86_bpfel.go",
		elf:    "internal/lsm/cfmlsm_x86_bpfel.o",
	},
	{
		goFile: "internal/lsm/cfmlsm_arm64_bpfel.go",
		elf:    "internal/lsm/cfmlsm_arm64_bpfel.o",
	},
}

func main() {
	repoRoot, err := findRepoRoot()
	if err != nil {
		fail("cannot locate repo root: %v", err)
	}

	failed := false
	for _, b := range bindings {
		goPath := filepath.Join(repoRoot, b.goFile)
		elfPath := filepath.Join(repoRoot, b.elf)

		bindingNames, err := parseEBPFTags(goPath)
		if err != nil {
			fail("parsing %s: %v", b.goFile, err)
		}
		elfNames, err := elfSymbols(elfPath)
		if err != nil {
			fail("loading %s: %v", b.elf, err)
		}

		missing := difference(bindingNames, elfNames)
		extra := difference(elfNames, bindingNames)

		if len(missing) == 0 && len(extra) == 0 {
			fmt.Printf("✓ %s ↔ %s (%d names match)\n", b.goFile, b.elf, len(bindingNames))
			continue
		}

		failed = true
		fmt.Fprintf(os.Stderr, "\n✗ %s and %s are out of sync:\n", b.goFile, b.elf)
		if len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "  Go bindings reference programs/maps NOT in the ELF (%d):\n", len(missing))
			for _, n := range missing {
				fmt.Fprintf(os.Stderr, "    - %s\n", n)
			}
		}
		if len(extra) > 0 {
			fmt.Fprintf(os.Stderr, "  ELF contains programs/maps NOT referenced by Go bindings (%d):\n", len(extra))
			for _, n := range extra {
				fmt.Fprintf(os.Stderr, "    - %s\n", n)
			}
		}
	}

	if failed {
		fmt.Fprintf(os.Stderr, "\n  Run `make bpf` to regenerate both the Go bindings and the .o files\n")
		fmt.Fprintf(os.Stderr, "  from internal/lsm/bpf/cfmlsm.bpf.c, then commit ALL of:\n")
		fmt.Fprintf(os.Stderr, "    - internal/lsm/cfmlsm_*_bpfel.go\n")
		fmt.Fprintf(os.Stderr, "    - internal/lsm/cfmlsm_*_bpfel.o\n")
		os.Exit(1)
	}
}

// parseEBPFTags walks a generated bpf2go Go file and collects every
// `ebpf:"name"` struct tag value. These name the programs and maps
// the bindings expect to find in the corresponding ELF.
func parseEBPFTags(path string) (map[string]struct{}, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	names := make(map[string]struct{})
	ast.Inspect(f, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}
		for _, field := range st.Fields.List {
			if field.Tag == nil {
				continue
			}
			tagValue := strings.Trim(field.Tag.Value, "`")
			tag := reflect.StructTag(tagValue).Get("ebpf")
			if tag == "" {
				continue
			}
			names[tag] = struct{}{}
		}
		return true
	})
	return names, nil
}

// elfSymbols loads a BPF ELF object via cilium/ebpf and returns the
// union of program, map, and global-variable names it declares. Using
// cilium/ebpf (rather than raw debug/elf) ensures we see the same
// names the runtime loader will look for.
func elfSymbols(path string) (map[string]struct{}, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}
	names := make(map[string]struct{})
	for n := range spec.Programs {
		names[n] = struct{}{}
	}
	for n := range spec.Maps {
		// bpf2go emits internal map names like ".rodata" / ".bss";
		// these never appear as ebpf-tagged Go fields, skip them so
		// they do not show up as spurious "extra" entries.
		if strings.HasPrefix(n, ".") {
			continue
		}
		names[n] = struct{}{}
	}
	for n := range spec.Variables {
		names[n] = struct{}{}
	}
	return names, nil
}

// difference returns elements of a not present in b, sorted.
func difference(a, b map[string]struct{}) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// findRepoRoot walks upward from the current working directory
// looking for go.mod. Lets the tool be invoked from any subdir.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found in any parent of %s", dir)
		}
		dir = parent
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "verify-bpf-bindings: "+format+"\n", args...)
	os.Exit(1)
}
