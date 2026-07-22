package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"cfm/internal/phpinventory"
)

// RunPHPInventory implements `cfm php-inventory` — read-only discovery of the
// host's PHP builds and whether the Snuffleupagus / Imunify PHP extensions are
// loaded (P0 of the PHP-runtime-defense roadmap). Touches no config.
func RunPHPInventory(args []string) int {
	fs := flag.NewFlagSet("php-inventory", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "emit the inventory as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rep := phpinventory.DefaultScanner().Scan()

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(os.Stderr, "php-inventory: encode:", err)
			return 1
		}
		return 0
	}

	fmt.Println("== cfm php-inventory ==")
	if len(rep.Builds) == 0 {
		fmt.Println("No PHP builds found in the known locations (cPanel EA4, alt-php, DirectAdmin, LiteSpeed lsphp, system).")
		return 0
	}
	fmt.Printf("%d PHP build(s) found\n\n", len(rep.Builds))

	bool2 := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	fmt.Printf("%-12s %-9s %-4s %-4s %-10s %-8s %s\n", "FLAVOR", "VERSION", "ZTS", "SP", "PROACTIVE", "MODULES", "PATH")
	for _, b := range rep.Builds {
		ver := b.Version
		if ver == "" {
			ver = "?"
		}
		fmt.Printf("%-12s %-9s %-4s %-4s %-10s %-8d %s\n",
			b.Flavor, ver, bool2(b.ZTS), bool2(b.HasSP), bool2(b.HasProactive), b.ModuleCount, b.Path)
	}

	if len(rep.Warnings) > 0 {
		fmt.Println()
		for _, w := range rep.Warnings {
			fmt.Printf("⚠  %s\n", w)
		}
	}
	return 0
}
