package locate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/firewall"
)

// nftlibBE answers ListTableJSON/ListSetJSON in nftlib's own JSON shapes and
// counts the reads; any other Backend method panics.
type nftlibBE struct {
	firewall.Backend
	reads map[string]int
}

func (b *nftlibBE) ListTableJSON(string, string) ([]byte, error) {
	b.reads["table"]++
	return []byte(`{"family":"inet","table":"cfm","sets":["block_v4","block_ext_v4_nets_MYBLOCK","syn_v4"],` +
		`"set_info":[{"name":"block_v4","type":"ipv4_addr"},{"name":"block_ext_v4_nets_MYBLOCK","type":"ipv4_addr"}]}`), nil
}

func (b *nftlibBE) ListSetJSON(_, _, set string) ([]byte, error) {
	b.reads[set]++
	elems := map[string]string{
		"block_v4":                  `["198.51.100.9"]`,
		"block_ext_v4_nets_MYBLOCK": `["192.0.2.0/24"]`,
	}[set]
	return []byte(`{"family":"inet","table":"cfm","set":"` + set + `","elements":` + elems + `}`), nil
}

func sources(locs []Location) string {
	var s []string
	for _, l := range locs {
		s = append(s, l.Source+":"+l.List+":"+l.Match)
	}
	return strings.Join(s, " ")
}

// Many queries read each source once, and each gets its own answer — the
// nft one from an nftlib backend too, where Find used to find nothing.
func TestFindMany_ReadsEachSourceOnce(t *testing.T) {
	cfg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg, "cfm.deny"), []byte("8.8.0.0/16 # bulk\n1.1.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	etc, data := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(etc, "csf.deny"), []byte("1.1.1.0/24 # csf net\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	be := &nftlibBE{reads: map[string]int{}}
	args := []string{"198.51.100.9", "192.0.2.7", "8.8.4.4", "1.1.1.1", "9.9.9.9", "198.51.100.9", "1.1.0.0/16"}
	res, err := FindMany(context.Background(), args, Options{BE: be, ConfigDir: cfg, CSFDir: etc, CSFDataDir: data})
	if err != nil {
		t.Fatal(err)
	}
	for arg, want := range map[string]string{
		"198.51.100.9": "nft:block_v4:198.51.100.9",
		"192.0.2.7":    "nft:block_ext_v4_nets_MYBLOCK:192.0.2.0/24",
		"8.8.4.4":      "cfm.deny:cfm.deny:8.8.0.0/16",
		"1.1.1.1":      "cfm.deny:cfm.deny:1.1.1.1 csf:csf.deny:1.1.1.0/24",
		"9.9.9.9":      "",
		"1.1.0.0/16":   "cfm.deny:cfm.deny:1.1.1.1 csf:csf.deny:1.1.1.0/24",
	} {
		r := res[arg]
		if r == nil {
			t.Errorf("%s: no result", arg)
			continue
		}
		if got := sources(r.Locations); got != want {
			t.Errorf("%s: found %q, want %q", arg, got, want)
		}
		if r.Query != arg {
			t.Errorf("%s: Query = %q", arg, r.Query)
		}
	}
	if len(res) != 6 {
		t.Errorf("%d results for 6 distinct arguments", len(res))
	}
	if be.reads["table"] != 1 || be.reads["block_v4"] != 1 || be.reads["block_ext_v4_nets_MYBLOCK"] != 1 {
		t.Errorf("nft reads = %v, want each once", be.reads)
	}

	if _, err := FindMany(context.Background(), []string{"1.1.1.1", "nope"}, Options{}); err == nil {
		t.Error("an unparsable argument should fail the call")
	}
	one, err := Find(context.Background(), " 1.1.1.1 ", Options{ConfigDir: cfg})
	if err != nil || one.Query != "1.1.1.1" || sources(one.Locations) != "cfm.deny:cfm.deny:1.1.1.1" || one.Skipped["nft"] != "no firewall backend" {
		t.Errorf("Find = %+v, %v", one, err)
	}
}
