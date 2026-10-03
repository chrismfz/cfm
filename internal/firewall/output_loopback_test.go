package firewall

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

const outputChainWithDrops = `table inet cfm {
	chain output { # handle 3
		type filter hook output priority filter; policy accept;
		ct state established,related accept # handle 40
		ct state invalid drop # handle 41
		ct state new tcp dport @tcp_out_ports accept # handle 42
		ct state new udp dport @udp_out_ports accept # handle 43
		ct state new tcp dport 0-65535 drop # handle 44
		ct state new udp dport 0-65535 drop # handle 45
	}
}
`

// Missing (every node upgraded from a release without it): one insert, at the
// head, and nothing deleted.
func TestOutputLoopbackScript_InsertsWhenMissing(t *testing.T) {
	got := OutputLoopbackScript("inet", "cfm", outputChainWithDrops)
	if got != `insert rule inet cfm output oif "lo" accept` {
		t.Fatalf("got %q", got)
	}
}

// Present as nft prints it: nothing to write, so no apply stacks copies.
func TestOutputLoopbackScript_NothingWhenPresent(t *testing.T) {
	listing := strings.Replace(outputChainWithDrops,
		"\t\tct state established,related accept # handle 40",
		"\t\toif \"lo\" accept # handle 39\n\t\tct state established,related accept # handle 40", 1)
	if got := OutputLoopbackScript("inet", "cfm", listing); got != "" {
		t.Fatalf("want no script, got %q", got)
	}
}

// Copies left by an apply that read the chain wrong are removed, the top-most
// one kept.
func TestOutputLoopbackScript_RemovesDuplicates(t *testing.T) {
	listing := strings.Replace(outputChainWithDrops,
		"\t\tct state established,related accept # handle 40",
		"\t\toif \"lo\" accept # handle 39\n\t\toif \"lo\" accept # handle 46\n\t\tct state established,related accept # handle 40\n\t\toif \"lo\" accept # handle 47", 1)
	got := OutputLoopbackScript("inet", "cfm", listing)
	want := "delete rule inet cfm output handle 46\ndelete rule inet cfm output handle 47"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// A narrower rule that merely contains the accept (an operator's per-port
// workaround) is not the exemption: it is inserted at the head anyway, and the
// narrower rule left alone.
func TestOutputLoopbackScript_NarrowerRuleIsNotPresent(t *testing.T) {
	listing := strings.Replace(outputChainWithDrops,
		"\t\tct state established,related accept # handle 40",
		"\t\ttcp dport 3306 oif \"lo\" accept # handle 39\n\t\tct state established,related accept # handle 40", 1)
	got := OutputLoopbackScript("inet", "cfm", listing)
	if got != `insert rule inet cfm output oif "lo" accept` {
		t.Fatalf("got %q", got)
	}
}

// An exact copy below the head (here under `ct state invalid drop`, which then
// drops invalid loopback packets first) is replaced by one at the head.
func TestOutputLoopbackScript_CopyNotAtHeadIsMoved(t *testing.T) {
	listing := strings.Replace(outputChainWithDrops,
		"\t\tct state new tcp dport @tcp_out_ports accept # handle 42",
		"\t\toif \"lo\" accept # handle 46\n\t\tct state new tcp dport @tcp_out_ports accept # handle 42", 1)
	got := OutputLoopbackScript("inet", "cfm", listing)
	want := "insert rule inet cfm output oif \"lo\" accept\ndelete rule inet cfm output handle 46"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// An unread chain is skipped: planned from an empty listing it would read as
// "missing" and stack a copy on every apply whose read times out.
func TestEnsureOutputLoopback_SkipsUnreadChain(t *testing.T) {
	var logged []string
	EnsureOutputLoopback("inet", "cfm",
		func() (string, error) { return "", errors.New("timed out") },
		func(s string) error { t.Fatalf("wrote %q for an unread chain", s); return nil },
		func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) })
	if len(logged) != 1 || !strings.Contains(logged[0], "timed out") {
		t.Fatalf("want the read error logged once, got %q", logged)
	}
}

// A failed write is logged, not returned: the caller must go on and write the
// rest of the egress policy.
func TestEnsureOutputLoopback_WriteFailureIsLogged(t *testing.T) {
	var wrote string
	var logged []string
	EnsureOutputLoopback("inet", "cfm",
		func() (string, error) { return outputChainWithDrops, nil },
		func(s string) error { wrote = s; return errors.New("nft: busy") },
		func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) })
	if wrote != `insert rule inet cfm output oif "lo" accept` {
		t.Fatalf("wrote %q", wrote)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "nft: busy") {
		t.Fatalf("want the write error logged once, got %q", logged)
	}
}

// Present: nothing written, nothing logged.
func TestEnsureOutputLoopback_NoopWhenPresent(t *testing.T) {
	listing := strings.Replace(outputChainWithDrops,
		"\t\tct state established,related accept # handle 40",
		"\t\toif \"lo\" accept # handle 39\n\t\tct state established,related accept # handle 40", 1)
	EnsureOutputLoopback("inet", "cfm",
		func() (string, error) { return listing, nil },
		func(s string) error { t.Fatalf("wrote %q although the rule is present", s); return nil },
		func(f string, a ...any) { t.Fatalf("logged %q", fmt.Sprintf(f, a...)) })
}

// Both engines' ApplyPortsPolicy must ensure the loopback accept right after
// the output chain exists: before the port sets are (re)loaded, so a stricter
// TCP_OUT never takes effect without it, and before any step that can return
// early. The helper is tested above; this pins that it stays wired in there.
// It reads the AST, so a commented-out call does not count, and requires the
// call as a statement of the function body itself, not inside a branch.
func TestApplyPortsPolicy_EnsuresOutputLoopbackFirst(t *testing.T) {
	for _, f := range []string{"nft/ports.go", "nftlib/ports_nftlib.go"} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var body *ast.BlockStmt
		for _, d := range file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "ApplyPortsPolicy" && fd.Recv != nil {
				body = fd.Body
			}
		}
		if body == nil {
			t.Fatalf("%s: ApplyPortsPolicy not found", f)
		}
		chain, call, sets := token.NoPos, token.NoPos, token.NoPos
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BasicLit:
				if chain == token.NoPos && strings.Contains(n.Value, "type filter hook output priority 0") {
					chain = n.Pos()
				}
			case *ast.CompositeLit:
				if sets == token.NoPos && len(n.Elts) == 4 {
					if id, ok := n.Elts[2].(*ast.Ident); ok && id.Name == "setTCPOut" {
						sets = n.Pos()
					}
				}
			}
			return true
		})
		for _, st := range body.List {
			es, ok := st.(*ast.ExprStmt)
			if !ok {
				continue
			}
			ce, ok := es.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			if sel, ok := ce.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "EnsureOutputLoopback" {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "firewall" {
					call = ce.Pos()
				}
			}
		}
		if chain == token.NoPos || call == token.NoPos || sets == token.NoPos || !(chain < call && call < sets) {
			t.Errorf("%s: firewall.EnsureOutputLoopback must be a top-level statement of ApplyPortsPolicy, after the output chain is ensured and before the port sets are loaded (chain=%v call=%v sets=%v)", f, chain, call, sets)
		}
	}
}
