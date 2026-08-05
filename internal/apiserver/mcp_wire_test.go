package apiserver

import "testing"

func TestMCPTokenUsable(t *testing.T) {
	cases := []struct {
		name string
		tok  string
		want bool
	}{
		{"empty", "", false},
		{"whitespace", "       ", false},
		{"too short", "short-token", false},
		{"exactly min", "abcdefghijklmnopqrstuvwx", true}, // 24 chars
		{"strong", "cfm-mcp-3f9a2b7c8d1e4f6a9b0c2d5e", true},
		{"padded but short", "  abc  ", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mcpTokenUsable(c.tok); got != c.want {
				t.Errorf("mcpTokenUsable(%q) = %v, want %v", c.tok, got, c.want)
			}
		})
	}
}
