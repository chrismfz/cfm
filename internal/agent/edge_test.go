package agent

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
)

func TestParseEdgeVersion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"openresty", "nginx version: openresty/1.25.3.2\n", "openresty/1.25.3.2"},
		{"angie", "Angie version: Angie/1.12.1\n", "Angie/1.12.1"},
		{"angie multiline", "Angie version: Angie/1.12.1\nbuilt with OpenSSL 3.0.7\n", "Angie/1.12.1"},
		{"plain nginx", "nginx version: nginx/1.24.0", "nginx/1.24.0"},
		{"no marker", "some unexpected output", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		if got := parseEdgeVersion(tc.in); got != tc.want {
			t.Errorf("%s: parseEdgeVersion(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestDetectEdge(t *testing.T) {
	origSystemctl := edgeSystemctlRunner
	origVersion := edgeVersionRunner
	origLookPath := edgeLookPath
	origStat := edgeStat
	defer func() {
		edgeSystemctlRunner = origSystemctl
		edgeVersionRunner = origVersion
		edgeLookPath = origLookPath
		edgeStat = origStat
	}()

	edgeLookPath = func(string) (string, error) { return "/usr/bin/systemctl", nil }
	edgeStat = func(name string) (fs.FileInfo, error) {
		if name == "/usr/local/openresty/nginx/sbin/nginx" || name == "/usr/sbin/angie" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}

	t.Run("openresty active", func(t *testing.T) {
		edgeSystemctlRunner = func(_ context.Context, args ...string) error {
			if args[len(args)-1] == "openresty" {
				return nil
			}
			return errors.New("inactive")
		}
		edgeVersionRunner = func(_ context.Context, bin string) (string, error) {
			return "nginx version: openresty/1.25.3.2\n", nil
		}
		name, ver, ok := detectEdge(context.Background())
		if !ok || name != "openresty" || ver != "openresty/1.25.3.2" {
			t.Fatalf("got name=%q ver=%q ok=%t", name, ver, ok)
		}
	})

	t.Run("angie active wins first", func(t *testing.T) {
		edgeSystemctlRunner = func(_ context.Context, args ...string) error { return nil }
		edgeVersionRunner = func(_ context.Context, bin string) (string, error) {
			return "Angie version: Angie/1.12.1\n", nil
		}
		name, ver, ok := detectEdge(context.Background())
		if !ok || name != "angie" || ver != "Angie/1.12.1" {
			t.Fatalf("got name=%q ver=%q ok=%t", name, ver, ok)
		}
	})

	t.Run("neither active is a real observation", func(t *testing.T) {
		edgeSystemctlRunner = func(_ context.Context, args ...string) error {
			return errors.New("inactive")
		}
		name, ver, ok := detectEdge(context.Background())
		if !ok || name != "" || ver != "" {
			t.Fatalf("got name=%q ver=%q ok=%t, want empty observation ok=true", name, ver, ok)
		}
	})

	t.Run("no systemctl means no observation", func(t *testing.T) {
		edgeLookPath = func(string) (string, error) { return "", errors.New("not found") }
		if _, _, ok := detectEdge(context.Background()); ok {
			t.Fatal("expected ok=false without systemctl")
		}
	})

	t.Run("version failure still reports edge name", func(t *testing.T) {
		edgeLookPath = func(string) (string, error) { return "/usr/bin/systemctl", nil }
		edgeSystemctlRunner = func(_ context.Context, args ...string) error {
			if args[len(args)-1] == "openresty" {
				return nil
			}
			return errors.New("inactive")
		}
		edgeVersionRunner = func(_ context.Context, bin string) (string, error) {
			return "", errors.New("exec failed")
		}
		name, ver, ok := detectEdge(context.Background())
		if !ok || name != "openresty" || ver != "" {
			t.Fatalf("got name=%q ver=%q ok=%t", name, ver, ok)
		}
	})
}
