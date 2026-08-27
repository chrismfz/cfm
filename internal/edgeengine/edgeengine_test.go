package edgeengine

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
)

func TestParseVersionToken(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"openresty", "nginx version: openresty/1.31.1.1\n", "openresty/1.31.1.1"},
		{"angie", "Angie version: Angie/1.12.1\n", "Angie/1.12.1"},
		{"angie multiline", "Angie version: Angie/1.12.1\nbuilt with OpenSSL 3.0.7\n", "Angie/1.12.1"},
		{"plain nginx", "nginx version: nginx/1.24.0", "nginx/1.24.0"},
		{"no marker", "some unexpected output", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		if got := ParseVersionToken(tc.in); got != tc.want {
			t.Errorf("%s: ParseVersionToken(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestDetect(t *testing.T) {
	origSystemctl, origVersion, origLookPath, origStat := SystemctlRunner, VersionRunner, LookPath, Stat
	defer func() {
		SystemctlRunner, VersionRunner, LookPath, Stat = origSystemctl, origVersion, origLookPath, origStat
	}()

	LookPath = func(string) (string, error) { return "/usr/bin/systemctl", nil }
	Stat = func(name string) (fs.FileInfo, error) {
		if name == "/usr/local/openresty/nginx/sbin/nginx" || name == "/usr/sbin/angie" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}

	t.Run("openresty active", func(t *testing.T) {
		SystemctlRunner = func(_ context.Context, args ...string) error {
			if args[len(args)-1] == "openresty" {
				return nil
			}
			return errors.New("inactive")
		}
		VersionRunner = func(_ context.Context, _ string) (string, error) {
			return "nginx version: openresty/1.31.1.1\n", nil
		}
		name, ver, ok := Detect(context.Background())
		if !ok || name != "openresty" || ver != "openresty/1.31.1.1" {
			t.Fatalf("got name=%q ver=%q ok=%t", name, ver, ok)
		}
	})

	t.Run("angie active wins first", func(t *testing.T) {
		SystemctlRunner = func(_ context.Context, _ ...string) error { return nil }
		VersionRunner = func(_ context.Context, _ string) (string, error) {
			return "Angie version: Angie/1.12.1\n", nil
		}
		name, ver, ok := Detect(context.Background())
		if !ok || name != "angie" || ver != "Angie/1.12.1" {
			t.Fatalf("got name=%q ver=%q ok=%t", name, ver, ok)
		}
	})

	t.Run("neither active is a real observation", func(t *testing.T) {
		SystemctlRunner = func(_ context.Context, _ ...string) error { return errors.New("inactive") }
		name, _, ok := Detect(context.Background())
		if !ok || name != "" {
			t.Fatalf("neither-active: got name=%q ok=%t, want name=\"\" ok=true", name, ok)
		}
	})

	t.Run("no systemctl is not-ok", func(t *testing.T) {
		LookPath = func(string) (string, error) { return "", os.ErrNotExist }
		if _, _, ok := Detect(context.Background()); ok {
			t.Fatal("no systemctl should report ok=false")
		}
	})
}
