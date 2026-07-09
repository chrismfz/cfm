package edge

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbeTSVLog(t *testing.T) {
	dir := t.TempDir()
	logf := filepath.Join(dir, "access_cfm_tsv.log")
	if err := os.WriteFile(logf, []byte("line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Quoted + inline-comment value, as it appears in detectors.conf.
	got := ProbeTSVLog(`"` + logf + `"  ; the tsv access log`)
	if !got.Configured || !got.Exists || !got.IsFile {
		t.Fatalf("expected configured/exists/file, got %+v", got)
	}
	if got.Path != logf {
		t.Errorf("Path = %q, want cleaned %q", got.Path, logf)
	}
	if got.ModAgeSec < 0 {
		t.Errorf("ModAgeSec = %d, want >= 0", got.ModAgeSec)
	}

	// Unset LOG_PATH → not configured, no false alarm.
	if p := ProbeTSVLog("  "); p.Configured || p.Exists {
		t.Errorf("empty LOG_PATH should be unconfigured, got %+v", p)
	}

	// Configured but missing file.
	if p := ProbeTSVLog(filepath.Join(dir, "nope.log")); !p.Configured || p.Exists {
		t.Errorf("missing file should be configured+!exists, got %+v", p)
	}
}

func TestProbeOriginRealIP_Apache(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "pre_main_global.conf")
	os.WriteFile(conf, []byte("RemoteIPHeader X-Forwarded-For\nRemoteIPTrustedProxy 127.0.0.1\nRemoteIPTrustedProxy 84.54.49.35\n"), 0o644)

	apacheGlobs := []string{filepath.Join(dir, "*.conf")}
	got := probeOriginRealIP("httpd", apacheGlobs, nil, nil)
	if got.Stack != "apache" || !got.Trusted {
		t.Fatalf("expected apache trusted, got %+v", got)
	}
	if got.Source != conf {
		t.Errorf("Source = %q, want %q", got.Source, conf)
	}
}

func TestProbeOriginRealIP_Nginx(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "cfm-realip.conf")
	os.WriteFile(ok, []byte("set_real_ip_from 127.0.0.1;\nset_real_ip_from ::1;\n"), 0o644)
	nginxGlobs := []string{filepath.Join(dir, "*.conf")}

	got := probeOriginRealIP("nginx", nil, nginxGlobs, nil)
	if got.Stack != "nginx" || !got.Trusted {
		t.Fatalf("expected nginx trusted, got %+v", got)
	}

	// Missing directive → not trusted, with the operator-facing note.
	empty := t.TempDir()
	os.WriteFile(filepath.Join(empty, "other.conf"), []byte("server_tokens off;\n"), 0o644)
	miss := probeOriginRealIP("nginx", nil, []string{filepath.Join(empty, "*.conf")}, nil)
	if miss.Trusted {
		t.Fatalf("expected NOT trusted when set_real_ip_from absent, got %+v", miss)
	}
	if miss.Note == "" {
		t.Errorf("expected a note explaining the missing trust")
	}
}

func TestProbeOriginRealIP_LiteSpeedNative(t *testing.T) {
	dir := t.TempDir()
	xml := filepath.Join(dir, "httpd_config.xml")
	os.WriteFile(xml, []byte("<httpServerConfig>\n <useIpInProxyHeader>2</useIpInProxyHeader>\n</httpServerConfig>\n"), 0o644)

	got := probeOriginRealIP("lshttpd", nil, nil, []string{xml})
	if got.Stack != "litespeed" || !got.Trusted {
		t.Fatalf("expected litespeed trusted via useIpInProxyHeader, got %+v", got)
	}
}

// A useIpInProxyHeader tag that is XML-commented out must NOT be read as trusted
// (a false "trusted" hides a real client-IP logging break).
func TestProbeOriginRealIP_LiteSpeedCommentedNotTrusted(t *testing.T) {
	dir := t.TempDir()
	xml := filepath.Join(dir, "httpd_config.xml")
	os.WriteFile(xml, []byte("<httpServerConfig>\n <!-- <useIpInProxyHeader>2</useIpInProxyHeader> -->\n <useIpInProxyHeader>0</useIpInProxyHeader>\n</httpServerConfig>\n"), 0o644)

	got := probeOriginRealIP("lshttpd", nil, nil, []string{xml})
	if got.Trusted {
		t.Fatalf("commented-out useIpInProxyHeader must not be trusted, got %+v", got)
	}
}

// Loopback CIDR forms (/32, /8) and ::1 must be recognized; a non-loopback
// 127.0.0.100 must not.
func TestOriginRealIP_LoopbackCIDRForms(t *testing.T) {
	write := func(t *testing.T, body string) []string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "x.conf"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return []string{filepath.Join(dir, "*.conf")}
	}

	// nginx
	for _, ok := range []string{"set_real_ip_from 127.0.0.1/32;\n", "set_real_ip_from 127.0.0.0/8;\n", "set_real_ip_from ::1;\n"} {
		if p := probeOriginRealIP("nginx", nil, write(t, ok), nil); !p.Trusted {
			t.Errorf("nginx: expected trusted for %q, got %+v", ok, p)
		}
	}
	if p := probeOriginRealIP("nginx", nil, write(t, "set_real_ip_from 127.0.0.100;\n"), nil); p.Trusted {
		t.Errorf("nginx: 127.0.0.100 must NOT be treated as loopback trust, got %+v", p)
	}

	// apache
	for _, ok := range []string{"RemoteIPInternalProxy 127.0.0.1/32\n", "RemoteIPTrustedProxy 127.0.0.0/8\n"} {
		if p := probeOriginRealIP("httpd", write(t, ok), nil, nil); !p.Trusted {
			t.Errorf("apache: expected trusted for %q, got %+v", ok, p)
		}
	}
	if p := probeOriginRealIP("httpd", write(t, "RemoteIPInternalProxy 127.0.0.100\n"), nil, nil); p.Trusted {
		t.Errorf("apache: 127.0.0.100 must NOT be treated as loopback trust, got %+v", p)
	}
}

func TestCleanConfValue(t *testing.T) {
	cases := map[string]string{
		`"/var/log/apache2/access_cfm_tsv.log"`: "/var/log/apache2/access_cfm_tsv.log",
		`/var/log/x.log  ; inline note`:         "/var/log/x.log",
		`  '/tmp/y.log'  `:                      "/tmp/y.log",
		``:                                      "",
	}
	for in, want := range cases {
		if got := cleanConfValue(in); got != want {
			t.Errorf("cleanConfValue(%q) = %q, want %q", in, got, want)
		}
	}
}

// guard against a probe hanging on a huge file (size cap).
func TestGrepGlobs_SizeCap(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.conf")
	f, _ := os.Create(big)
	_ = f.Truncate((1 << 20) + 1) // just over the 1 MiB cap
	f.Close()
	// mtime in the past so it's a normal file
	_ = os.Chtimes(big, time.Now(), time.Now())
	if got := grepGlobs([]string{filepath.Join(dir, "*.conf")}, nginxRealIPRe); got != "" {
		t.Errorf("oversized file should be skipped, matched %q", got)
	}
}
