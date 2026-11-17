package detectors

import "testing"

// [mysql_governor] ENABLED = 0 must reach the governor lifecycle as
// Enabled=false (do not start), not as "no section" (start with defaults).
func TestMySQLGovernorSectionEnabledFlag(t *testing.T) {
	oCfg, oOK := GetPendingGovernorConfig()
	t.Cleanup(func() { setPendingGovernorConfig(oCfg, oOK) })

	f, ok := getFactory("mysql_governor")
	if !ok {
		t.Fatal("mysql_governor factory not registered")
	}

	if _, err := f("mysql_governor", KV{"ENABLED": "0"}, KV{}); err != nil {
		t.Fatal(err)
	}
	cfg, ok := GetPendingGovernorConfig()
	if !ok || cfg.Enabled {
		t.Fatalf("ENABLED = 0: ok=%v Enabled=%v, want ok=true Enabled=false", ok, cfg.Enabled)
	}

	if _, err := f("mysql_governor", KV{"ENABLED": "1", "MODE": "enforce"}, KV{}); err != nil {
		t.Fatal(err)
	}
	cfg, ok = GetPendingGovernorConfig()
	if !ok || !cfg.Enabled || cfg.Mode != "enforce" {
		t.Fatalf("ENABLED = 1: ok=%v cfg=%+v", ok, cfg)
	}
}
