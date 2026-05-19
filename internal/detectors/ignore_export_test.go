package detectors

// Test-only exported constructor so external packages (or smoke tests) can
// build an IPIgnore from a KV map without touching unexported fields.
func NewIPIgnoreFromGlobalForTest(global map[string]string) *IPIgnore {
	return newIPIgnoreFromGlobal(KV(global))
}
