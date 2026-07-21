package clam

import "testing"

// The baseline config globs match case-insensitively against the signature
// name; the shipped default pattern must catch the observed production FP.
func TestSigIgnoredConfigPatterns(t *testing.T) {
	m := NewManager(Config{SigIgnore: []string{"*_Hunting.UNOFFICIAL", "Eicar-Test-*"}})

	// The FP that motivated the layer.
	if ok, by := m.sigIgnored("a.example.com", "YARA.SIGNATURE_BASE_Brooxml_Hunting.UNOFFICIAL"); !ok {
		t.Fatal("Brooxml hunting sig must match the shipped default pattern")
	} else if by != "config:*_Hunting.UNOFFICIAL" {
		t.Fatalf("wrong match source: %q", by)
	}
	// Case-insensitive.
	if ok, _ := m.sigIgnored("a.example.com", "yara.signature_base_brooxml_hunting.unofficial"); !ok {
		t.Fatal("match must be case-insensitive")
	}
	// A real verdict must NOT match.
	if ok, by := m.sigIgnored("a.example.com", "Win.Trojan.Hide-1"); ok {
		t.Fatalf("real trojan verdict downgraded by %q", by)
	}
	if ok, _ := m.sigIgnored("a.example.com", "Php.Malware.Agent"); ok {
		t.Fatal("real PHP malware verdict downgraded")
	}
	// Empty signature never matches.
	if ok, _ := m.sigIgnored("a.example.com", ""); ok {
		t.Fatal("empty signature must not match")
	}
}

// An empty pattern list (explicit CLAM_SIG_IGNORE=) acts on everything, and
// the runtime lookup (webdetector store) is consulted after the config globs,
// with panics contained.
func TestSigIgnoredRuntimeLookup(t *testing.T) {
	t.Cleanup(func() { SetSigIgnoreLookup(nil) })
	m := NewManager(Config{SigIgnore: nil})

	if ok, _ := m.sigIgnored("h.example.com", "Anything.At.All"); ok {
		t.Fatal("no config patterns + no lookup: nothing may be ignored")
	}

	SetSigIgnoreLookup(func(host, sig string) (bool, string) {
		if host == "h.example.com" && sig == "Some.Sig" {
			return true, "store:h.example.com:Some.Sig"
		}
		return false, ""
	})
	if ok, by := m.sigIgnored("h.example.com", "Some.Sig"); !ok || by != "store:h.example.com:Some.Sig" {
		t.Fatalf("lookup match = (%v, %q)", ok, by)
	}
	if ok, _ := m.sigIgnored("other.example.com", "Some.Sig"); ok {
		t.Fatal("lookup is host-specific; other host must not match")
	}

	// A panicking lookup must not take down the scanner worker.
	SetSigIgnoreLookup(func(string, string) (bool, string) { panic("boom") })
	if ok, _ := m.sigIgnored("h.example.com", "Some.Sig"); ok {
		t.Fatal("panicking lookup must resolve to not-ignored")
	}

	// A malformed glob never matches (and never errors out).
	m2 := NewManager(Config{SigIgnore: []string{"[unclosed"}})
	if ok, _ := m2.sigIgnored("h.example.com", "whatever"); ok {
		t.Fatal("malformed pattern must not match")
	}
}
