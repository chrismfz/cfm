package webdetector

import "testing"

func TestDatacenterClass(t *testing.T) {
	tests := []struct {
		name    string
		asn     uint
		asnName string
		want    string
	}{
		// Curated ASN map wins (exact), regardless of org string.
		{"aws by asn", 16509, "Amazon.com, Inc.", "amazon-aws"},
		{"hetzner by asn", 24940, "Hetzner Online GmbH", "hetzner"},
		{"google by asn", 15169, "Google LLC", "google"},
		{"contabo by asn", 51167, "Contabo GmbH", "contabo"},
		// Org-name fallback for ASNs not in the curated map.
		{"ovh by name", 99999, "OVH SAS", "ovh"},
		{"leaseweb by name", 88888, "LeaseWeb Netherlands B.V.", "leaseweb"},
		{"generic hosting by name", 77777, "Big Hosting LLC", "hosting"},
		// "data center" (with a space) in an org name must canonicalize to a
		// space-free tag — the abuse-shadow log line is space-delimited, so a
		// tag with an interior space would split the provider= field and the
		// parser would drop the tail.
		{"data center org canonicalizes space-free", 66666, "Acme Data Center Ltd", "datacenter"},
		// Consumer ISPs must NOT classify — the reason the keyword list avoids
		// ambiguous tokens like "server"/"cloud"/"net"/"solutions".
		{"greek isp", 6799, "Ote SA (Hellenic Telecommunications Organisation)", ""},
		{"cosmote mobile", 29247, "Cosmote Mobile Telecommunications S.A.", ""},
		{"comcast", 7922, "Comcast Cable Communications, LLC", ""},
		{"vodafone", 12361, "Vodafone-panafon Hellenic Telecommunications", ""},
		{"a generic cloudy-sounding isp name must not match", 55555, "SkyNet Solutions ISP", ""},
		{"empty", 0, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DatacenterClass(tc.asn, tc.asnName); got != tc.want {
				t.Errorf("DatacenterClass(%d, %q) = %q, want %q", tc.asn, tc.asnName, got, tc.want)
			}
			if IsDatacenter(tc.asn, tc.asnName) != (tc.want != "") {
				t.Errorf("IsDatacenter(%d, %q) = %v, want %v", tc.asn, tc.asnName, !(tc.want != ""), tc.want != "")
			}
		})
	}
}
