package webdetector

import (
	"testing"
	"time"
)

func TestIsWPAdminAjaxOrigin403(t *testing.T) {
	const host = "ndnodo.com"
	ajax := func(uri, ref string) LogRec {
		return LogRec{Host: host, URI: uri, Ref: ref, Status: 403, Upstream: true, UpstreamName: "cfm_apache"}
	}
	const polled = "/wp-admin/admin-ajax.php?reqbs=reqbs-backgroundindexing&action=barcodescanneraction&id=1&token=e69&usersession=&usertoken=&platform=web"
	const adminRef = "https://ndnodo.com/wp-admin/edit.php?post_type=shop_order"
	for name, rec := range map[string]LogRec{
		"titan 2026-11-17":      ajax(polled, adminRef),
		"no query":              ajax("/wp-admin/admin-ajax.php", adminRef),
		"install dir":           ajax("/shop/wp-admin/admin-ajax.php?action=heartbeat", "https://ndnodo.com/shop/wp-admin/post.php?post=1&action=edit"),
		"http referer, port":    ajax("/wp-admin/admin-ajax.php?action=heartbeat", "http://ndnodo.com:443/wp-admin/"),
		"12-column edge":        {Host: host, URI: "/wp-admin/admin-ajax.php", Ref: adminRef, Status: 403, Upstream: true},
		"host carries the port": {Host: host + ":443", URI: "/wp-admin/admin-ajax.php", Ref: adminRef, Status: 403, Upstream: true, UpstreamName: "cfm_apache"},
		"micro upstream":        {Host: host, URI: "/wp-admin/admin-ajax.php", Ref: adminRef, Status: 403, Upstream: true, UpstreamName: "cfm_apache_micro"},
	} {
		if !isWPAdminAjaxOrigin403(rec) {
			t.Errorf("%s: %+v must be exempt", name, rec)
		}
	}
	for name, rec := range map[string]LogRec{
		"edge 403 (WAF)":       {Host: host, URI: "/wp-admin/admin-ajax.php", Ref: adminRef, Status: 403},
		"challenge server":     {Host: host, URI: "/wp-admin/admin-ajax.php", Ref: adminRef, Status: 403, Upstream: true, UpstreamName: "cfm_challenge"},
		"404":                  {Host: host, URI: "/wp-admin/admin-ajax.php", Ref: adminRef, Status: 404, Upstream: true, UpstreamName: "cfm_apache"},
		"no referer":           ajax(polled, ""),
		"front-end referer":    ajax(polled, "https://ndnodo.com/shop/"),
		"other host referer":   ajax(polled, "https://evil.example/wp-admin/edit.php"),
		"sibling host referer": ajax(polled, "https://b2bnodo.com/wp-admin/edit.php"),
		"suffix host trick":    ajax(polled, "https://ndnodo.com.evil.example/wp-admin/"),
		"userinfo trick":       ajax(polled, "https://ndnodo.com@evil.example/wp-admin/"),
		"non-http referer":     ajax(polled, "ftp://ndnodo.com/wp-admin/"),
		"relative referer":     ajax(polled, "/wp-admin/edit.php"),
		"wp-admin lookalike":   ajax(polled, "https://ndnodo.com/wp-adminx/"),
		"referer climbs":       ajax(polled, "https://ndnodo.com/wp-admin/../wp-login.php"),
		"referer too deep":     ajax(polled, "https://ndnodo.com/a/b/wp-admin/"),
		"referer dot dir":      ajax(polled, "https://ndnodo.com/.git/wp-admin/"),
		"admin-post":           ajax("/wp-admin/admin-post.php", adminRef),
		"wp-login":             ajax("/wp-login.php", adminRef),
		"other admin page":     ajax("/wp-admin/options.php", adminRef),
		"deep ajax path":       ajax("/a/b/wp-admin/admin-ajax.php", adminRef),
		"dot install dir":      ajax("/.git/wp-admin/admin-ajax.php", adminRef),
		"escaped climb":        ajax("/%2e%2e/wp-admin/admin-ajax.php", adminRef),
		"login action":         ajax("/wp-admin/admin-ajax.php?action=ajax_login", adminRef),
		"password action":      ajax("/wp-admin/admin-ajax.php?action=lostpassword", adminRef),
		"escaped login action": ajax("/wp-admin/admin-ajax.php?action=ajax_l%6fgin", adminRef),
		"last action wins":     ajax("/wp-admin/admin-ajax.php?action=heartbeat&action=xoo_el_login", adminRef),
		"bad action escape":    ajax("/wp-admin/admin-ajax.php?action=%zz", adminRef),
	} {
		if isWPAdminAjaxOrigin403(rec) {
			t.Errorf("%s: %+v must not be exempt", name, rec)
		}
	}
}

func TestIsRuleBlock403(t *testing.T) {
	if !isRuleBlock403(LogRec{Status: 403, UpstreamName: "cfm_block_rule"}) {
		t.Fatal("a traffic rule's 403 must be exempt")
	}
	for name, rec := range map[string]LogRec{
		"ip/vhost/waf block": {Status: 403, UpstreamName: "cfm_block"},
		"older edge":         {Status: 403},
		"origin 403":         {Status: 403, Upstream: true, UpstreamName: "cfm_apache"},
		"rule block code":    {Status: 444, UpstreamName: "cfm_block_rule"},
	} {
		if isRuleBlock403(rec) {
			t.Errorf("%s: %+v must not be exempt", name, rec)
		}
	}
}

// The two Greek false positives of the 2026-11-17 read: a shop admin's
// expired wp-admin tab polling admin-ajax (titan), and a shopper whose
// WhatsApp link-preview retries a traffic rule refused (rigel). Neither may
// reach 403_flood or 40x_combo; both did before.
func TestIP403Flood_AdminAjaxAndRuleBlockIgnored(t *testing.T) {
	e := NewEngine(Config{
		Every:                 1 * time.Second,
		Window:                2 * time.Minute,
		IP403Count:            5,
		IP40xComboCount:       5,
		IP40xComboUniquePaths: 1,
	})
	now := float64(time.Now().Unix())
	for i := 0; i < 20; i++ {
		e.ingest(LogRec{
			TS: now + float64(i), IP: "10.0.3.1", Host: "ndnodo.com", Method: "post",
			URI:    "/wp-admin/admin-ajax.php?reqbs=reqbs-backgroundindexing&action=barcodescanneraction&id=" + itoa(i),
			Ref:    "https://ndnodo.com/wp-admin/edit.php?post_type=shop_order",
			Status: 403, Bytes: 110, UA: "mozilla/5.0", Upstream: true, UpstreamName: "cfm_apache",
		}, "raw")
		e.ingest(LogRec{
			TS: now + float64(i), IP: "10.0.3.2", Host: "gokids.gr", Method: "get",
			URI:    "/proion/mads-paidiko-trapezi/?gclid=x" + itoa(i),
			Status: 403, Bytes: 150, UA: "whatsapp/2.23.20.0", UpstreamName: "cfm_block_rule",
		}, "raw")
	}
	rows := e.IPShort(0)
	for _, ip := range []string{"10.0.3.1", "10.0.3.2"} {
		if ipHasReasonPrefix(rows, ip, "403_flood") || ipHasReasonPrefix(rows, ip, "40x_combo") {
			t.Fatalf("%s: must not reach 403_flood / 40x_combo; rows=%+v", ip, rows)
		}
	}
}

// The exclusions must not open a hole: the same admin-ajax 403s without the
// wp-admin Referer, an AJAX login refused by the origin, and the edge's other
// blocks (cfm_block: IP / vhost / WAF) all still trip 403_flood.
func TestIP403Flood_AdminAjaxLookalikesStillCount(t *testing.T) {
	type c struct {
		uri, ref, up string
		upstream     bool
	}
	cases := map[string]c{
		"10.0.4.1": {"/wp-admin/admin-ajax.php?action=x", "", "cfm_apache", true},
		"10.0.4.2": {"/wp-admin/admin-ajax.php?action=x", "https://evil.example/wp-admin/", "cfm_apache", true},
		"10.0.4.3": {"/wp-admin/admin-ajax.php?action=ajaxlogin", "https://example.com/wp-admin/", "cfm_apache", true},
		"10.0.4.4": {"/wp-admin/admin-ajax.php?action=x", "https://example.com/wp-admin/", "cfm_block", false},
		"10.0.4.5": {"/shop/item", "", "cfm_block", false},
	}
	e := NewEngine(Config{Every: 1 * time.Second, Window: 2 * time.Minute, IP403Count: 5})
	now := float64(time.Now().Unix())
	for ip, cc := range cases {
		for i := 0; i < 6; i++ {
			e.ingest(LogRec{
				TS: now + float64(i), IP: ip, Host: "example.com", Method: "post",
				URI: cc.uri, Ref: cc.ref, Status: 403, UA: "ua",
				Upstream: cc.upstream, UpstreamName: cc.up,
			}, "raw")
		}
	}
	rows := e.IPShort(0)
	for ip := range cases {
		if !ipHas403FloodReason(rows, ip) {
			t.Errorf("%s: expected 403_flood; rows=%+v", ip, rows)
		}
	}
}
