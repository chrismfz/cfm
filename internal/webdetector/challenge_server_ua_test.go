package webdetector

import (
	"strings"
	"testing"
)

// The challenge page must reach the in-app browsers: a Facebook / Instagram ad
// click on a challenged vhost got `403 bad ua` (vol2.gr, 2026-10-28), their
// UAs being longer than 256 bytes and carrying 18-19 `;()[]`.
func TestIsWeirdUAInAppBrowsers(t *testing.T) {
	for _, ua := range []string{
		// Facebook, iOS (titan access log, 2026-10-28)
		"Mozilla/5.0 (iPhone; CPU iPhone OS 26_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/23C71 Safari/604.1 [FBAN/FBIOS;FBAV/584.1.0.65.70;FBBV/1097955119;FBDV/iPhone13,4;FBMD/iPhone;FBSN/iOS;FBSV/26.2.1;FBSS/3;FBID/phone;FBLC/el_GR;FBOP/5;FBRV/1101057903;IABMV/1]",
		// Facebook, iOS, with an empty FBCR/ (the customer's reproduction)
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/22G86 [FBAN/FBIOS;FBAV/530.0.0.40.94;FBBV/780000000;FBDV/iPhone15,2;FBMD/iPhone;FBSN/iOS;FBSV/18.6;FBSS/3;FBCR/;FBID/phone;FBLC/el_GR;FBOP/5;FBRV/0]",
		// Facebook, Android
		"Mozilla/5.0 (Linux; Android 14; SM-A528B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.8078.52 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/584.0.0.48.70;IABMV/1;]",
		// Instagram, Android (titan access log, 2026-10-28)
		"Mozilla/5.0 (Linux; Android 14; SM-A528B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.8078.52 Mobile Safari/537.36 Instagram 453.0.0.55.79 Android (34/14; 450dpi; 1080x2400; samsung; SM-A528B; a52sxq; qcom; el_GR; 1100455559; IABMV/1) NV/501",
		// Instagram, iOS
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/22G86 Instagram 400.0.0.37.83 (iPhone15,2; iOS 18_6; el_GR; el; scale=3.00; 1179x2556; 812345678; IABMV/1)",
		// TikTok, Android
		"Mozilla/5.0 (Linux; Android 13; SM-G991B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.6723.107 Mobile Safari/537.36 trill_370504 JsSdk/1.0 NetType/WIFI Channel/googleplay AppName/musical_ly app_version/37.5.4 ByteLocale/el ByteFullLocale/el Region/GR AppId/1233 Spark/1.6.3 AppVersion/37.5.4 BytedanceWebview/d8a21c6",
		// exactly the 1024-byte cap
		"Mozilla/5.0 " + strings.Repeat("a", 1012),
		// 15 of the counted characters (one under the threshold)
		`Mozilla/5.0 "a" "b" "c" "d" "e" "f" "g" '`,
		// a desktop browser
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
	} {
		if isWeirdUA(ua) {
			t.Errorf("a real browser is a bad ua (len %d): %s", len(ua), ua)
		}
	}
}

func TestIsWeirdUARejects(t *testing.T) {
	for name, ua := range map[string]string{
		"empty":      "",
		"blank":      "   ",
		"too long":   "Mozilla/5.0 " + strings.Repeat("a", 1013), // 1025 bytes
		"newline":    "Mozilla/5.0\r\nX-Injected: 1",
		"control":    "Mozilla/5.0\x01",
		"bad utf8":   "Mozilla/5.0 \xff\xfe",
		"sqlmap":     "sqlmap/1.8#stable (https://sqlmap.org)",
		"nikto":      "Mozilla/5.00 (Nikto/2.5.0)",
		"markup":     `"><script>alert('x')</script><img src=x onerror="y"><b>"'`,
		"quoted":     `'||'"||"{${jndi}}"||"'||'`,
		"16 counted": `Mozilla/5.0 "a" "b" "c" "d" "e" "f" "g" "h"`,
		"templates":  "{{7*7}}{{8*8}}<%= 1 %><><{}>|||",
	} {
		if !isWeirdUA(ua) {
			t.Errorf("%s: not a bad ua: %q", name, ua)
		}
	}
}
