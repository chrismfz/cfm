package webdetector

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// metaStaticMapLine is the $meta_throttle_image entry: the PHP path-info guard
// (`/x.php/a.js` is a script) and the static-file extensions.
const metaStaticMapLine = `"~*^(?!.*\.(?:phtml|pht|php[0-9]|php|phar)/).*\.(?:jpe?g|jfif|png|gif|webp|avif|ico|bmp|tiff?|css|m?js|map|woff2?|ttf|otf|eot)$" 1;`

// The crawler throttle (Meta / SEO bots) lives only in the edge confs: the
// http-block maps and zones, and the server-level limit_req/limit_conn lines.
// Images, css/js and fonts take their own, looser budget (meta_img_host_*) so
// a catalog crawl of a shop's product images, or meta-externalads rendering
// an ad's landing page with all its assets, is not 429'd by the page limit. These
// tests pin that both edges carry the same throttle block and that every
// server applying the page limits applies the image limits too.

var crawlerThrottleConfs = []string{"../../configs/openresty.conf", "../../configs/angie.conf"}

// crawlerThrottleBlock returns the http-block throttle section: from the
// crawler UA map to the end of the throttle-log switch.
func crawlerThrottleBlock(t *testing.T, path, conf string) string {
	t.Helper()
	start := strings.Index(conf, "map $http_user_agent $is_meta_crawler {")
	if start < 0 {
		t.Fatalf("%s: crawler UA map not found", path)
	}
	rest := conf[start:]
	logMap := strings.Index(rest, "$log_meta_throttle {")
	if logMap < 0 {
		t.Fatalf("%s: $log_meta_throttle map not found", path)
	}
	end := strings.Index(rest[logMap:], "\n    }\n")
	if end < 0 {
		t.Fatalf("%s: end of $log_meta_throttle map not found", path)
	}
	return rest[:logMap+end+len("\n    }\n")]
}

func TestCrawlerThrottleBlockSameOnBothEdges(t *testing.T) {
	var blocks []string
	for _, f := range crawlerThrottleConfs {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		blk := crawlerThrottleBlock(t, f, string(b))
		for _, want := range []string{
			"map $uri $meta_throttle_image {",
			// Static files a page render fetches: images, css/js, fonts. A
			// css/js file back on the page budget 429s the ads crawler. The
			// whole line is pinned, so the PHP path-info guard stays too.
			metaStaticMapLine,
			`"~^[12]\|0\|0$" 1;`, // pages: any listed crawler, host not exempt
			`"~^2\|0\|1$" 1;`,    // images: Meta crawlers only
			"zone=meta_img_host_rps:20m rate=50r/s;",
			"zone=meta_img_host_conn:20m;",
			// Pages: SEO crawlers 5 r/s, Meta's 10 r/s, per vhost.
			"zone=meta_seo_host_rps:20m rate=5r/s;",
			"zone=meta_fb_host_rps:20m  rate=10r/s;",
			`"1|1"   "seo";`,
			`"2|1"   "meta";`,
			`"~^([^|]+)\|seo$" "$1";`,
			`"~^([^|]+)\|meta$" "$1";`,
			// Only value-2 (Meta) crawlers reach the image budget: a Meta UA
			// set back to 1 would silently 429 catalog image fetches again.
			`"~*meta-externalagent"   2;`,
			`"~*meta-externalads"     2;`,
			`"~*facebookexternalhit"  2;`,
			`"~*facebookcatalog"      2;`,
		} {
			if !strings.Contains(blk, want) {
				t.Errorf("%s: crawler throttle block lacks %q", f, want)
			}
		}
		if !strings.Contains(string(b), "img=$is_meta_crawler_img_throttled") {
			t.Errorf("%s: throttle.log format must log which budget applied (img=$is_meta_crawler_img_throttled)", f)
		}
		blocks = append(blocks, blk)
	}
	if blocks[0] != blocks[1] {
		t.Errorf("crawler throttle block differs between %s and %s; change both together",
			crawlerThrottleConfs[0], crawlerThrottleConfs[1])
	}
}

func TestCrawlerThrottleImageLimitsWhereverPageLimitsApply(t *testing.T) {
	for _, f := range crawlerThrottleConfs {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		conf := string(b)
		page := strings.Count(conf, "limit_req  zone=meta_seo_host_rps burst=60 nodelay;")
		if page == 0 {
			t.Fatalf("%s: no server applies the crawler page limit", f)
		}
		for _, want := range []string{
			"limit_req  zone=meta_fb_host_rps  burst=100 nodelay;",
			"limit_req  zone=meta_img_host_rps burst=200 nodelay;",
			"limit_conn meta_img_host_conn 30;",
		} {
			if n := strings.Count(conf, want); n != page {
				t.Errorf("%s: %q in %d servers, page limit in %d", f, want, n, page)
			}
		}
	}
}

// Every extension the static-asset location serves must take the crawler's
// static-file budget: a css/js file left on the page budget 429'd Meta's ads
// crawler rendering a landing page (2026-11-11). The two lists cannot share
// one definition in nginx, so this test is what keeps them together.
func TestCrawlerThrottleStaticBudgetCoversStaticLocation(t *testing.T) {
	locRe := regexp.MustCompile(`location ~\* "\^\(\?!\.\*\\\.\(\?:phtml\|pht\|php\[0-9\]\|php\|phar\)/\)\.\*\\\.\(\?:([a-z0-9|?]+)\)\$" \{`)
	mapExt := regexp.MustCompile(`\\\.\(\?:([a-z0-9|?]+)\)\$" 1;`).FindStringSubmatch(metaStaticMapLine)
	if mapExt == nil {
		t.Fatal("extension group not found in metaStaticMapLine")
	}
	inBudget := regexp.MustCompile(`(?i)\.(?:` + mapExt[1] + `)$`)
	for _, f := range crawlerThrottleConfs {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		locs := locRe.FindAllStringSubmatch(string(b), -1)
		if len(locs) == 0 {
			t.Fatalf("%s: no static-asset location found", f)
		}
		for _, loc := range locs {
			for _, ext := range strings.Split(loc[1], "|") {
				if !inBudget.MatchString("/a." + ext) {
					t.Errorf("%s: static-asset location serves .%s, but $meta_throttle_image leaves it on the page budget", f, ext)
				}
			}
		}
	}
}
