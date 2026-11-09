package webdetector

import (
	"os"
	"strings"
	"testing"
)

// The crawler throttle (Meta / SEO bots) lives only in the edge confs: the
// http-block maps and zones, and the server-level limit_req/limit_conn lines.
// Images take their own, looser budget (meta_img_host_*) so a catalog crawl
// of a shop's product images is not 429'd by the 5 r/s page limit. These
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
			`"~^[12]\|0\|0$" 1;`, // pages: any listed crawler, host not exempt
			`"~^2\|0\|1$" 1;`, // images: Meta crawlers only
			"zone=meta_img_host_rps:20m rate=50r/s;",
			"zone=meta_img_host_conn:20m;",
		} {
			if !strings.Contains(blk, want) {
				t.Errorf("%s: crawler throttle block lacks %q", f, want)
			}
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
		page := strings.Count(conf, "limit_req  zone=meta_host_rps    burst=60 nodelay;")
		if page == 0 {
			t.Fatalf("%s: no server applies the crawler page limit", f)
		}
		for _, want := range []string{
			"limit_req  zone=meta_img_host_rps burst=200 nodelay;",
			"limit_conn meta_img_host_conn 30;",
		} {
			if n := strings.Count(conf, want); n != page {
				t.Errorf("%s: %q in %d servers, page limit in %d", f, want, n, page)
			}
		}
	}
}
