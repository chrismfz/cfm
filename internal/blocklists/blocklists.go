package blocklists

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"path"
//	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ListType int

const (
	TypeBlock ListType = iota
	TypeAllow
	TypeIgnore
)

func (t ListType) String() string {
        switch t {
        case TypeAllow:
                return "ALLOW"
        case TypeIgnore:
                return "IGNORE"
        default:
                return "BLOCK"
        }
}

type Feed struct {
	Name     string         // e.g. SPAMDROP
	Type     ListType       // BLOCK or ALLOW
	Interval time.Duration  // refresh interval
	Max      int            // 0 = all
	URL      string         // source URL
	TTL      *time.Duration // optional, per-feed element timeout
}

// ParseConfig διαβάζει ένα αρχείο τύπου CSF (NAME|TYPE|INTERVAL|MAX|URL[|TTL=1h])
// Αγνοεί κενές γραμμές και σχόλια (#...).
func ParseConfig(r io.Reader) ([]Feed, error) {
	var feeds []Feed
	sc := bufio.NewScanner(r)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			// μπορεί να είναι σχολιασμένη με leading '# ' αλλά έμεινε κάτι; αγνόησε
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		typS := strings.ToUpper(strings.TrimSpace(parts[1]))
		var typ ListType
		switch typS {
		case "BLOCK":
			typ = TypeBlock
		case "ALLOW":
			typ = TypeAllow
                case "IGNORE":
                        typ = TypeIgnore
		default:
			// συμβατότητα με CSF που δεν έχει TYPE: αν δίνεται μόνο 4 πεδία και λείπει TYPE,
			// μπορείς να προσαρμόσεις εδώ. Προς το παρόν απαιτούμε 5 πεδία.
			continue
		}
		ivalS := strings.TrimSpace(parts[2])
		ivalSec, err := strconv.Atoi(ivalS)
		if err != nil || ivalSec < 3600 {
			// ελάχιστο 3600s, όπως CSF
			continue
		}
		maxS := strings.TrimSpace(parts[3])
		maxN, err := strconv.Atoi(maxS)
		if err != nil || maxN < 0 {
			maxN = 0
		}
		url := strings.TrimSpace(parts[4])
		if url == "" {
			continue
		}
		var ttl *time.Duration
		// προαιρετικά επιπλέον πεδία μετά το URL (π.χ. TTL=1h)
		for _, extra := range parts[5:] {
			extra = strings.TrimSpace(extra)
			if strings.HasPrefix(strings.ToUpper(extra), "TTL=") {
				val := strings.TrimSpace(extra[4:])
				if d, err := time.ParseDuration(val); err == nil && d > 0 {
					ttl = &d
				}
			}
		}
		feeds = append(feeds, Feed{
			Name:     name,
			Type:     typ,
			Interval: time.Duration(ivalSec) * time.Second,
			Max:      maxN,
			URL:      url,
			TTL:      ttl,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return feeds, nil
}

// ---------- Fetch & Decode ----------

type FetchResult struct {
	V4 []string // elements: "IP" ή "IP/prefix"
	V6 []string // στοιχεία IPv6 (IP ή prefix)
	// μελλοντικά: raw meta (etag, last-modified) για conditional GET
}

// FetchAndParse κατεβάζει και επιστρέφει IPs/CIDRs (v4/v6) από ένα feed,
// υποστηρίζοντας gzip/zip και "θορυβώδη" formats με σχόλια/στήλες.
//
// Χωρίς token: για feeds τρίτων. Για τα feeds του cfm-web βλ. FetchAndParseAuth.
func FetchAndParse(ctx context.Context, client *http.Client, f Feed) (*FetchResult, error) {
	return FetchAndParseAuth(ctx, client, f, APIAuth{})
}

// FetchAndParseAuth is FetchAndParse, plus the cfm-web `Token:` header when the
// feed lives on the configured API_URL origin (see APIAuth.tokenFor). cfm-web
// used to authenticate these header-less pulls by source IP alone; that
// fallback is being retired, so the node must present its AUTH_TOKEN like
// every other agent call does.
func FetchAndParseAuth(ctx context.Context, client *http.Client, f Feed, auth APIAuth) (*FetchResult, error) {
	res, _, err := fetchAndParse(ctx, client, f, auth)
	return res, err
}

// fetchMeta is what a fetch observed on the wire, for Manager.Status.
type fetchMeta struct {
	TokenSent  bool
	HTTPStatus int // 0 = no response (DNS/TLS/timeout)
}

func fetchAndParse(ctx context.Context, client *http.Client, f Feed, auth APIAuth) (*FetchResult, fetchMeta, error) {
	var meta fetchMeta
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", f.URL, nil)
	if err != nil {
		return nil, meta, err
	}
	if tok := auth.tokenFor(req.URL); tok != "" {
		req.Header.Set("Token", tok)
		meta.TokenSent = true
		req.Header.Set("X-Agent-Version", "CFM-Agent-Go")
		// Go strips only Authorization/Cookie/WWW-Authenticate on a
		// cross-host redirect; a custom header is forwarded as-is. Never
		// let a redirect carry the token off the cfm-web origin.
		c := *client
		prev := client.CheckRedirect
		c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
			if auth.tokenFor(r.URL) == "" {
				r.Header.Del("Token")
			}
			if prev != nil {
				return prev(r, via)
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		}
		client = &c
	}
	// Μπορούμε να προσθέσουμε ETag/If-Modified-Since αργότερα (cache).
	resp, err := client.Do(req)
	if err != nil {
		return nil, meta, err
	}
	defer resp.Body.Close()
	meta.HTTPStatus = resp.StatusCode
	// What the FINAL hop carried: a redirect off the API origin drops the
	// token, and that host's answer must not read as cfm-web's verdict on it.
	if resp.Request != nil {
		meta.TokenSent = resp.Request.Header.Get("Token") != ""
	}
	if resp.StatusCode == http.StatusNotModified {
		// handled by caller (χρειάζεται cache-aware design)
		return &FetchResult{}, meta, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		authErr := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
		// cfm-web explains an auth refusal in the body ("Invalid token", "IP
		// address mismatch", "Token required", a usage limit): surface it,
		// clipped and on one line.
		body := ""
		if authErr || meta.TokenSent {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
			body = strings.Join(strings.Fields(string(b)), " ")
		}
		final := req.URL
		if resp.Request != nil && resp.Request.URL != nil {
			final = resp.Request.URL // the host that actually answered
		}
		if !meta.TokenSent && authErr && auth.Token != "" && auth.looksLikeAPIFeed(final) {
			if why := auth.mismatch(final); why != "" {
				return nil, meta, fmt.Errorf("http %d (no Token sent: %s)", resp.StatusCode, why)
			}
		}
		if body != "" {
			return nil, meta, fmt.Errorf("http %d: %s", resp.StatusCode, body)
		}
		return nil, meta, fmt.Errorf("http %d", resp.StatusCode)
	}

	var body []byte
	ctype := resp.Header.Get("Content-Type")
	// Αν είναι zip/gzip, χειρίσου ανάλογα. Αλλιώς διάβασε κανονικά.
	if isGzip(ctype, f.URL) {
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, meta, err
		}
		defer gr.Close()
		body, err = io.ReadAll(gr)
		if err != nil {
			return nil, meta, err
		}
	} else if isZip(ctype, f.URL) {
		// Πρέπει να κατεβάσουμε first σε buffer για zip reader
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, meta, err
		}
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			return nil, meta, err
		}
		// Περιμένουμε ένα text entry. Πάρε το πρώτο text-like.
		var found io.ReadCloser
		for _, zf := range zr.File {
			// αγνόησε dirs
			if zf.FileInfo().IsDir() {
				continue
			}
			rc, err := zf.Open()
			if err != nil {
				continue
			}
			found = rc
			break
		}
		if found == nil {
			return nil, meta, errors.New("zip: no file entry")
		}
		defer found.Close()
		body, err = io.ReadAll(found)
		if err != nil {
			return nil, meta, err
		}
	} else {
		var err error
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, meta, err
		}
	}

	v4, v6 := ExtractIPs(bytes.NewReader(body), f.Max)
	return &FetchResult{V4: v4, V6: v6}, meta, nil
}

func isGzip(contentType, url string) bool {
	// έλεγχος μέσω Content-Type ή επέκτασης
	if ct, _, _ := mime.ParseMediaType(contentType); ct == "application/gzip" || ct == "application/x-gzip" {
		return true
	}
	ext := strings.ToLower(path.Ext(url))
	return ext == ".gz"
}

func isZip(contentType, url string) bool {
	if ct, _, _ := mime.ParseMediaType(contentType); ct == "application/zip" {
		return true
	}
	ext := strings.ToLower(path.Ext(url))
	return ext == ".zip"
}

// ---------- Parsing helpers ----------

// Regular expressions για IPv4/IPv6 & CIDR.
// Προσοχή: κρατάμε conservative patterns για να αποφεύγουμε false positives.
var (
	reIPv4     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reIPv4CIDR = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/(?:3[0-2]|[12]?\d)\b`)

	// IPv6 λίγη πιο χαλαρή + CIDR
	reIPv6     = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F:]{1,4}\b`)
	reIPv6CIDR = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F:]{1,4}/(?:12[0-8]|1[01]\d|\d{1,2})\b`)
)

// ExtractIPs παίρνει αυθαίρετο text (γραμμές με σχόλια/στήλες) και
// επιστρέφει slice από στοιχεία (v4/v6) που είναι είτε IP είτε CIDR.
// Αν max>0, κόβει μετά από max στοιχεία (ανά family ξεχωριστά).
func ExtractIPs(r io.Reader, max int) (v4 []string, v6 []string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024) // επιτρέπουμε μεγάλες γραμμές
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 1) CIDRs πρώτα (μην τα ξανα-πιάσουμε ως σκέτα IPs)
		for _, cidr := range reIPv4CIDR.FindAllString(line, -1) {
			if _, _, err := net.ParseCIDR(cidr); err == nil {
				v4 = append(v4, cidr)
			}
		}
		for _, cidr := range reIPv6CIDR.FindAllString(line, -1) {
			if _, _, err := net.ParseCIDR(cidr); err == nil {
				v6 = append(v6, cidr)
			}
		}

		// 2) DShield-style: "startIP<TAB>endIP<TAB>mask"
		// Παράδειγμα: 123.136.6.0  123.136.6.255  24 ...
		// Θα κρατήσουμε "startIP/mask" αν είναι valid.
		fields := splitFieldsTabsOrSpaces(line)
		if len(fields) >= 3 && isIPv4(fields[0]) && isIPv4(fields[1]) && isMask(fields[2], 32) {
			cidr := fmt.Sprintf("%s/%s", fields[0], fields[2])
			if _, _, err := net.ParseCIDR(cidr); err == nil {
				v4 = append(v4, cidr)
			}
		}
		// (αν προκύψει αντίστοιχο pattern για IPv6, μπορείς να το προσθέσεις)

		// 3) Σκέτα IPv4/IPv6 (όχι CIDR)
		// Προσοχή να μην διπλοπροσθέσουμε στοιχεία που ήδη συλλέξαμε ως CIDR.
		for _, ip := range reIPv4.FindAllString(line, -1) {
			// Μην προσθέσεις αν το ip ήταν αρχή CIDR στο ίδιο line
			if strings.Contains(line, ip+"/") {
				continue
			}
			if net.ParseIP(ip) != nil {
				v4 = append(v4, ip)
			}
		}
		for _, ip := range reIPv6.FindAllString(line, -1) {
			// Μην προσθέσεις αν ήταν CIDR
			if strings.Contains(line, ip+"/") {
				continue
			}
			// Κόψε προφανή false-positives από συντεταγμένες/UUID-like (basic sanity)
			if net.ParseIP(ip) != nil {
				v6 = append(v6, ip)
			}
		}

		// Respect MAX (separately per family)
		if max > 0 {
			if len(v4) >= max && len(v6) >= max {
				break
			}
		}
	}
	// Deduplicate διατηρώντας σειρά
	v4 = dedupKeepOrder(v4)
	v6 = dedupKeepOrder(v6)
	if max > 0 && len(v4) > max {
		v4 = v4[:max]
	}
	if max > 0 && len(v6) > max {
		v6 = v6[:max]
	}
	return v4, v6
}

func splitFieldsTabsOrSpaces(s string) []string {
	// Κλασικά feeds έχουν \t (tabs) — αλλά υποστήριξε και spaces
	// Ενοποιούμε tabs→space και κάνουμε Fields
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.Fields(s)
}

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func isMask(s string, maxBits int) bool {
	n, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return n >= 0 && n <= maxBits
}

func dedupKeepOrder(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, x := range in {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}
