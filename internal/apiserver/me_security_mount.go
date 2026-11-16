package apiserver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// goauth serves the account-security routes (/me/security/...). They are
// registered on a mux of their own and mounted through meSecurityHandler, so
// cfm can act on them in one place.

const totpEnrollStartPath = "/me/security/mfa/totp/enroll/start"

// meSecurityHandler wraps goauth's account-security routes.
func meSecurityHandler(routes http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == totpEnrollStartPath {
			serveTOTPEnrollStartWithQR(w, r, routes)
			return
		}
		routes.ServeHTTP(w, r)
	})
}

// serveTOTPEnrollStartWithQR adds the enrollment QR code to goauth's answer.
//
// goauth returns the otpauth:// URI only. The Settings page then had no image
// to show and asked api.qrserver.com to draw one, with the URI in the query
// string: the URI contains the TOTP secret, so every enrollment handed the
// account's second factor to a third party (and to whatever logs its URLs).
// The image is made here instead and the secret stays on the node.
func serveTOTPEnrollStartWithQR(w http.ResponseWriter, r *http.Request, routes http.Handler) {
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, r)

	if rec.Code == http.StatusOK {
		var payload map[string]any
		if json.Unmarshal(rec.Body.Bytes(), &payload) == nil {
			if uri, _ := payload["otpauth_uri"].(string); uri != "" {
				if dataURL, err := totpQRDataURL(uri); err == nil {
					payload["qr_data_url"] = dataURL
					if body, err := json.Marshal(payload); err == nil {
						rec.Body = bytes.NewBuffer(body)
						rec.Header().Del("Content-Length")
					}
				}
				// On an error the answer goes out as goauth wrote it: the page
				// then shows the URI for manual entry.
			}
		}
	}
	// The body carries the TOTP secret.
	rec.Header().Set("Cache-Control", "no-store")
	copyRecorderResponse(w, rec)
}

const (
	totpQRTargetPx     = 264 // about this wide, before the margin
	totpQRQuietModules = 4   // white quiet zone the QR spec asks for; scanners need it on a dark page
)

// totpQRDataURL renders an otpauth:// URI as a PNG data URL.
func totpQRDataURL(uri string) (string, error) {
	img, _, err := totpQRImage(uri)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// totpQRImage draws the code with a whole number of pixels per module (no
// resampling blur) inside a white quiet zone, and returns that pixel count.
func totpQRImage(uri string) (image.Image, int, error) {
	if !strings.HasPrefix(uri, "otpauth://") || len(uri) > 1024 {
		return nil, 0, errNotOTPAuthURI
	}
	code, err := qr.Encode(uri, qr.M, qr.Auto)
	if err != nil {
		return nil, 0, err
	}
	modules := code.Bounds().Dx()
	px := max(totpQRTargetPx/modules, 3)
	scaled, err := barcode.Scale(code, modules*px, modules*px)
	if err != nil {
		return nil, 0, err
	}
	margin := totpQRQuietModules * px
	side := modules*px + 2*margin
	img := image.NewRGBA(image.Rect(0, 0, side, side))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(margin, margin, side-margin, side-margin), scaled, image.Point{}, draw.Src)
	return img, px, nil
}
