package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"cfm/internal/logging"
)

type suppressAuthAuditKey struct{}

const (
	maxAuthAuditUserBytes = 256
	maxAuthAuditPathBytes = 2048
	maxAuthAuditUABytes   = 512
	maxAuditFieldBytes    = 4096
)

type authAttemptAudit struct {
	Kind     string
	Result   string
	AuthMech string
	User     string
	TokenID  string
	Status   int
	MFA      string
}

var writeAuthAuditLine = func(line string) {
	logging.LogfAPI("%s", line)
}

func auditAuthAttempt(r *http.Request, attempt authAttemptAudit) {
	if r != nil {
		if suppressed, _ := r.Context().Value(suppressAuthAuditKey{}).(bool); suppressed {
			return
		}
	}
	peer := requestPeer(r)
	srcIP := "unknown"
	if peer.ClientIP != nil {
		srcIP = peer.ClientIP.String()
	}
	peerIP := "unknown"
	if peer.ImmediateIP != nil {
		peerIP = peer.ImmediateIP.String()
	}
	method, path := "unknown", "/"
	if r != nil {
		method = r.Method
		if r.URL != nil && r.URL.Path != "" {
			path = r.URL.Path
		}
	}
	path = boundedAuditValue(path, maxAuthAuditPathBytes)
	attempt.User = boundedAuditValue(attempt.User, maxAuthAuditUserBytes)
	fields := []string{
		"[apiserver]",
		"event=auth_attempt",
		auditField("kind", attempt.Kind),
		auditField("result", attempt.Result),
		auditField("src_ip", srcIP),
		auditField("peer_ip", peerIP),
		auditField("entry", peer.Entry),
		auditField("scheme", peer.Scheme),
		auditField("auth_mech", attempt.AuthMech),
	}
	if attempt.User != "" {
		fields = append(fields, auditField("user", attempt.User))
	}
	if attempt.TokenID != "" {
		fields = append(fields, auditField("token_id", attempt.TokenID))
	}
	fields = append(fields,
		auditField("method", method),
		auditField("path", path),
		fmt.Sprintf("status=%d", attempt.Status),
	)
	if attempt.MFA != "" {
		fields = append(fields, auditField("mfa", attempt.MFA))
	}
	writeAuthAuditLine(strings.Join(fields, " "))
}

func suppressAuthAudit(ctx context.Context) context.Context {
	return context.WithValue(ctx, suppressAuthAuditKey{}, true)
}

func markDirectAuthAnomaly(r *http.Request) {
	if state := anomalyStateFromRequest(r); state != nil {
		state.markDirect()
	}
}

func auditField(key, value string) string {
	if value == "" {
		value = "unknown"
	}
	value = boundedAuditValue(value, maxAuditFieldBytes)
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("._:/@+-", r) {
			continue
		}
		return key + "=" + strconv.Quote(value)
	}
	return key + "=" + value
}

func boundedAuditValue(value string, maxBytes int) string {
	const marker = "...[truncated]"
	if maxBytes <= len(marker) || len(value) <= maxBytes {
		return value
	}
	end := maxBytes - len(marker)
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end] + marker
}

func publishRequestAnomaly(r *http.Request, reason string, status int) {
	method, path, ua := "", "", ""
	if r != nil {
		method = r.Method
		if r.URL != nil {
			path = r.URL.Path
		}
		ua = strings.TrimSpace(r.UserAgent())
	}
	publishAPIAnomalyEvent(APIAnomalyEvent{
		When:      time.Now(),
		Source:    "apiserver",
		Reason:    reason,
		Signal:    reason,
		Scope:     "control_plane",
		Count:     1,
		SrcIP:     realIPFromRequest(r),
		Method:    method,
		Path:      path,
		Status:    status,
		UserAgent: ua,
	})
}
