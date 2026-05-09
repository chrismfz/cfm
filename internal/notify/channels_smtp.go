package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

type smtpChannel struct {
	name     string
	host     string // host:port
	user     string
	pass     string
	from     string
	to       []string
	starttls bool
	insecure bool
}

func (c *smtpChannel) Name() string { return c.name }

func (c *smtpChannel) Send(ev Event, subj, body string) error {
	from, err := sanitizeAddress(c.from)
	if err != nil {
		return err
	}
	to := make([]string, 0, len(c.to))
	for _, rcpt := range c.to {
		addr, aerr := sanitizeAddress(rcpt)
		if aerr != nil {
			return aerr
		}
		to = append(to, addr)
	}
	safeSubj, err := sanitizeHeaderValue(subj)
	if err != nil {
		return err
	}

	addr := c.host
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	auth := smtp.PlainAuth("", c.user, c.pass, host)
	// Header injection is structurally prevented here even though `body` may
	// carry attacker-influenced bytes (template-rendered Event fields). All
	// header inputs are CRLF-rejected upstream — `from`/`to` via
	// sanitizeAddress, `subj` via sanitizeHeaderValue — and `body` is
	// concatenated AFTER the literal "\r\n\r\n" header/body separator. By
	// RFC 5322 every byte after that separator is parsed as message body,
	// not headers; CRLF inside `body` is legitimate body content. The
	// CodeQL "Email content injection" alerts (#605, #606 in the
	// 2026-05-09 triage) are FPs against this construction.
	msg := "From: " + from + "\r\n" +
		"To: " + strings.Join(to, ", ") + "\r\n" +
		fmt.Sprintf("Subject: %s\r\n", safeSubj) +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body

	if c.starttls {
		d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		conn, err := d.DialContext(context.Background(), "tcp", addr)
		if err != nil {
			return err
		}

		client, err := smtp.NewClient(conn, host)
		if err != nil {
			_ = conn.Close()
			return err
		}
		defer func() { _ = client.Close() }()

		tlsConf := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: c.insecure, // #nosec G402 - allow only when user explicitly sets insecure
		}
		if err := client.StartTLS(tlsConf); err != nil {
			_ = client.Quit()
			return err
		}
		if c.user != "" {
			if err := client.Auth(auth); err != nil {
				_ = client.Quit()
				return err
			}
		}
		if err := client.Mail(from); err != nil {
			_ = client.Quit()
			return err
		}
		for _, rcpt := range to {
			if err := client.Rcpt(rcpt); err != nil {
				_ = client.Quit()
				return err
			}
		}
		w, err := client.Data()
		if err != nil {
			_ = client.Quit()
			return err
		}
		n, werr := w.Write([]byte(msg))
		if werr != nil {
			_ = w.Close()
			_ = client.Quit()
			return werr
		}
		if n < len(msg) {
			_ = w.Close()
			_ = client.Quit()
			return fmt.Errorf("smtp: short write: wrote %d of %d bytes", n, len(msg))
		}
		if err := w.Close(); err != nil {
			_ = client.Quit()
			return err
		}
		if err := client.Quit(); err != nil {
			return err
		}
		return nil
	}

	return smtp.SendMail(addr, auth, from, to, []byte(msg))
}

func sanitizeHeaderValue(v string) (string, error) {
	if strings.ContainsAny(v, "\r\n") {
		return "", fmt.Errorf("smtp header values cannot contain newlines")
	}
	return strings.TrimSpace(v), nil
}

func sanitizeAddress(raw string) (string, error) {
	if strings.ContainsAny(raw, "\r\n") {
		return "", fmt.Errorf("smtp address cannot contain newlines")
	}
	parsed, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid smtp address %q: %w", raw, err)
	}
	return parsed.Address, nil
}
