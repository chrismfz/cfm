package notify

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
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
	addr := c.host
	host, _, err := net.SplitHostPort(addr)
	if err != nil { return err }

	auth := smtp.PlainAuth("", c.user, c.pass, host)
	msg := "From: " + c.from + "\r\n" +
		"To: " + strings.Join(c.to, ", ") + "\r\n" +
		fmt.Sprintf("Subject: %s\r\n", subj) +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body

	if c.starttls {
		conn, err := net.Dial("tcp", addr); if err != nil { return err }
		client, err := smtp.NewClient(conn, host); if err != nil { return err }
		tlsConf := &tls.Config{ServerName: host, InsecureSkipVerify: c.insecure}
		if err := client.StartTLS(tlsConf); err != nil { client.Quit(); return err }
		if c.user != "" {
			if err := client.Auth(auth); err != nil { client.Quit(); return err }
		}
		if err := client.Mail(c.from); err != nil { client.Quit(); return err }
		for _, rcpt := range c.to { if err := client.Rcpt(rcpt); err != nil { client.Quit(); return err } }
		w, err := client.Data(); if err != nil { client.Quit(); return err }
		_, _ = w.Write([]byte(msg))
		if err := w.Close(); err != nil { client.Quit(); return err }
		return client.Quit()
	}
	return smtp.SendMail(addr, auth, c.from, c.to, []byte(msg))
}
