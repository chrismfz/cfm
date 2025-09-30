package notify

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"context"
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
	addr := c.host
	host, _, err := net.SplitHostPort(addr)
	if err != nil { return err }

	auth := smtp.PlainAuth("", c.user, c.pass, host)
	msg := "From: " + c.from + "\r\n" +
		"To: " + strings.Join(c.to, ", ") + "\r\n" +
		fmt.Sprintf("Subject: %s\r\n", subj) +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body

	if c.starttls {
               // Dial with timeout to avoid hangs
               d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
               conn, err := d.DialContext(context.Background(), "tcp", addr)
               if err != nil { return err }

               client, err := smtp.NewClient(conn, host)
               if err != nil {
                       _ = conn.Close()
                       return err
               }
               // Ensure connection closed on all paths
               defer func() { _ = client.Close() }()

               tlsConf := &tls.Config{
                       ServerName:         host,
                       InsecureSkipVerify: c.insecure, // #nosec G402 - allow only when user explicitly sets insecure
               }
               if err := client.StartTLS(tlsConf); err != nil {
                       // attempt a clean quit but prefer the original error
                       _ = client.Quit()
                       return err
               }
               if c.user != "" {
                       if err := client.Auth(auth); err != nil {
                               _ = client.Quit()
                               return err
                       }
               }
               if err := client.Mail(c.from); err != nil {
                       _ = client.Quit()
                       return err
               }
               for _, rcpt := range c.to {
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
               // write body and handle errors
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
               // return any quit error (none expected in success path)
               if err := client.Quit(); err != nil { return err }
               return nil
	}

       // Non-STARTTLS path
       return smtp.SendMail(addr, auth, c.from, c.to, []byte(msg))
}
