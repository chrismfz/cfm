package notify

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type sendmailChannel struct {
	name string
	path string
	from string
	to   []string
}

func (c *sendmailChannel) Name() string { return c.name }

func (c *sendmailChannel) Send(ev Event, subj, body string) error {
	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: %s\r\n", c.from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(c.to, ", ")))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subj))
	msg.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n")
	msg.WriteString(body)
	cmd := exec.Command(c.path, "-t")
	cmd.Stdin = &msg
	return cmd.Run()
}
