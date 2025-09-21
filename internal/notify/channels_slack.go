package notify

import (
	"bytes"
	"encoding/json"
	"net/http"
)

type slackChannel struct {
	name      string
	webhook   string
	mention   string
	username  string
	iconEmoji string
}

func (c *slackChannel) Name() string { return c.name }

func (c *slackChannel) Send(ev Event, subj, body string) error {
	payload := map[string]interface{}{
		"text": "*" + subj + "*\n```\n" + body + "\n```",
	}
	if c.mention != "" { payload["text"] = c.mention + " " + payload["text"].(string) }
	if c.username != "" { payload["username"] = c.username }
	if c.iconEmoji != "" { payload["icon_emoji"] = c.iconEmoji }
	b, _ := json.Marshal(payload)
	_, err := http.Post(c.webhook, "application/json", bytes.NewReader(b))
	return err
}
