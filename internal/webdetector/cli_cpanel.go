// internal/webdetector/cli_cpanel.go
package webdetector

import (
	"encoding/json"
	"fmt"
	"os"
)

// RunCpanelUserInfo is called by "cfm cpanel user-info <user>"
func RunCpanelUserInfo(user string) {
	if user == "" {
		fmt.Fprintln(os.Stderr, "usage: cfm cpanel user-info <cpanel-username>")
		os.Exit(1)
	}

	if !cpanelUserExists(user) {
		fmt.Fprintf(os.Stderr, "user %q not found under /var/cpanel/users/\n", user)
		os.Exit(1)
	}

	info := cpanelUserInfo{User: user}
	info.Domains = cpanelDomainsForUser(user)
	info.DBUsers, info.Databases = cpanelDBInfoForUser(user)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}
