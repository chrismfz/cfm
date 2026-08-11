package setinventory

import (
	"strings"

	"cfm/internal/blocklists"
	"cfm/internal/firewall/feedutil"
)

func BuildSetNames(feeds []blocklists.Feed) map[string]string {
	setNames := map[string]string{
		"block_v4":       "block_v4",
		"block_v6":       "block_v6",
		"block_v4_nets":  "block_v4_nets",
		"block_v6_nets":  "block_v6_nets",
		"allow_v4":       "allow_v4",
		"allow_v6":       "allow_v6",
		"allow_v4_nets":  "allow_v4_nets",
		"allow_v6_nets":  "allow_v6_nets",
		"ignore_v4":      "ignore_v4",
		"ignore_v6":      "ignore_v6",
		"ignore_v4_nets": "ignore_v4_nets",
		"ignore_v6_nets": "ignore_v6_nets",
		"allow_dyn_v4":   "allow_dyn_v4",
		"allow_dyn_v6":   "allow_dyn_v6",
	}
	for _, f := range feeds {
		key := feedutil.SanitizeFeedName(f.Name)
		base := "block_ext"
		if f.Type == blocklists.TypeAllow {
			base = "allow_ext"
		}
		for _, suffix := range []string{"v4_hosts", "v4_nets", "v6_hosts", "v6_nets"} {
			name := base + "_" + suffix + "_" + key
			setNames[name] = name
		}
	}
	return setNames
}

func ClassifySet(name string) (action, family, scope, feed string, ok bool) {
	switch name {
	case "allow_v4", "allow_v4_nets":
		return "ALLOW", "v4", "manual", "", true
	case "allow_v6", "allow_v6_nets":
		return "ALLOW", "v6", "manual", "", true
	case "allow_dyn_v4":
		return "ALLOW", "v4", "dyn", "", true
	case "allow_dyn_v6":
		return "ALLOW", "v6", "dyn", "", true
	case "block_v4", "block_v4_nets":
		return "BLOCK", "v4", "manual", "", true
	case "block_v6", "block_v6_nets":
		return "BLOCK", "v6", "manual", "", true
	}

	if strings.HasPrefix(name, "allow_ext_") || strings.HasPrefix(name, "block_ext_") {
		parts := strings.Split(name, "_")
		if len(parts) >= 5 {
			action = strings.ToUpper(parts[0])
			if parts[2] == "v4" || parts[2] == "v6" {
				family = parts[2]
			}
			if parts[3] == "hosts" || parts[3] == "nets" {
				scope = parts[3]
			}
			feed = strings.Join(parts[4:], "_")
			return action, family, scope, feed, true
		}
	}
	return "", "", "", "", false
}
