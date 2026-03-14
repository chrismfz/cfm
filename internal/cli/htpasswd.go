package cli

import (
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// RunHtpasswd prints an Apache-compatible line: username:{SHA}base64(sha1(password))
//
// Usage:
//   cfm htpasswd <username>
//   cfm htpasswd <username> <password>
//
// If password is omitted, it is read from terminal without echo.
func RunHtpasswd(args []string) int {
	fs := flag.NewFlagSet("htpasswd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rest := fs.Args()
	if len(rest) < 1 || len(rest) > 2 {
		fmt.Fprintln(os.Stderr, "usage: cfm htpasswd <username> [password]")
		return 2
	}

	user := strings.TrimSpace(rest[0])
	if user == "" || strings.Contains(user, ":") {
		fmt.Fprintln(os.Stderr, "htpasswd: invalid username (empty or contains ':')")
		return 2
	}

	var pass string
	if len(rest) == 2 {
		pass = rest[1]
	} else {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "htpasswd: read password: %v\n", err)
			return 1
		}
		pass = string(b)
	}

	if pass == "" {
		fmt.Fprintln(os.Stderr, "htpasswd: empty password not allowed")
		return 2
	}

	d := sha1.Sum([]byte(pass))
	hash := "{SHA}" + base64.StdEncoding.EncodeToString(d[:])
	fmt.Printf("%s:%s\n", user, hash)
	return 0
}
