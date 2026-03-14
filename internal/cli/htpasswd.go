package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// RunHtpasswd prints an nginx/Apache-compatible bcrypt line: username:$2y$...
//
// Usage:
//
//	cfm htpasswd <username>
//	cfm htpasswd <username> <password>
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
	raw, err := bcrypt.GenerateFromPassword([]byte(pass), 12)
	if err != nil {
		fmt.Fprintf(os.Stderr, "htpasswd: hash password: %v\n", err)
		return 1
	}
	// golang.org/x/crypto emits $2a$; rewrite to $2y$ which is what
	// nginx and Apache htpasswd tooling conventionally expect.
	hash := strings.Replace(string(raw), "$2a$", "$2y$", 1)
	fmt.Printf("%s:%s\n", user, hash)
	return 0
}
