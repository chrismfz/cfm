// cmd/cfm/auth_cli.go
//
// Embedded auth management CLI for cfm.
// Short-circuits in main() before any config load or server start:
//
//   cfm auth user add -u admin -r admin
//   cfm auth user list
//   cfm auth user passwd -u admin
//   cfm auth user roles -u admin -r admin,viewer
//   cfm auth user deactivate -u user
//   cfm auth user activate   -u user
//   cfm auth user delete -u user --force
//   cfm auth session list
//   cfm auth session purge
//   cfm auth log tail [-n 50] [--ip 1.2.3.4]
//   cfm auth log purge [--days 90]
//   cfm auth --db /other/path.db user list   # override db path

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"cfm/internal/authstore"
	"github.com/chrismfz/goauth"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const defaultAuthDB = "/var/lib/cfm/auth.db"

func runAuthCLI() {
	var dbPath string

	authRoot := &cobra.Command{
		Use:   "auth",
		Short: "Manage cfm web UI users and sessions",
		Long: `Manage users, sessions, and auth audit logs for the cfm-admin web UI.

Use this command when running cfm-admin behind a proxy or in direct-access mode.
It lets you bootstrap and maintain local auth state without starting the web UI.`,
		Example: `  # first-run: create an admin user
  cfm auth user add -u admin -r admin

  # verify users
  cfm auth user list

  # reset an admin password
  cfm auth user passwd -u admin

  # inspect and purge sessions
  cfm auth session list
  cfm auth session purge

  # review auth audit log
  cfm auth log tail -n 50

  # use a non-default auth database
  cfm auth --db /tmp/auth.db user list`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	authRoot.PersistentFlags().StringVar(&dbPath, "db", defaultAuthDB, "Auth database path")

	userCmd := &cobra.Command{Use: "user", Short: "Manage user accounts"}
	userCmd.AddCommand(
		authCmdUserAdd(&dbPath),
		authCmdUserList(&dbPath),
		authCmdUserPasswd(&dbPath),
		authCmdUserRoles(&dbPath),
		authCmdUserActivate(&dbPath),
		authCmdUserDeactivate(&dbPath),
		authCmdUserDelete(&dbPath),
	)

	sessionCmd := &cobra.Command{Use: "session", Short: "Manage sessions"}
	sessionCmd.AddCommand(
		authCmdSessionList(&dbPath),
		authCmdSessionPurge(&dbPath),
	)

	logCmd := &cobra.Command{Use: "log", Short: "View auth audit log"}
	logCmd.AddCommand(
		authCmdLogTail(&dbPath),
		authCmdLogPurge(&dbPath),
	)

	mfaCmd := &cobra.Command{Use: "mfa", Short: "Manage MFA for users"}
	mfaCmd.AddCommand(
		authCmdMFAReset(&dbPath),
		authCmdMFARecoveryRegenerate(&dbPath),
		authCmdMFAStatus(&dbPath),
	)

	authRoot.AddCommand(userCmd, sessionCmd, logCmd, mfaCmd)

	root := &cobra.Command{
		Use:           "cfm",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(authRoot)
	root.SetArgs(os.Args[1:])

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func authOpen(dbPath *string) (*goauth.Manager, error) {
	mgr, err := goauth.New(goauth.Config{
		DBPath:       *dbPath,
		SessionTTL:   8 * time.Hour,
		SecureCookie: false, // irrelevant for CLI
		// CLI must be able to run MFA admin operations without external env wiring.
		MFAEncryptionKey: "cfm-auth-cli-mfa-key-32-bytes!!!",
		MFAIssuer:        "cfm-admin",
	})
	if err != nil {
		return nil, err
	}
	_ = authstore.HardenSQLiteFiles(*dbPath)
	return mgr, nil
}

func authPromptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(syscall.Stdin)) {
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	var pw string
	_, err := fmt.Scanln(&pw)
	return pw, err
}

func authCmdUserAdd(dbPath *string) *cobra.Command {
	var username, password string
	var roles []string
	cmd := &cobra.Command{
		Use:     "add",
		Short:   "Create a new user",
		Example: "  cfm auth user add -u chris -r admin",
		RunE: func(cmd *cobra.Command, args []string) error {
			if password == "" {
				var err error
				password, err = authPromptPassword("Password: ")
				if err != nil {
					return err
				}
				confirm, err := authPromptPassword("Confirm password: ")
				if err != nil {
					return err
				}
				if password != confirm {
					return fmt.Errorf("passwords do not match")
				}
			}
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			if err := m.Users.Create(username, password, roles); err != nil {
				return err
			}
			fmt.Printf("✓ User %q created with roles: [%s]\n", username, strings.Join(roles, ", "))
			return nil
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Password (prompted if omitted)")
	cmd.Flags().StringSliceVarP(&roles, "roles", "r", []string{}, "Comma-separated roles (e.g. admin,viewer)")
	_ = cmd.MarkFlagRequired("username")
	return cmd
}

func authCmdUserList(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all users",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			users, err := m.Users.List()
			if err != nil {
				return err
			}
			if len(users) == 0 {
				fmt.Println("No users.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "ID\tUSERNAME\tROLES\tACTIVE\tCREATED")
			fmt.Fprintln(tw, "--\t--------\t-----\t------\t-------")
			for _, u := range users {
				active := "yes"
				if !u.Active {
					active = "no"
				}
				fmt.Fprintf(tw, "%d\t%s\t[%s]\t%s\t%s\n",
					u.ID, u.Username, strings.Join(u.Roles, ", "),
					active, u.CreatedAt.Format("2006-01-02 15:04"))
			}
			tw.Flush()
			return nil
		},
	}
}

func authCmdUserPasswd(dbPath *string) *cobra.Command {
	var username, password string
	cmd := &cobra.Command{
		Use:   "passwd",
		Short: "Change a user's password",
		RunE: func(cmd *cobra.Command, args []string) error {
			if password == "" {
				var err error
				password, err = authPromptPassword("New password: ")
				if err != nil {
					return err
				}
				confirm, err := authPromptPassword("Confirm: ")
				if err != nil {
					return err
				}
				if password != confirm {
					return fmt.Errorf("passwords do not match")
				}
			}
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			if err := m.Users.SetPassword(username, password); err != nil {
				return err
			}
			fmt.Printf("✓ Password updated for %q\n", username)
			return nil
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "New password (prompted if omitted)")
	_ = cmd.MarkFlagRequired("username")
	return cmd
}

func authCmdUserRoles(dbPath *string) *cobra.Command {
	var username string
	var roles []string
	cmd := &cobra.Command{
		Use:   "roles",
		Short: "Replace role list for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			if err := m.Users.SetRoles(username, roles); err != nil {
				return err
			}
			fmt.Printf("✓ Roles for %q: [%s]\n", username, strings.Join(roles, ", "))
			return nil
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.Flags().StringSliceVarP(&roles, "roles", "r", nil, "New roles (replaces existing)")
	_ = cmd.MarkFlagRequired("username")
	_ = cmd.MarkFlagRequired("roles")
	return cmd
}

func authCmdUserActivate(dbPath *string) *cobra.Command {
	var username string
	cmd := &cobra.Command{
		Use:   "activate",
		Short: "Re-enable a disabled user",
		RunE: func(cmd *cobra.Command, args []string) error {
			return authSetActive(dbPath, username, true)
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	_ = cmd.MarkFlagRequired("username")
	return cmd
}

func authCmdUserDeactivate(dbPath *string) *cobra.Command {
	var username string
	cmd := &cobra.Command{
		Use:   "deactivate",
		Short: "Disable a user account",
		RunE: func(cmd *cobra.Command, args []string) error {
			return authSetActive(dbPath, username, false)
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	_ = cmd.MarkFlagRequired("username")
	return cmd
}

func authSetActive(dbPath *string, username string, active bool) error {
	m, err := authOpen(dbPath)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Users.SetActive(username, active); err != nil {
		return err
	}
	state := "activated"
	if !active {
		state = "deactivated"
	}
	fmt.Printf("✓ User %q %s\n", username, state)
	return nil
}

func authCmdUserDelete(dbPath *string) *cobra.Command {
	var username string
	var force bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Permanently delete a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				fmt.Printf("Pass --force to confirm deletion of %q\n", username)
				return nil
			}
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			if err := m.Users.Delete(username); err != nil {
				return err
			}
			fmt.Printf("✓ User %q deleted\n", username)
			return nil
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.Flags().BoolVar(&force, "force", false, "Confirm permanent deletion")
	_ = cmd.MarkFlagRequired("username")
	return cmd
}

func authCmdSessionList(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List active sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			sessions, err := m.ListSessions()
			if err != nil {
				return err
			}
			if len(sessions) == 0 {
				fmt.Println("No active sessions.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "TOKEN (prefix)\tEXPIRES")
			fmt.Fprintln(tw, "-------------\t-------")
			for _, s := range sessions {
				tok := s.Token
				if len(tok) > 16 {
					tok = tok[:16] + "…"
				}
				fmt.Fprintf(tw, "%s\t%s\n", tok, s.Expiry.Format("2006-01-02 15:04:05"))
			}
			tw.Flush()
			return nil
		},
	}
}

func authCmdSessionPurge(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "purge",
		Short: "Delete all expired sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			n, err := m.PurgeSessions()
			if err != nil {
				return err
			}
			fmt.Printf("✓ Purged %d expired session(s)\n", n)
			return nil
		},
	}
}

func authCmdLogTail(dbPath *string) *cobra.Command {
	var limit int
	var ip string
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show recent login attempts",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			var entries []goauth.AuthLogEntry
			if ip != "" {
				entries, err = m.QueryAuthLogByIP(ip, limit)
			} else {
				entries, err = m.QueryAuthLog(limit)
			}
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Println("No auth log entries.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "TIME\tEVENT\tUSERNAME\tIP\tREASON")
			for _, e := range entries {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					e.Time.Format("2006-01-02 15:04:05"),
					e.Event, e.Username, e.IP, e.Reason)
			}
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().IntVarP(&limit, "count", "n", 50, "Number of entries to show")
	cmd.Flags().StringVar(&ip, "ip", "", "Filter by IP address")
	return cmd
}

func authCmdLogPurge(dbPath *string) *cobra.Command {
	var days int
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Delete auth log entries older than N days",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			n, err := m.PurgeAuthLog(time.Duration(days) * 24 * time.Hour)
			if err != nil {
				return err
			}
			fmt.Printf("✓ Purged %d auth log entries older than %d days\n", n, days)
			return nil
		},
	}
	cmd.Flags().IntVar(&days, "days", 90, "Delete entries older than N days")
	return cmd
}

func authCmdMFAReset(dbPath *string) *cobra.Command {
	var username string
	var audit authAuditFlags
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset all MFA factors and challenges for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := audit.contextFor(username)
			if err != nil {
				return err
			}
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			if err := m.AdminResetMFA(ctx); err != nil {
				return err
			}
			fmt.Printf("✓ MFA reset for %q\n", username)
			return nil
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	_ = cmd.MarkFlagRequired("username")
	audit.bind(cmd)
	return cmd
}

func authCmdMFARecoveryRegenerate(dbPath *string) *cobra.Command {
	var username string
	var count int
	var audit authAuditFlags
	cmd := &cobra.Command{
		Use:   "recovery-regenerate",
		Short: "Regenerate MFA recovery codes for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := audit.contextFor(username)
			if err != nil {
				return err
			}
			if count < 5 {
				return fmt.Errorf("--count must be at least 5")
			}
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			codes, err := m.AdminRotateRecoveryCodes(ctx, count)
			if err != nil {
				return err
			}
			fmt.Printf("✓ Recovery codes regenerated for %q (%d code(s))\n", username, len(codes))
			return nil
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.Flags().IntVar(&count, "count", goauth.DefaultRecoveryCodeCount, "Number of recovery codes to generate (minimum 5)")
	_ = cmd.MarkFlagRequired("username")
	audit.bind(cmd)
	return cmd
}

func authCmdMFAStatus(dbPath *string) *cobra.Command {
	var username string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show MFA status for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()
			u, err := m.Users.GetByUsername(username)
			if err != nil {
				return err
			}
			recovery, err := m.Users.CountRecoveryCodes(username)
			if err != nil {
				return err
			}
			verified := "no"
			if u.TOTPVerifiedAt != nil {
				verified = u.TOTPVerifiedAt.UTC().Format("2006-01-02 15:04:05")
			}
			fmt.Printf("user=%s mfa_enabled=%t mfa_type=%s recovery_codes=%d totp_verified_at=%s\n",
				u.Username, u.MFAEnabled, u.MFAType, recovery, verified)
			return nil
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	_ = cmd.MarkFlagRequired("username")
	return cmd
}

type authAuditFlags struct {
	actor      string
	sourceIP   string
	sourceHost string
	reason     string
	ticket     string
}

func (a *authAuditFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&a.actor, "actor", "", "Audit actor (required, minimum 3 chars)")
	cmd.Flags().StringVar(&a.sourceIP, "source-ip", "", "Audit source IP (required)")
	cmd.Flags().StringVar(&a.sourceHost, "source-host", "", "Audit source host (required, minimum 3 chars)")
	cmd.Flags().StringVar(&a.reason, "reason", "", "Audit reason (required, minimum 8 chars)")
	cmd.Flags().StringVar(&a.ticket, "ticket", "", "Audit ticket/change reference (required, minimum 3 chars)")
	_ = cmd.MarkFlagRequired("actor")
	_ = cmd.MarkFlagRequired("source-ip")
	_ = cmd.MarkFlagRequired("source-host")
	_ = cmd.MarkFlagRequired("reason")
	_ = cmd.MarkFlagRequired("ticket")
}

func (a *authAuditFlags) contextFor(target string) (goauth.AdminAuditContext, error) {
	actor := strings.TrimSpace(a.actor)
	ip := strings.TrimSpace(a.sourceIP)
	host := strings.TrimSpace(a.sourceHost)
	reason := strings.TrimSpace(a.reason)
	ticket := strings.TrimSpace(a.ticket)
	if len(actor) < 3 {
		return goauth.AdminAuditContext{}, fmt.Errorf("--actor must be at least 3 characters")
	}
	if parsed := net.ParseIP(ip); parsed == nil {
		return goauth.AdminAuditContext{}, fmt.Errorf("--source-ip must be a valid IP address")
	}
	if len(host) < 3 {
		return goauth.AdminAuditContext{}, fmt.Errorf("--source-host must be at least 3 characters")
	}
	if len(reason) < 8 {
		return goauth.AdminAuditContext{}, fmt.Errorf("--reason must be at least 8 characters")
	}
	if len(ticket) < 3 {
		return goauth.AdminAuditContext{}, fmt.Errorf("--ticket must be at least 3 characters")
	}
	return goauth.AdminAuditContext{
		Actor:  actor,
		Target: strings.TrimSpace(target),
		IP:     ip,
		Host:   host,
		Reason: reason,
		Ticket: ticket,
	}, nil
}
