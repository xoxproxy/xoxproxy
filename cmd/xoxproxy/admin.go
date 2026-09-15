package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/auth"
	"github.com/xoxproxy/xoxproxy/internal/config"
	"github.com/xoxproxy/xoxproxy/internal/logging"
	"github.com/xoxproxy/xoxproxy/internal/store/sqlite"
)

// runAdmin dispatches "xoxproxy admin <subcommand>". These commands run on
// the host itself (installer or operator shell) and authenticate by
// machine access rather than a dashboard session — every invocation is
// audited with actor "cli".
func runAdmin(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(`admin: no subcommand given
  xoxproxy admin create         -username NAME [-generate]
  xoxproxy admin reset-password -username NAME [-generate]`)
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "create":
		return adminCredentialOp(ctx, "create", rest)
	case "reset-password":
		return adminCredentialOp(ctx, "reset-password", rest)
	default:
		return fmt.Errorf("admin: unknown subcommand %q", sub)
	}
}

// adminCredentialOp implements both credential operations: they differ only
// in the auth.Service call at the end.
func adminCredentialOp(ctx context.Context, op string, args []string) error {
	fs := flag.NewFlagSet("admin "+op, flag.ContinueOnError)
	cfgPath := configFlag(fs)
	username := fs.String("username", "", "administrator username")
	generate := fs.Bool("generate", false, "generate a strong password and print it once")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("admin %s: -username is required", op)
	}
	if len(*username) > 64 || !validUsername(*username) {
		return fmt.Errorf("admin %s: username must be 1-64 characters of letters, digits, dots, hyphens, underscores", op)
	}

	cfg, err := config.Load(resolveConfigPath(fs, cfgPath))
	if err != nil {
		return err
	}
	db, err := sqlite.Open(ctx, cfg.Database.Path)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	password, err := obtainPassword(*generate)
	if err != nil {
		return err
	}

	svc, err := newAdminService(cfg, db)
	if err != nil {
		return err
	}

	switch op {
	case "create":
		if _, err := svc.CreateAccount(ctx, *username, password, "cli", ""); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Created administrator %q.\n", *username)
	case "reset-password":
		if err := svc.ResetPassword(ctx, *username, password, "cli", ""); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Password reset for %q; all dashboard sessions revoked.\n", *username)
	}
	if *generate {
		// The generated password is printed exactly once, to the terminal
		// that ran the command. It is never logged or stored in plaintext.
		fmt.Fprintf(os.Stderr, "Password: %s\n", password)
	}
	return nil
}

// newAdminService builds an auth.Service with a logger to stderr so CLI
// output (including passwords on stdout) stays clean.
func newAdminService(cfg config.Config, db *sqlite.DB) (*auth.Service, error) {
	logger, err := logging.New(os.Stderr, cfg.Log.Level)
	if err != nil {
		return nil, err
	}
	auditSvc := audit.New(logger, sqlite.NewAuditRepository(db))
	return auth.New(logger,
		sqlite.NewAdminRepository(db),
		sqlite.NewSessionRepository(db),
		auditSvc, auth.Options{})
}

// obtainPassword either generates a strong password or prompts for one
// (twice, to catch typos; hidden input on a terminal).
func obtainPassword(generate bool) (string, error) {
	if generate {
		return auth.GeneratePassword(), nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	first, err := readPassword()
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	second, err := readPassword()
	if err != nil {
		return "", err
	}
	fmt.Fprintln(os.Stderr)
	if first != second {
		return "", fmt.Errorf("passwords do not match")
	}
	if first == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	return first, nil
}

// readPassword reads a password from the terminal without echo, or from
// stdin when input is piped (for scripted use with care).
func readPassword() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func validUsername(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return len(s) > 0
}
