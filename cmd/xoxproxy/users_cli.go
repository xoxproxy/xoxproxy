package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/config"
	"github.com/xoxproxy/xoxproxy/internal/logging"
	"github.com/xoxproxy/xoxproxy/internal/store"
	"github.com/xoxproxy/xoxproxy/internal/store/sqlite"
	"github.com/xoxproxy/xoxproxy/internal/users"
)

// runUsers dispatches "xoxproxy users <subcommand>". Like `admin`, these
// run on the host and authenticate by machine access; every invocation is
// audited with actor "cli". They share the exact service layer the HTTP
// API uses — no duplicated business logic.
func runUsers(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(`users: no subcommand given
  xoxproxy users list            [-status active|disabled|expired]
  xoxproxy users create          -username NAME [-password|-generate] [-protocols http,socks5] [-expires DURATION]
  xoxproxy users disable         -username NAME
  xoxproxy users enable          -username NAME
  xoxproxy users rotate-password -username NAME [-password|-generate]`)
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "list":
		return usersList(ctx, rest)
	case "create":
		return usersCreate(ctx, rest)
	case "disable":
		return usersSetStatus(ctx, "disable", rest)
	case "enable":
		return usersSetStatus(ctx, "enable", rest)
	case "rotate-password":
		return usersRotate(ctx, rest)
	default:
		return fmt.Errorf("users: unknown subcommand %q", sub)
	}
}

// usersService opens the configured database and builds the shared users
// service with a stderr logger (stdout stays clean for data output). The
// caller owns closing the database handle; the config is returned so
// mutating commands can run the deploy pipeline afterwards.
func usersService(ctx context.Context, cfgPath string) (*users.Service, *sqlite.DB, config.Config, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, config.Config{}, err
	}
	db, err := sqlite.Open(ctx, cfg.Database.Path)
	if err != nil {
		return nil, nil, config.Config{}, err
	}
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		return nil, nil, config.Config{}, fmt.Errorf("migrate database: %w", err)
	}
	logger, err := logging.New(os.Stderr, cfg.Log.Level)
	if err != nil {
		db.Close()
		return nil, nil, config.Config{}, err
	}
	auditSvc := audit.New(logger, sqlite.NewAuditRepository(db))
	svc := users.NewService(logger,
		sqlite.NewUserRepository(db),
		sqlite.NewCredentialRepository(db),
		auditSvc)
	return svc, db, cfg, nil
}

// deployAfterChange runs the deploy pipeline synchronously after a CLI
// mutation, so the data plane reflects the change before the command
// returns. A failure leaves the mutation in place (the store is the
// source of truth; the server's startup reconcile will converge) but is
// reported.
func deployAfterChange(ctx context.Context, cfg config.Config, db *sqlite.DB, reason string) error {
	logger, err := logging.New(os.Stderr, cfg.Log.Level)
	if err != nil {
		return err
	}
	svc, err := buildDeployService(ctx, cfg, db, logger)
	if err != nil {
		return err
	}
	_, err = svc.DeployNow(ctx, "cli", reason)
	return err
}

func usersList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("users list", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	status := fs.String("status", "", "filter by status (active, disabled, expired)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *status != "" {
		switch *status {
		case store.UserActive, store.UserDisabled, store.UserExpired:
		default:
			return fmt.Errorf("users list: -status must be active, disabled or expired")
		}
	}

	svc, db, _, err := usersService(ctx, resolveConfigPath(fs, cfgPath))
	if err != nil {
		return err
	}
	defer db.Close()

	list, err := svc.List(ctx, store.UserFilter{Status: *status, Limit: 500})
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no users")
		return nil
	}
	fmt.Printf("%-24s %-9s %-11s %-12s %s\n", "USERNAME", "STATUS", "PROTOCOLS", "EXPIRES", "ID")
	for _, u := range list {
		expires := "never"
		if u.ExpiresAt != nil {
			expires = u.ExpiresAt.Local().Format(time.RFC3339)
		}
		fmt.Printf("%-24s %-9s %-11s %-12s %d\n",
			u.Username, u.Status, strings.Join(u.AllowedProtocols, ","), expires, u.ID)
	}
	return nil
}

func usersCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("users create", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	username := fs.String("username", "", "proxy username")
	generate := fs.Bool("generate", true, "generate a strong password (default true)")
	password := fs.String("password", "", "use this password instead of generating one")
	protocols := fs.String("protocols", "http,socks5", "comma-separated: http, socks5")
	expires := fs.String("expires", "", "expire after a Go duration (e.g. 24h, 30d as 720h); empty = never")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("users create: -username is required")
	}
	protos, err := parseProtocols(*protocols)
	if err != nil {
		return err
	}
	var expiresAt *time.Time
	if *expires != "" {
		d, err := time.ParseDuration(*expires)
		if err != nil || d <= 0 {
			return fmt.Errorf("users create: -expires must be a positive Go duration (e.g. 24h, 720h)")
		}
		t := time.Now().UTC().Add(d)
		expiresAt = &t
	}

	svc, db, cfg, err := usersService(ctx, resolveConfigPath(fs, cfgPath))
	if err != nil {
		return err
	}
	defer db.Close()

	chosen := ""
	if !*generate {
		if *password == "" {
			var err error
			chosen, err = readPassword()
			if err != nil {
				return err
			}
		} else {
			chosen = *password
		}
	}

	user, oneTime, err := svc.Create(ctx, users.CreateInput{
		Username:  *username,
		Password:  chosen,
		Protocols: protos,
		ExpiresAt: expiresAt,
	}, users.Actor{Name: "cli"})
	if err != nil {
		return err
	}
	if err := deployAfterChange(ctx, cfg, db, "user.create:"+user.Username); err != nil {
		fmt.Fprintf(os.Stderr, "User created, but deploying the engine config failed: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "Created user %q (id %d, status %s).\n", user.Username, user.ID, user.Status)
	// The password is printed exactly once, to the terminal that ran the
	// command. It is never logged or stored in plaintext.
	fmt.Fprintf(os.Stderr, "Password: %s\n", oneTime)
	return nil
}

func usersSetStatus(ctx context.Context, op string, args []string) error {
	fs := flag.NewFlagSet("users "+op, flag.ContinueOnError)
	cfgPath := configFlag(fs)
	username := fs.String("username", "", "proxy username")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("users %s: -username is required", op)
	}

	svc, db, cfg, err := usersService(ctx, resolveConfigPath(fs, cfgPath))
	if err != nil {
		return err
	}
	defer db.Close()

	user, err := svc.List(ctx, store.UserFilter{Username: *username, Limit: 1})
	if err != nil {
		return err
	}
	if len(user) == 0 {
		return fmt.Errorf("users %s: no user named %q", op, *username)
	}
	actor := users.Actor{Name: "cli"}
	if op == "disable" {
		_, err = svc.Disable(ctx, user[0].ID, user[0].Version, actor)
	} else {
		_, err = svc.Enable(ctx, user[0].ID, user[0].Version, actor)
	}
	if err != nil {
		return err
	}
	if err := deployAfterChange(ctx, cfg, db, "user."+op+":"+*username); err != nil {
		fmt.Fprintf(os.Stderr, "Status changed, but deploying the engine config failed: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "User %q %sd.\n", *username, op)
	return nil
}

func usersRotate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("users rotate-password", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	username := fs.String("username", "", "proxy username")
	generate := fs.Bool("generate", true, "generate a strong password (default true)")
	password := fs.String("password", "", "use this password instead of generating one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("users rotate-password: -username is required")
	}

	svc, db, cfg, err := usersService(ctx, resolveConfigPath(fs, cfgPath))
	if err != nil {
		return err
	}
	defer db.Close()

	found, err := svc.List(ctx, store.UserFilter{Username: *username, Limit: 1})
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return fmt.Errorf("users rotate-password: no user named %q", *username)
	}

	chosen := ""
	if !*generate {
		if *password == "" {
			chosen, err = readPassword()
			if err != nil {
				return err
			}
		} else {
			chosen = *password
		}
	}

	_, oneTime, err := svc.RotateCredentials(ctx, found[0].ID, chosen, users.Actor{Name: "cli"})
	if err != nil {
		return err
	}
	if err := deployAfterChange(ctx, cfg, db, "user.rotate_credentials:"+*username); err != nil {
		fmt.Fprintf(os.Stderr, "Password rotated, but deploying the engine config failed: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "Password rotated for %q; the old credential is revoked.\n", *username)
	fmt.Fprintf(os.Stderr, "Password: %s\n", oneTime)
	return nil
}

func parseProtocols(s string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no protocols given")
	}
	return out, nil
}
