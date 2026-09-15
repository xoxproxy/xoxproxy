package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/config"
	"github.com/xoxproxy/xoxproxy/internal/deploy"
	"github.com/xoxproxy/xoxproxy/internal/engine/threeproxy"
	"github.com/xoxproxy/xoxproxy/internal/logging"
	"github.com/xoxproxy/xoxproxy/internal/store/sqlite"
)

// engineSettingsFrom derives the 3proxy deployer settings from the
// control-plane configuration. All engine files live under the engine
// config dir, matching the layout the installer (Phase 9) provisions.
func engineSettingsFrom(cfg config.Config) threeproxy.Settings {
	dir := cfg.Engine.ConfigDir
	return threeproxy.Settings{
		ConfigFile:  dir + "/3proxy.cfg",
		PidFile:     dir + "/3proxy.pid",
		CounterFile: dir + "/3proxy.3cf",
		LogFile:     dir + "/traffic.log",
		HTTPPort:    cfg.Proxy.HTTPPort,
		SOCKS5Port:  cfg.Proxy.SOCKS5Port,
	}
}

// buildDeployService wires the deploy pipeline over an open database: the
// real 3proxy deployer, the user-store state source, and the version
// history. Shared by the server and the CLI so both deploy identically.
func buildDeployService(ctx context.Context, cfg config.Config, db *sqlite.DB, logger *slog.Logger) (*deploy.Service, error) {
	deployer, err := threeproxy.NewDeployer(engineSettingsFrom(cfg), logger)
	if err != nil {
		return nil, err
	}
	auditSvc := audit.New(logger, sqlite.NewAuditRepository(db))
	return deploy.NewService(logger,
		deploy.NewThreeproxy(deployer),
		deploy.UsersStateSource(sqlite.NewUserRepository(db)),
		sqlite.NewConfigVersionRepository(db),
		auditSvc), nil
}

// runDeploy implements "xoxproxy deploy": synchronously reconcile the
// engine config with the store (render, install, reload, record). This is
// the operator's manual version of what every mutation does automatically.
func runDeploy(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	reason := fs.String("reason", "manual", "reason recorded in the config history")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(resolveConfigPath(fs, cfgPath))
	if err != nil {
		return err
	}
	logger, err := logging.New(os.Stderr, cfg.Log.Level)
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

	svc, err := buildDeployService(ctx, cfg, db, logger)
	if err != nil {
		return err
	}
	res, err := svc.DeployNow(ctx, "cli", *reason)
	if err != nil {
		return err
	}
	switch {
	case res.RolledBack:
		fmt.Fprintln(os.Stderr, "Deploy rolled back: the engine did not survive the reload; previous config restored.")
	case !res.Changed:
		fmt.Fprintln(os.Stderr, "Config already up to date; nothing to do.")
	case res.Reloaded:
		fmt.Fprintf(os.Stderr, "Config deployed and engine reloaded (checksum %s).\n", res.Checksum)
	default:
		fmt.Fprintf(os.Stderr, "Config written; engine not running, it will apply on next start (checksum %s).\n", res.Checksum)
	}
	return nil
}
