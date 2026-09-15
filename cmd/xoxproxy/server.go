package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xoxproxy/xoxproxy/internal/analytics"
	"github.com/xoxproxy/xoxproxy/internal/api"
	"github.com/xoxproxy/xoxproxy/internal/audit"
	"github.com/xoxproxy/xoxproxy/internal/auth"
	"github.com/xoxproxy/xoxproxy/internal/buildinfo"
	"github.com/xoxproxy/xoxproxy/internal/config"
	"github.com/xoxproxy/xoxproxy/internal/logging"
	"github.com/xoxproxy/xoxproxy/internal/store/sqlite"
	"github.com/xoxproxy/xoxproxy/internal/system"
	"github.com/xoxproxy/xoxproxy/internal/users"
)

// expirySweepInterval is the expiration reconciliation cadence. One minute
// bounds the window between an expiry passing and the status flip; the
// state builder excludes past-expiry users immediately regardless, so this
// is a reporting/audit cadence, not a security deadline.
const expirySweepInterval = time.Minute

// runExpirySweep periodically expires past-expiry users until the context
// is cancelled. Single goroutine, bounded work per tick (one UPDATE),
// failures logged and retried on the next tick.
func runExpirySweep(ctx context.Context, logger *slog.Logger, svc *users.Service) {
	ticker := time.NewTicker(expirySweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := svc.SweepExpired(ctx)
			if err != nil {
				logger.Warn("expiry sweep failed", slog.String("error", err.Error()))
				continue
			}
			if n > 0 {
				logger.Info("expired users deactivated", slog.Int64("count", n))
			}
		}
	}
}

// shutdownTimeout bounds graceful shutdown: in-flight requests finish or
// are cut off, but the process never hangs on a stuck connection.
const shutdownTimeout = 10 * time.Second

// serverLimits are conservative defaults for an internet-facing control
// plane on a small VPS.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 1 << 20
)

// configFlag registers the -config flag with the standard default chain:
// explicit flag > $XOXPROXY_CONFIG > /etc/xoxproxy/config.toml.
func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", os.Getenv(config.EnvOverride),
		"path to configuration file (default $"+config.EnvOverride+" or "+config.DefaultPath+")")
}

func resolveConfigPath(fs *flag.FlagSet, p *string) string {
	if *p == "" {
		return config.DefaultPath
	}
	return *p
}

func runServer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(resolveConfigPath(fs, cfgPath))
	if err != nil {
		return err
	}
	logger, err := logging.Default(cfg.Log.Level)
	if err != nil {
		return err
	}

	// Database: open, migrate, and expose liveness through readiness.
	db, err := sqlite.Open(ctx, cfg.Database.Path)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	// Services.
	auditSvc := audit.New(logger, sqlite.NewAuditRepository(db))
	authSvc, err := auth.New(logger,
		sqlite.NewAdminRepository(db),
		sqlite.NewSessionRepository(db),
		auditSvc, auth.Options{})
	if err != nil {
		return err
	}
	usersSvc := users.NewService(logger,
		sqlite.NewUserRepository(db),
		sqlite.NewCredentialRepository(db),
		auditSvc)

	// Deploy pipeline: user mutations and the expiry sweep trigger
	// automatic, coalesced redeploys; a startup reconcile brings the
	// on-disk config in line with the store (the engine may have
	// restarted with an older config).
	deploySvc, err := buildDeployService(ctx, cfg, db, logger)
	if err != nil {
		return err
	}
	usersSvc.SetStateChangeHook(deploySvc.Trigger)
	go deploySvc.Start(ctx)
	go func() {
		if _, err := deploySvc.DeployNow(ctx, "system", "startup"); err != nil {
			logger.Error("startup deploy failed", slog.String("error", err.Error()))
		}
	}()

	// Secure cookies whenever the dashboard is served over HTTPS; an
	// HTTP-only IP deployment is an explicit operator decision with a
	// documented risk (see DESIGN-REVIEW S4).
	secureCookies := strings.HasPrefix(cfg.Server.PublicBaseURL, "https://")

	// Analytics: tail the engine traffic log off the data path, fold
	// records into capped in-memory aggregates, flush to SQLite in one
	// transaction per interval. Started before the API so the routes have
	// a service; it tails until the context ends and flushes on shutdown.
	flushEvery, err := cfg.AnalyticsFlush()
	if err != nil {
		return err
	}
	ringSize := 0
	if cfg.Analytics.Verbosity == config.VerbosityDetailed {
		ringSize = cfg.Analytics.RecentConnections
	}
	analyticsRepo := sqlite.NewAnalyticsRepository(db)
	resume, err := analyticsRepo.LoadCursor(ctx)
	if err != nil {
		return fmt.Errorf("load analytics cursor: %w", err)
	}
	sysProvider := system.NewLocal(cfg.Database.Path)
	analyticsSvc := analytics.NewService(logger,
		analyticsRepo,
		sqlite.NewUserRepository(db),
		resume,
		analytics.Options{
			LogPath:                engineSettingsFrom(cfg).LogFile,
			FlushInterval:          flushEvery,
			QueueSize:              cfg.Analytics.QueueSize,
			RingSize:               ringSize,
			MaxDestinationsPerUser: cfg.Analytics.MaxDestinationsPerUser,
			RetentionDays:          cfg.Analytics.RetentionDays,
		})

	apiServer := api.NewServer(logger, authSvc, auditSvc, usersSvc, deploySvc, analyticsSvc, system.NewLocal(cfg.Database.Path), api.Options{
		SecureCookies: secureCookies,
	})
	apiServer.AddReadinessCheck("database", db.Ping)

	// Deployment posture for the Server page: proxy ports, TLS scheme,
	// and the public-IP source. The engine traffic-log path feeds the
	// Logs page.
	apiServer.SetDeploymentInfo(api.DeploymentInfo{
		HTTPPort:   cfg.Proxy.HTTPPort,
		SOCKS5Port: cfg.Proxy.SOCKS5Port,
		TLS:        strings.HasPrefix(cfg.Server.PublicBaseURL, "https://"),
		PublicIP:   sysProvider.PublicIP,
	})
	apiServer.SetTrafficLogPath(engineSettingsFrom(cfg).LogFile)

	// Quota resets zero the usage ledger through the analytics repository.
	usersSvc.SetUsageResetter(sqlite.NewAnalyticsRepository(db))

	analyticsDone := analyticsSvc.Done()
	go analyticsSvc.Start(ctx)

	// Expiration reconciliation: a bounded, cancellable job that flips
	// past-expiry users to "expired". It must not depend on the dashboard
	// being open; the desired-state builder independently excludes
	// past-expiry users, so the sweep is for accurate status/audit rather
	// than for correctness of access denial.
	go runExpirySweep(ctx, logger, usersSvc)

	httpSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("control plane listening",
			slog.String("addr", cfg.Server.Listen),
			slog.String("version", buildinfo.Version),
		)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("listen %s: %w", cfg.Server.Listen, err)
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	// The analytics final flush has its own deadline; the wait is bounded
	// so a stuck database cannot hang shutdown. Unflushed records are not
	// lost — the persisted cursor precedes them.
	select {
	case <-analyticsDone:
	case <-time.After(shutdownTimeout):
		logger.Warn("analytics final flush timed out; records will be re-read on next start")
	}
	logger.Info("stopped")
	return nil
}
