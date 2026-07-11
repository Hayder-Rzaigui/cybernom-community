// Command cybernom is the CyberNom server: it runs the HTTP API, the feed
// ingestion engine, and (if enabled) the Microsoft Graph collector as a
// single process with coordinated graceful shutdown.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hayderrzaigui/cybernom/internal/api"
	"github.com/hayderrzaigui/cybernom/internal/auth"
	"github.com/hayderrzaigui/cybernom/internal/config"
	"github.com/hayderrzaigui/cybernom/internal/graph"
	"github.com/hayderrzaigui/cybernom/internal/ingester"
	"github.com/hayderrzaigui/cybernom/internal/logger"
	"github.com/hayderrzaigui/cybernom/internal/notifier"
	"github.com/hayderrzaigui/cybernom/internal/storage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "cybernom: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config/config.yaml", "path to config.yaml")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	logPretty := flag.Bool("log-pretty", false, "use human-readable text logs instead of JSON")
	initAdmin := flag.Bool("init-admin", false, "interactively create an admin user and exit, instead of starting the server")
	flag.Parse()

	// -init-admin replaces the old README-documented workflow of manually
	// bcrypt-hashing a password and hand-writing an INSERT statement. It
	// exits after creating the user rather than falling through to server
	// startup, so it's safe to run against a live config without also
	// spinning up the ingester/HTTP server.
	if *initAdmin {
		return runInitAdmin(*configPath)
	}

	log := logger.New(*logLevel, *logPretty)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	log.Info("configuration loaded", "feeds", len(cfg.Feeds), "keywords", len(cfg.Keywords), "graph_enabled", cfg.Graph.Enabled)

	// Root context cancelled on SIGINT/SIGTERM, driving graceful shutdown
	// of every subsystem below.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := storage.Open(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	router := notifier.NewRouter(log)
	if err := wireNotifications(router, cfg); err != nil {
		return fmt.Errorf("wiring notifications: %w", err)
	}
	store = store.WithRouter(router)

	// Encrypted secrets vault + SIEM forwarding are Enterprise-only
	// features (ENTERPRISE.md sections 3-4). setupSecurityExtensions has
	// one implementation per edition:
	//   - setup_enterprise.go (build tag enterprise): requires
	//     CYBERNOM_MASTER_ENCRYPTION_KEY at startup (hard failure if
	//     missing — silently degrading to plaintext secrets would be far
	//     worse than refusing to start) and wires up real SIEM forwarding
	//     from CYBERNOM_SIEM_* env vars.
	//   - setup_community.go (build tag !enterprise): does not require or
	//     read any of those env vars, and returns a no-op forwarder. There
	//     is nothing in Community that ever needs the vault, so this
	//     build never requires an encryption key to start.
	vault, siemForwarder, err := setupSecurityExtensions(log)
	if err != nil {
		return fmt.Errorf("initializing security extensions: %w", err)
	}
	if siemForwarder != nil {
		defer siemForwarder.Close()
	}
	store = store.WithSIEMForwarder(siemForwarder)

	tokenIssuer, err := auth.NewTokenIssuer(
		os.Getenv(cfg.Auth.JWTSigningKeyEnvVar),
		cfg.Auth.AccessTokenTTL,
		cfg.Auth.RefreshTokenTTL,
	)
	if err != nil {
		return fmt.Errorf("initializing token issuer: %w", err)
	}

	ingestEngine, err := ingester.NewEngine(cfg, log, store)
	if err != nil {
		return fmt.Errorf("initializing ingester engine: %w", err)
	}

	server := api.NewServer(cfg, log, store, tokenIssuer)
	server.SetSecretsVault(vault)
	server.SetSIEMForwarder(siemForwarder)
	httpServer := &http.Server{
		Addr:         cfg.Server.ListenAddress,
		Handler:      server.Router(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// --- start subsystems ---

	errCh := make(chan error, 2)

	go func() {
		log.Info("http server listening", "address", cfg.Server.ListenAddress)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	go ingestEngine.Run(ctx)

	if cfg.Graph.Enabled {
		graphClient := graph.NewClient(cfg.Graph.TenantID, cfg.Graph.ClientID, cfg.Graph.ClientSecretEnvVar, cfg.Graph.Scopes)
		go runGraphCollector(ctx, log, graphClient, store, cfg.Graph.PollInterval)
	}

	// --- wait for shutdown signal or fatal error ---

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		log.Error("fatal subsystem error, shutting down", "error", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("http server graceful shutdown failed", "error", err)
	}

	ingestEngine.Shutdown()

	log.Info("cybernom stopped cleanly")
	return nil
}

func wireNotifications(router *notifier.Router, cfg *config.Config) error {
	for _, ch := range cfg.Notifications {
		if !ch.Enabled {
			continue
		}
		switch ch.Type {
		case "discord":
			if err := router.Register(notifier.NewDiscordChannel(ch.WebhookEnvVar), ch.MinSeverity); err != nil {
				return err
			}
		case "slack":
			if err := router.Register(notifier.NewSlackChannel(ch.WebhookEnvVar), ch.MinSeverity); err != nil {
				return err
			}
		case "telegram":
			if ch.BotTokenEnvVar == "" || ch.ChatIDEnvVar == "" {
				return fmt.Errorf("notification type telegram is enabled but missing bot_token_env_var or chat_id_env_var")
			}
			if err := router.Register(notifier.NewTelegramChannel(ch.BotTokenEnvVar, ch.ChatIDEnvVar), ch.MinSeverity); err != nil {
				return err
			}
		case "email":
			if ch.SMTP == nil {
				return fmt.Errorf("notification type email is enabled but has no smtp config")
			}
			email := notifier.NewEmailChannel(ch.SMTP.Host, ch.SMTP.Port, ch.SMTP.Username, ch.SMTP.PasswordEnvVar, ch.SMTP.From, ch.SMTP.To, ch.SMTP.UseTLS)
			if err := router.Register(email, ch.MinSeverity); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown notification channel type %q", ch.Type)
		}
	}
	return nil
}

// runGraphCollector polls Microsoft Graph on an interval and persists
// normalized snapshots. It runs independently of the feed ingester and
// stops cleanly when ctx is cancelled.
func runGraphCollector(ctx context.Context, log *slog.Logger, client *graph.Client, store *storage.Store, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	poll := func() {
		pollCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()

		alerts, err := client.ListSecurityAlerts(pollCtx, 50)
		if err != nil {
			log.Error("graph: fetching security alerts failed", "error", err)
		} else {
			for _, a := range alerts {
				payload, _ := json.Marshal(a)
				if err := store.SaveGraphSnapshot(pollCtx, "security_alert", a.Severity, payload); err != nil {
					log.Error("graph: saving security alert snapshot failed", "error", err)
				}
			}
			log.Info("graph: security alerts synced", "count", len(alerts))
		}

		risky, err := client.ListRiskySignIns(pollCtx, 50)
		if err != nil {
			log.Error("graph: fetching risky sign-ins failed", "error", err)
		} else {
			for _, rs := range risky {
				payload, _ := json.Marshal(rs)
				if err := store.SaveGraphSnapshot(pollCtx, "risky_signin", rs.RiskLevel, payload); err != nil {
					log.Error("graph: saving risky sign-in snapshot failed", "error", err)
				}
			}
			log.Info("graph: risky sign-ins synced", "count", len(risky))
		}
	}

	poll()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}
