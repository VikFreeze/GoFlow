// Command goflow runs the GoFlow reverse proxy.
//
//	go build -o goflow ./cmd/goflow
//	./goflow --listen-http 127.0.0.1:8080 --listen-https 127.0.0.1:8443 \
//	        --config-dir ./goflow --log-level info
//
// The admin password comes from the GOFLOW_ADMIN_PASSWORD environment
// variable (never a flag — flags land in process listings). On first start
// without it, a random password is generated and logged once.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var (
		listenHTTP  = flag.String("listen-http", ":8080", "plaintext HTTP listen address")
		listenHTTPS = flag.String("listen-https", "", "TLS listen address (empty disables HTTPS)")
		configDir   = flag.String("config-dir", "goflow", "directory for routes.json, admin.hash, certs, ACME state")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, error")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("goflow " + version)
		return
	}

	logger := newLogger(*logLevel)

	app, err := NewApp(Options{
		ConfigDir: *configDir,
		Logger:    logger,
	})
	if err != nil {
		logger.Error("startup failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("goflow starting",
		"version", version,
		"http", *listenHTTP,
		"https", *listenHTTPS,
		"config", *configDir,
	)
	if err := app.Run(ctx, *listenHTTP, *listenHTTPS, 10*time.Second); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
	logger.Info("goflow stopped cleanly")
}

// version is set at link time via -ldflags "-X main.version=..."; it defaults
// to "dev" for local builds.
var version = "dev"

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	case "info", "":
		lvl = slog.LevelInfo
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(h)
}
