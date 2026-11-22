// Package main wires GoFlow's components into a runnable application and
// provides App, a fully constructed (but not yet listening) instance that
// tests can drive.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/VikFreeze/goflow/internal/acme"
	"github.com/VikFreeze/goflow/internal/admin"
	"github.com/VikFreeze/goflow/internal/config"
	"github.com/VikFreeze/goflow/internal/proxy"
	tlsx "github.com/VikFreeze/goflow/internal/tls"
)

// EnvAdminPassword is the env var holding the admin password at first start.
const EnvAdminPassword = admin.EnvPassword

// EnvACMEEmail is the env var holding the ACME account contact. When unset,
// ACME routes fall back to self-signed certs (and a warning is logged).
const EnvACMEEmail = "GOFLOW_ACME_EMAIL"

// EnvACMEDirectory is the env var overriding the ACME directory URL
// (defaults to Let's Encrypt staging).
const EnvACMEDirectory = "GOFLOW_ACME_DIRECTORY"

// Options configures an App.
type Options struct {
	ConfigDir string
	Logger    *slog.Logger
	// ListenHTTP/ListenHTTPS are ignored by App (the Run method takes them);
	// they exist so a single struct can describe the whole deployment.
	ListenHTTP  string
	ListenHTTPS string
}

// App is a fully wired GoFlow instance: config, proxy, cert store, admin
// surface, and (optionally) the ACME issuer. It is safe to build one and
// serve it on any number of listeners, or to close it.
type App struct {
	configDir string
	cfgPath   string
	logger    *slog.Logger

	mu      sync.RWMutex
	cfg     *config.Config
	matcher *proxy.Matcher
	proxy   *proxy.Handler
	reqLog  *proxy.Log
	certs   *tlsx.Store
	admin   *admin.Server
	issuer  *acme.Issuer
}

// NewApp loads configuration, builds the proxy and admin surface, and
// (if ACME routes exist and an email is configured) the ACME issuer.
func NewApp(opts Options) (*App, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.ConfigDir == "" {
		opts.ConfigDir = "goflow"
	}
	cfgPath := config.Path(opts.ConfigDir)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	a := &App{
		configDir: opts.ConfigDir,
		cfgPath:   cfgPath,
		logger:    opts.Logger,
		cfg:       cfg,
		matcher:   proxy.NewMatcher(cfg),
		reqLog:    proxy.NewLog(1024),
		certs:     tlsx.NewStore(opts.Logger),
	}
	a.proxy = proxy.NewHandler(a.matcher, a.reqLog, opts.Logger)

	// Load TLS certs for routes that declare them.
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		if r.TLSCertFile != "" || r.TLSKeyFile != "" {
			if _, err := a.certs.LoadRoute(r.Hosts, r.TLSCertFile, r.TLSKeyFile, opts.ConfigDir); err != nil {
				opts.Logger.Error("tls: load route cert failed", "route", r.Name, "err", err)
			}
		}
	}
	// A fallback self-signed cert so the HTTPS listener never fails a
	// handshake for an unknown SNI name.
	if fb, err := selfSignedFallback(); err == nil {
		a.certs.SetFallback(fb)
	}

	// Admin auth: password from env, or loaded/generated hash.
	hashPath := filepath.Join(opts.ConfigDir, "admin.hash")
	pw, generated, auth, err := admin.Bootstrap(hashPath, opts.Logger)
	if err != nil {
		return nil, fmt.Errorf("admin bootstrap: %w", err)
	}
	if generated {
		// Shown exactly once, here. The plaintext is never written to
		// any file — only the bcrypt hash is persisted.
		opts.Logger.Warn("admin: generated a first-run password (logged once, never stored in plaintext)", "password", pw)
	}
	a.admin = admin.NewServer(admin.Deps{
		Auth:      auth,
		Load:      a.Load,
		Save:      a.Save,
		Reload:    a.Reload,
		Requests:  a.recentRequests,
		ConfigDir: opts.ConfigDir,
	}, opts.Logger)

	// ACME issuer (optional).
	if email := os.Getenv(EnvACMEEmail); email != "" {
		if hasACMERoute(cfg) {
			a.issuer = acme.NewIssuer(acme.Options{
				Email:     email,
				Directory: os.Getenv(EnvACMEDirectory),
				ConfigDir: opts.ConfigDir,
				Store:     a.certs,
				Logger:    opts.Logger,
			})
		}
	} else if hasACMERoute(cfg) {
		opts.Logger.Warn("acme: routes request ACME but no GOFLOW_ACME_EMAIL set; they will use self-signed certs")
	}

	return a, nil
}

// Load returns the current in-memory config (a copy the caller may mutate).
func (a *App) Load() (*config.Config, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := *a.cfg
	out.Routes = make([]config.Route, len(a.cfg.Routes))
	copy(out.Routes, a.cfg.Routes)
	return &out, nil
}

// Save validates, persists, and hot-applies a new config.
func (a *App) Save(cfg *config.Config) error {
	if err := cfg.ValidateIn(a.configDir); err != nil {
		return err
	}
	if err := cfg.Save(a.cfgPath); err != nil {
		return fmt.Errorf("persist: %w", err)
	}
	return a.apply(cfg)
}

// Reload re-reads the config from disk and hot-applies it.
func (a *App) Reload() error {
	cfg, err := config.Load(a.cfgPath)
	if err != nil {
		return err
	}
	return a.apply(cfg)
}

// apply swaps in a new config: rebuilds the matcher and (re)loads certs for
// TLS routes. It is called under no lock; it takes the app lock itself.
func (a *App) apply(cfg *config.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := proxy.NewMatcher(cfg)
	a.proxy.SetMatcher(m)
	a.matcher = m
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		if r.TLSCertFile != "" || r.TLSKeyFile != "" {
			if _, err := a.certs.LoadRoute(r.Hosts, r.TLSCertFile, r.TLSKeyFile, a.configDir); err != nil {
				a.logger.Warn("tls: reload route cert failed", "route", r.Name, "err", err)
			}
		}
	}
	a.cfg = cfg
	a.logger.Info("config applied", "routes", len(cfg.Routes))
	return nil
}

// recentRequests maps the proxy log to admin entries.
func (a *App) recentRequests(n int) []admin.ProxyEntry {
	snap := a.reqLog.Snapshot(n)
	out := make([]admin.ProxyEntry, 0, len(snap))
	for _, e := range snap {
		out = append(out, admin.ProxyEntry{
			Time:      e.Time.Format("15:04:05"),
			Method:    e.Method,
			Host:      e.Host,
			Path:      e.Path,
			Backend:   e.Backend,
			Client:    e.Client,
			Status:    e.Status,
			LatencyMS: e.LatencyMS,
			WebSocket: e.WebSocket,
			Redirect:  e.Redirect,
			Denied:    e.Denied,
			Route:     e.Route,
		})
	}
	return out
}

// Router returns the root HTTP handler: /healthz, ACME challenge (if an
// issuer is present), the /admin subtree, and everything else to the proxy.
func (a *App) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "ok\n")
	})
	if a.issuer != nil {
		mux.HandleFunc("GET /.well-known/acme-challenge/{token}", a.handleACMEChallenge)
	}
	if a.admin != nil {
		// The admin's internal patterns are written relative to its own
		// root (/routes, /api/...), while the browser sees /admin/routes.
		// Serve the admin only for /admin and /admin/..., stripping the
		// prefix; anything else falls through to the proxy.
		inner := a.admin.Handler()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") {
				r2 := r.Clone(r.Context())
				r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/admin")
				if r2.URL.Path == "" {
					r2.URL.Path = "/"
				}
				inner.ServeHTTP(w, r2)
				return
			}
			a.proxy.ServeHTTP(w, r)
		})
	} else {
		mux.HandleFunc("/", a.proxy.ServeHTTP)
	}
	return mux
}

// handleACMEChallenge answers an HTTP-01 challenge fetch.
func (a *App) handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	host := config.NormaliseHost(r.Host)
	if a.issuer == nil {
		http.NotFound(w, r)
		return
	}
	if keyAuth, ok := a.issuer.Challenges().Lookup(host, token); ok {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, keyAuth)
		return
	}
	http.NotFound(w, r)
}

// HTTPListener/HTTPSListener build net.Listeners for Run; they are separate
// so tests can override them.
func (a *App) HTTPListener(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }

// Run starts the HTTP and (optionally) HTTPS listeners and blocks until the
// context is cancelled, then shuts both down gracefully.
func (a *App) Run(ctx context.Context, listenHTTP, listenHTTPS string, shutdownTimeout time.Duration) error {
	if shutdownTimeout <= 0 {
		shutdownTimeout = 10 * time.Second
	}
	router := a.Router()

	httpSrv := &http.Server{
		Addr:              listenHTTP,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	var httpsSrv *http.Server
	if listenHTTPS != "" {
		httpsSrv = &http.Server{
			Addr:              listenHTTPS,
			Handler:           router,
			TLSConfig:         a.certs.TLSConfig(),
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	errCh := make(chan error, 2)
	go func() {
		a.logger.Info("http listener started", "addr", listenHTTP)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("http: %w", err)
		}
	}()
	if httpsSrv != nil {
		go func() {
			a.logger.Info("https listener started", "addr", listenHTTPS)
			if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("https: %w", err)
			}
		}()
	}

	// Start ACME issuance in the background (does not block serving).
	if a.issuer != nil {
		routes := a.acmeRoutes()
		go a.issuer.Run(routes)
	}

	select {
	case <-ctx.Done():
		a.logger.Info("shutting down", "timeout", shutdownTimeout.String())
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpSrv.Shutdown(shutCtx); err != nil {
			a.logger.Error("http shutdown", "err", err)
		}
		if httpsSrv != nil {
			if err := httpsSrv.Shutdown(shutCtx); err != nil {
				a.logger.Error("https shutdown", "err", err)
			}
		}
		return nil
	case err := <-errCh:
		return err
	}
}

func (a *App) acmeRoutes() []*acme.Route {
	var out []*acme.Route
	for i := range a.cfg.Routes {
		r := &a.cfg.Routes[i]
		if r.ACME {
			out = append(out, &acme.Route{Name: r.Name, Hosts: r.Hosts})
		}
	}
	return out
}

func hasACMERoute(cfg *config.Config) bool {
	for i := range cfg.Routes {
		if cfg.Routes[i].ACME {
			return true
		}
	}
	return false
}

// selfSignedFallback mints a throwaway self-signed cert used only so the
// HTTPS listener can complete a handshake for an SNI name with no cert.
func selfSignedFallback() (*tls.Certificate, error) {
	return tlsx.SelfSigned([]string{"goflow.local"})
}
