package admin

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/VikFreeze/goflow/internal/config"
)

//go:embed templates/*.html
var tplFS embed.FS

// Deps are the pieces of GoFlow the admin surface drives.
type Deps struct {
	Auth      *Auth
	Load      func() (*config.Config, error) // current config
	Save      func(*config.Config) error     // persist + hot-reload
	Reload    func() error                   // re-read from disk
	Requests  func(int) []ProxyEntry         // recent request log (newest first)
	ConfigDir string                         // base dir for relative cert paths
}

// ProxyEntry mirrors proxy.Entry without importing proxy (keeps the admin
// package decoupled; cmd maps proxy.Entry -> ProxyEntry).
type ProxyEntry struct {
	Time      string `json:"time"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	Path      string `json:"path"`
	Backend   string `json:"backend"`
	Client    string `json:"client"`
	Status    int    `json:"status"`
	LatencyMS int64  `json:"latencyMs"`
	WebSocket bool   `json:"websocket"`
	Redirect  bool   `json:"redirect"`
	Denied    bool   `json:"denied"`
	Route     string `json:"route"`
}

// Server is the embedded admin UI + JSON API.
type Server struct {
	deps Deps
	log  *slog.Logger
	tpl  *template.Template
}

const (
	sessionCookie = "goflow_session"
	logLimit      = 200
)

// NewServer builds an admin server.
func NewServer(deps Deps, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{deps: deps, log: logger}
}

func (s *Server) init() error {
	tpl, err := template.New("").Funcs(template.FuncMap{
		"join": strings.Join,
		"add":  func(a, b int) int { return a + b },
		"statusClass": func(code int) string {
			if code == 0 {
				return ""
			}
			return fmt.Sprintf("status-%d", code/100)
		},
	}).ParseFS(tplFS, "templates/*.html")
	if err != nil {
		return fmt.Errorf("admin: parse templates: %w", err)
	}
	s.tpl = tpl
	return nil
}

// Routes returns the HTTP handler for the admin subtree (mounted at /admin).
func (s *Server) Handler() http.Handler {
	if s.tpl == nil {
		// Parse lazily; NewServer does not error so wiring stays simple.
		_ = s.init()
	}
	mux := http.NewServeMux()
	// Pages (HTML).
	mux.HandleFunc("GET /", s.pageLogin)
	mux.HandleFunc("POST /login", s.postLogin)
	mux.HandleFunc("POST /logout", s.postLogout)
	mux.HandleFunc("GET /routes", s.authed(s.pageRoutes))
	mux.HandleFunc("GET /routes/new", s.authed(s.pageRouteForm))
	mux.HandleFunc("GET /routes/{name}/edit", s.authed(s.pageRouteForm))
	mux.HandleFunc("POST /routes", s.authed(s.postRoute))
	mux.HandleFunc("POST /routes/{name}/delete", s.authed(s.postDeleteRoute))
	mux.HandleFunc("POST /reload", s.authed(s.postReload))
	mux.HandleFunc("GET /logs", s.authed(s.pageLogs))
	// JSON API (consumed by the vanilla JS in the templates).
	mux.HandleFunc("POST /api/login", s.apiLogin)
	mux.HandleFunc("GET /api/routes", s.authedJSON(s.apiRoutes))
	mux.HandleFunc("GET /api/logs", s.authedJSON(s.apiLogs))
	mux.HandleFunc("POST /api/routes", s.authedJSON(s.apiUpsertRoute))
	mux.HandleFunc("DELETE /api/routes/{name}", s.authedJSON(s.apiDeleteRoute))
	mux.HandleFunc("POST /api/reload", s.authedJSON(s.apiReload))
	return mux
}

// ---- auth plumbing -------------------------------------------------------

func (s *Server) sessionValid(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	return s.deps.Auth.Valid(c.Value)
}

func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.sessionValid(r) {
			http.Redirect(w, r, "/admin/", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) authedJSON(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.sessionValid(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}
		next(w, r)
	}
}

// ---- pages ---------------------------------------------------------------

func (s *Server) pageLogin(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "login", nil)
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pw := r.PostFormValue("password")
	if !s.deps.Auth.VerifyPassword(pw) {
		// Constant-time-ish: still compare so timing is similar; bcrypt
		// already dominates.
		s.render(w, http.StatusUnauthorized, "login", map[string]any{"error": "invalid password"})
		return
	}
	tok := s.deps.Auth.Begin()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/admin/routes", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.deps.Auth.End(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/admin", MaxAge: -1})
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func (s *Server) pageRoutes(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.deps.Load()
	if err != nil {
		s.render(w, http.StatusInternalServerError, "error", map[string]any{"error": err.Error()})
		return
	}
	s.render(w, http.StatusOK, "routes", map[string]any{"Routes": cfg.Routes})
}

func (s *Server) pageRouteForm(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.deps.Load()
	if err != nil {
		s.render(w, http.StatusInternalServerError, "error", map[string]any{"error": err.Error()})
		return
	}
	name := r.PathValue("name")
	var existing *config.Route
	if name != "" {
		for i := range cfg.Routes {
			if cfg.Routes[i].Name == name {
				existing = &cfg.Routes[i]
				break
			}
		}
	}
	s.render(w, http.StatusOK, "route_form", map[string]any{"Route": existing, "Name": name})
}

func (s *Server) postRoute(w http.ResponseWriter, r *http.Request) {
	// HTML form POST: parse, validate, save, redirect back.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	cfg, err := s.deps.Load()
	if err != nil {
		s.render(w, http.StatusInternalServerError, "error", map[string]any{"error": err.Error()})
		return
	}
	if err := s.applyRouteForm(cfg, r); err != nil {
		s.render(w, http.StatusBadRequest, "error", map[string]any{"error": err.Error()})
		return
	}
	if err := s.deps.Save(cfg); err != nil {
		s.render(w, http.StatusInternalServerError, "error", map[string]any{"error": err.Error()})
		return
	}
	http.Redirect(w, r, "/admin/routes", http.StatusSeeOther)
}

func (s *Server) postDeleteRoute(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg, err := s.deps.Load()
	if err != nil {
		s.render(w, http.StatusInternalServerError, "error", map[string]any{"error": err.Error()})
		return
	}
	out := cfg.Routes[:0]
	removed := false
	for _, rt := range cfg.Routes {
		if rt.Name == name {
			removed = true
			continue
		}
		out = append(out, rt)
	}
	if !removed {
		s.render(w, http.StatusNotFound, "error", map[string]any{"error": "route not found"})
		return
	}
	cfg.Routes = out
	if err := s.deps.Save(cfg); err != nil {
		s.render(w, http.StatusInternalServerError, "error", map[string]any{"error": err.Error()})
		return
	}
	http.Redirect(w, r, "/admin/routes", http.StatusSeeOther)
}

func (s *Server) postReload(w http.ResponseWriter, r *http.Request) {
	if err := s.deps.Reload(); err != nil {
		s.render(w, http.StatusInternalServerError, "error", map[string]any{"error": err.Error()})
		return
	}
	http.Redirect(w, r, "/admin/routes", http.StatusSeeOther)
}

func (s *Server) pageLogs(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "logs", map[string]any{"Entries": s.deps.Requests(logLimit)})
}

// ---- JSON API ------------------------------------------------------------

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
		return
	}
	if !s.deps.Auth.VerifyPassword(body.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid password"})
		return
	}
	tok := s.deps.Auth.Begin()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/admin", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) apiRoutes(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.deps.Load()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, cfg.Routes)
}

func (s *Server) apiLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.deps.Requests(logLimit))
}

func (s *Server) apiUpsertRoute(w http.ResponseWriter, r *http.Request) {
	var rt config.Route
	if err := json.NewDecoder(r.Body).Decode(&rt); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body: " + err.Error()})
		return
	}
	cfg, err := s.deps.Load()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := upsertRoute(cfg, rt); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := cfg.ValidateIn(s.deps.ConfigDir); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.deps.Save(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) apiDeleteRoute(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg, err := s.deps.Load()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := cfg.Routes[:0]
	removed := false
	for _, rt := range cfg.Routes {
		if rt.Name == name {
			removed = true
			continue
		}
		out = append(out, rt)
	}
	cfg.Routes = out
	if !removed {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "route not found"})
		return
	}
	if err := s.deps.Save(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) apiReload(w http.ResponseWriter, r *http.Request) {
	if err := s.deps.Reload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

// ---- shared helpers ------------------------------------------------------

// upsertRoute inserts or replaces a route by name in cfg.
func upsertRoute(cfg *config.Config, rt config.Route) error {
	if strings.TrimSpace(rt.Name) == "" {
		return fmt.Errorf("route name is required")
	}
	for i := range cfg.Routes {
		if cfg.Routes[i].Name == rt.Name {
			cfg.Routes[i] = rt
			return nil
		}
	}
	cfg.Routes = append(cfg.Routes, rt)
	return nil
}

// applyRouteForm reads a route from the HTML form fields.
func (s *Server) applyRouteForm(cfg *config.Config, r *http.Request) error {
	rt := config.Route{
		Name:         strings.TrimSpace(r.PostFormValue("name")),
		Hosts:        splitCSV(r.PostFormValue("hosts")),
		Backend:      strings.TrimSpace(r.PostFormValue("backend")),
		Allowlist:    splitCSV(r.PostFormValue("allowlist")),
		TLSCertFile:  strings.TrimSpace(r.PostFormValue("tlsCertFile")),
		TLSKeyFile:   strings.TrimSpace(r.PostFormValue("tlsKeyFile")),
		ACME:         r.PostFormValue("acme") == "on",
		RedirectHTTP: r.PostFormValue("redirectHttp") == "on",
	}
	if err := upsertRoute(cfg, rt); err != nil {
		return err
	}
	return cfg.ValidateIn(s.deps.ConfigDir)
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (s *Server) render(w http.ResponseWriter, code int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("admin: template render failed", "template", name, "err", err)
	}
}

// atomicWrite writes data to path via temp file + rename.
func atomicWrite(path string, data []byte, mode int) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, os.FileMode(mode)); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
