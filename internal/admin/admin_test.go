package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VikFreeze/goflow/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// testServer builds an admin.Server backed by a config persisted under a
// temp dir, so Save/Reload behave like in production.
func testServer(t *testing.T, pw string) (*Server, string) {
	t.Helper()
	t.Setenv(EnvPassword, pw)
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "admin.hash")
	_, _, auth, err := Bootstrap(hashPath, nil)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	cfgPath := config.Path(dir)
	srv := NewServer(Deps{
		Auth: auth,
		Load: func() (*config.Config, error) { return config.Load(cfgPath) },
		Save: func(c *config.Config) error { return c.Save(cfgPath) },
		Reload: func() error {
			_, err := config.Load(cfgPath)
			return err
		},
		Requests: func(n int) []ProxyEntry {
			return []ProxyEntry{{Time: "12:00:00", Method: "GET", Host: "a.example.com", Path: "/", Status: 200, Route: "a", Backend: "127.0.0.1:1"}}
		},
	}, nil)
	if err := srv.init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	return srv, dir
}

// do performs a request against the handler and returns the response.
func do(t *testing.T, h http.Handler, method, target string, body io.Reader, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// doForm performs an application/x-www-form-urlencoded POST (the content
// type is required for ParseForm to read the body).
func doForm(t *testing.T, h http.Handler, target string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// loginCookie runs POST /api/login and returns the session cookie.
func loginCookie(t *testing.T, h http.Handler, pw string) *http.Cookie {
	t.Helper()
	rec := do(t, h, "POST", "/api/login", bytes.NewReader([]byte(`{"password":"`+pw+`"}`)), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status %d body %s", rec.Code, rec.Body.String())
	}
	cookie := rec.Result().Cookies()
	if len(cookie) != 1 || cookie[0].Name != sessionCookie {
		t.Fatalf("login: cookies = %v", cookie)
	}
	return cookie[0]
}

func TestBootstrapFromEnv(t *testing.T) {
	t.Setenv(EnvPassword, "hunter2-secret")
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "admin.hash")
	pw, generated, auth, err := Bootstrap(hashPath, nil)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if generated {
		t.Error("env password must not report generated")
	}
	if pw != "" {
		t.Errorf("env bootstrap must not echo a password, got %q", pw)
	}
	if !auth.VerifyPassword("hunter2-secret") {
		t.Error("env password should verify")
	}
	if auth.VerifyPassword("wrong") {
		t.Error("wrong password should not verify")
	}
	// The hash is on disk, the plaintext is not.
	data, err := os.ReadFile(hashPath)
	if err != nil {
		t.Fatalf("hash file: %v", err)
	}
	if !bytes.Contains(data, []byte("$2a$")) && !bytes.Contains(data, []byte("$2b$")) && !bytes.Contains(data, []byte("$2y$")) {
		t.Errorf("hash file does not look like bcrypt: %q", data)
	}
	if bytes.Contains(data, []byte("hunter2")) {
		t.Error("plaintext password must never be written to disk")
	}
	fi, _ := os.Stat(hashPath)
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("hash file perms %o, want 600", perm)
	}
}

func TestBootstrapFromExistingFile(t *testing.T) {
	t.Setenv(EnvPassword, "")
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "admin.hash")
	hash, _ := bcrypt.GenerateFromPassword([]byte("stored-pw"), bcrypt.DefaultCost)
	if err := os.WriteFile(hashPath, hash, 0o600); err != nil {
		t.Fatal(err)
	}
	_, generated, auth, err := Bootstrap(hashPath, nil)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if generated {
		t.Error("existing file must not report generated")
	}
	if !auth.VerifyPassword("stored-pw") {
		t.Error("password from existing file should verify")
	}
}

func TestBootstrapFirstRunGenerates(t *testing.T) {
	t.Setenv(EnvPassword, "")
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "admin.hash")
	pw, generated, auth, err := Bootstrap(hashPath, nil)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if !generated {
		t.Fatal("first run without env must generate a password")
	}
	if len(pw) != 24 {
		t.Errorf("generated password length %d, want 24", len(pw))
	}
	if !auth.VerifyPassword(pw) {
		t.Error("generated password should verify")
	}
	data, _ := os.ReadFile(hashPath)
	if bytes.Contains(data, []byte(pw)) {
		t.Error("generated plaintext must never be written to disk")
	}
}

func TestSessionStore(t *testing.T) {
	s := NewSessionStore()
	tok := s.Create(5 * time.Second)
	if !s.Valid(tok) {
		t.Fatal("fresh token should be valid")
	}
	tok2 := s.Create(1 * time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if s.Valid(tok2) {
		t.Error("expired token should be invalid")
	}
	s.Invalidate(tok)
	if s.Valid(tok) {
		t.Error("invalidated token should be invalid")
	}
	if s.Valid("") {
		t.Error("empty token should be invalid")
	}
}

func TestLoginFlow(t *testing.T) {
	srv, _ := testServer(t, "correct-horse")
	h := srv.Handler()

	// Unauthenticated page -> redirect to login.
	rec := do(t, h, "GET", "/routes", nil, nil)
	if rec.Code != http.StatusSeeOther || !strings.HasSuffix(rec.Header().Get("Location"), "/admin/") {
		t.Errorf("unauthed /routes: %d %q, want 303 -> /admin/", rec.Code, rec.Header().Get("Location"))
	}
	// Unauthenticated JSON -> 401.
	rec = do(t, h, "GET", "/api/routes", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthed /api/routes: %d, want 401", rec.Code)
	}
	// Wrong password.
	rec = do(t, h, "POST", "/api/login", bytes.NewReader([]byte(`{"password":"nope"}`)), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d, want 401", rec.Code)
	}
	// Right password -> cookie, then access.
	ck := loginCookie(t, h, "correct-horse")
	rec = do(t, h, "GET", "/api/routes", nil, ck)
	if rec.Code != http.StatusOK {
		t.Fatalf("authed /api/routes: %d body %s", rec.Code, rec.Body.String())
	}
	var routes []config.Route
	if err := json.Unmarshal(rec.Body.Bytes(), &routes); err != nil {
		t.Fatalf("routes json: %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("fresh server should have no routes, got %v", routes)
	}
	// Login page renders.
	rec = do(t, h, "GET", "/", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Sign in") {
		t.Errorf("login page: %d", rec.Code)
	}
}

func TestHTMLFormAddRoute(t *testing.T) {
	srv, dir := testServer(t, "pw")
	h := srv.Handler()
	ck := loginCookie(t, h, "pw")

	form := url.Values{}
	form.Set("name", "files")
	form.Set("hosts", "files.dev.test, shares.dev.test")
	form.Set("backend", "127.0.0.1:41240")
	form.Set("allowlist", "192.168.0.0/16")
	rec := doForm(t, h, "/routes", form, ck)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("form add: %d body %s", rec.Code, rec.Body.String())
	}
	cfg, err := config.Load(config.Path(dir))
	if err != nil {
		t.Fatalf("load after form add: %v", err)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("routes = %d, want 1", len(cfg.Routes))
	}
	r := cfg.Routes[0]
	if r.Name != "files" || len(r.Hosts) != 2 || r.Backend != "127.0.0.1:41240" || len(r.Allowlist) != 1 {
		t.Errorf("route not saved correctly: %+v", r)
	}
}

func TestAPIRouteCRUD(t *testing.T) {
	srv, dir := testServer(t, "pw")
	h := srv.Handler()
	ck := loginCookie(t, h, "pw")

	// Add.
	body, _ := json.Marshal(config.Route{
		Name: "vault", Hosts: []string{"vault.example.com"}, Backend: "127.0.0.1:40031",
	})
	rec := do(t, h, "POST", "/api/routes", bytes.NewReader(body), ck)
	if rec.Code != http.StatusOK {
		t.Fatalf("add: %d %s", rec.Code, rec.Body.String())
	}
	// Invalid route (bad backend) rejected with 400.
	rec = do(t, h, "POST", "/api/routes", bytes.NewReader([]byte(`{"name":"bad","hosts":["bad.example.com"],"backend":"noport"}`)), ck)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad backend: %d, want 400", rec.Code)
	}
	// Duplicate host across routes rejected.
	rec = do(t, h, "POST", "/api/routes", bytes.NewReader([]byte(`{"name":"dup","hosts":["vault.example.com"],"backend":"127.0.0.1:2"}`)), ck)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("duplicate host: %d, want 400", rec.Code)
	}
	// List shows the added route.
	rec = do(t, h, "GET", "/api/routes", nil, ck)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	cfg, err := config.Load(config.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Name != "vault" {
		t.Fatalf("routes on disk: %+v", cfg.Routes)
	}
	// Delete.
	rec = do(t, h, "DELETE", "/api/routes/vault", nil, ck)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, "DELETE", "/api/routes/vault", nil, ck)
	if rec.Code != http.StatusNotFound {
		t.Errorf("delete missing: %d, want 404", rec.Code)
	}
}

func TestLogsView(t *testing.T) {
	srv, _ := testServer(t, "pw")
	h := srv.Handler()
	ck := loginCookie(t, h, "pw")
	rec := do(t, h, "GET", "/api/logs", nil, ck)
	if rec.Code != http.StatusOK {
		t.Fatalf("api logs: %d", rec.Code)
	}
	var entries []ProxyEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Host != "a.example.com" {
		t.Errorf("log entries = %v", entries)
	}
	// HTML log page renders the entry.
	rec = do(t, h, "GET", "/logs", nil, ck)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "a.example.com") {
		t.Errorf("log page: %d", rec.Code)
	}
}

func TestFormPagesRender(t *testing.T) {
	srv, _ := testServer(t, "pw")
	h := srv.Handler()
	ck := loginCookie(t, h, "pw")

	// New-route form renders with a nil existing route.
	rec := do(t, h, "GET", "/routes/new", nil, ck)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Add route") {
		t.Fatalf("new form: %d", rec.Code)
	}
	// Routes page renders the empty state.
	rec = do(t, h, "GET", "/routes", nil, ck)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "No routes yet") {
		t.Fatalf("routes page: %d", rec.Code)
	}
	// Edit form renders for an existing route.
	body, _ := json.Marshal(config.Route{Name: "e", Hosts: []string{"e.example.com"}, Backend: "127.0.0.1:1"})
	do(t, h, "POST", "/api/routes", bytes.NewReader(body), ck)
	rec = do(t, h, "GET", "/routes/e/edit", nil, ck)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Edit route: e") {
		t.Fatalf("edit form: %d", rec.Code)
	}
}

func TestLogout(t *testing.T) {
	srv, _ := testServer(t, "pw")
	h := srv.Handler()
	ck := loginCookie(t, h, "pw")
	rec := do(t, h, "POST", "/logout", nil, ck)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout: %d", rec.Code)
	}
	rec = do(t, h, "GET", "/api/routes", nil, ck)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("after logout: %d, want 401", rec.Code)
	}
}
