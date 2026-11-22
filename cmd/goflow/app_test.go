package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VikFreeze/goflow/internal/config"
)

// ---- helpers -------------------------------------------------------------

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestApp builds an App in a temp config dir with the admin password set.
func newTestApp(t *testing.T, pw string, cfgDir string) *App {
	t.Helper()
	t.Setenv(EnvAdminPassword, pw)
	app, err := NewApp(Options{ConfigDir: cfgDir, Logger: testLogger()})
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	return app
}

// serveHTTP runs the app's router on a random localhost port.
func serveHTTP(t *testing.T, app *App) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: app.Router(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

// serveHTTPS runs the app's router over TLS (certs from the app's store).
func serveHTTPS(t *testing.T, app *App) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           app.Router(),
		TLSConfig:         app.certs.TLSConfig(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}

// noRedirectClient never follows redirects (needed for 301 assertions).
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func getHost(t *testing.T, client *http.Client, base, host, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s %s: %v", host, path, err)
	}
	return resp
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// mintCertPEM writes a self-signed PEM cert/key pair for hosts into dir and
// returns the absolute file paths.
func mintCertPEM(t *testing.T, dir string, name string, hosts []string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              hosts,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	crt := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	if err := os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return crt, keyPath
}

// ---- tests ---------------------------------------------------------------

func TestAppRoutesByHostAndAlias(t *testing.T) {
	one := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "one") }))
	two := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "two") }))
	defer one.Close()
	defer two.Close()

	dir := t.TempDir()
	app := newTestApp(t, "pw", dir)
	cfg, _ := app.Load()
	cfg.Routes = []config.Route{
		{Name: "a", Hosts: []string{"a.example.com", "a-alias.example.com"}, Backend: one.Listener.Addr().String()},
		{Name: "b", Hosts: []string{"b.example.com"}, Backend: two.Listener.Addr().String()},
	}
	if err := app.Save(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	base := serveHTTP(t, app)
	client := noRedirectClient()

	cases := []struct {
		host string
		want string
	}{
		{"a.example.com", "one"},
		{"a-alias.example.com", "one"}, // alias resolves to the same backend
		{"b.example.com", "two"},
	}
	for _, tc := range cases {
		resp := getHost(t, client, base, tc.host, "/")
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", tc.host, resp.StatusCode)
		}
		if got := body(t, resp); !strings.Contains(got, tc.want) {
			t.Errorf("%s: body %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestAppUnknownHost404(t *testing.T) {
	dir := t.TempDir()
	app := newTestApp(t, "pw", dir)
	base := serveHTTP(t, app)
	resp := getHost(t, noRedirectClient(), base, "nope.example.com", "/")
	if resp.StatusCode != 404 {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
	b := body(t, resp)
	if !strings.Contains(b, "unknown host") {
		t.Errorf("body %q", b)
	}
}

func TestAppAllowlistDenyAndAllow(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") }))
	defer be.Close()
	dir := t.TempDir()
	app := newTestApp(t, "pw", dir)
	cfg, _ := app.Load()
	cfg.Routes = []config.Route{
		// Test client is 127.0.0.1 -> allowed.
		{Name: "lan-open", Hosts: []string{"lan.example.com"}, Backend: be.Listener.Addr().String(), Allowlist: []string{"127.0.0.1/32"}},
		// 10.0.0.0/8 does not include 127.0.0.1 -> denied.
		{Name: "lan-closed", Hosts: []string{"closed.example.com"}, Backend: be.Listener.Addr().String(), Allowlist: []string{"10.0.0.0/8"}},
	}
	if err := app.Save(cfg); err != nil {
		t.Fatal(err)
	}
	base := serveHTTP(t, app)
	client := noRedirectClient()

	resp := getHost(t, client, base, "lan.example.com", "/")
	if resp.StatusCode != 200 {
		t.Errorf("allowed source: status %d, want 200", resp.StatusCode)
	}
	body(t, resp)
	resp = getHost(t, client, base, "closed.example.com", "/")
	if resp.StatusCode != 403 {
		t.Errorf("denied source: status %d, want 403", resp.StatusCode)
	}
	b := body(t, resp)
	if !strings.Contains(b, "forbidden") {
		t.Errorf("denied body %q", b)
	}
}

func TestAppRedirectHTTP(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") }))
	defer be.Close()
	dir := t.TempDir()
	app := newTestApp(t, "pw", dir)
	cfg, _ := app.Load()
	cfg.Routes = []config.Route{
		{Name: "sec", Hosts: []string{"sec.example.com"}, Backend: be.Listener.Addr().String(), RedirectHTTP: true},
	}
	if err := app.Save(cfg); err != nil {
		t.Fatal(err)
	}
	base := serveHTTP(t, app)

	resp := getHost(t, noRedirectClient(), base, "sec.example.com", "/foo/bar")
	if resp.StatusCode != 301 {
		t.Fatalf("status %d, want 301", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "https://sec.example.com/foo/bar" {
		t.Errorf("Location %q", loc)
	}
	resp.Body.Close()
}

func TestAppHealthz(t *testing.T) {
	dir := t.TempDir()
	app := newTestApp(t, "pw", dir)
	base := serveHTTP(t, app)
	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.Contains(body(t, resp), "ok") {
		t.Fatal("healthz broken")
	}
}

func TestAppAdminLoginAndHotAddRoute(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "hot") }))
	defer be.Close()
	dir := t.TempDir()
	app := newTestApp(t, "s3cret-pw", dir)
	base := serveHTTP(t, app)

	// Unauthenticated -> 401.
	resp, err := http.Get(base + "/admin/api/routes")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unauthed: %d, want 401", resp.StatusCode)
	}

	// Login.
	resp, err = http.Post(base+"/admin/api/login", "application/json", bytes.NewReader([]byte(`{"password":"s3cret-pw"}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "goflow_session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session cookie returned by login")
	}

	// Add a route via the API (no restart).
	payload, _ := json.Marshal(config.Route{Name: "hot", Hosts: []string{"hot.example.com"}, Backend: be.Listener.Addr().String()})
	req, _ := http.NewRequest("POST", base+"/admin/api/routes", bytes.NewReader(payload))
	req.AddCookie(session)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("add route: %d", resp.StatusCode)
	}

	// The new route is live immediately (hot apply).
	client := noRedirectClient()
	client.Jar = newJar(t, session)
	resp = getHost(t, client, base, "hot.example.com", "/")
	if resp.StatusCode != 200 || !strings.Contains(body(t, resp), "hot") {
		t.Fatalf("hot route not live: %d", resp.StatusCode)
	}
}

func TestAppPersistenceAcrossRestart(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "persisted") }))
	defer be.Close()
	dir := t.TempDir()

	// First run: add a route.
	app1 := newTestApp(t, "pw", dir)
	cfg, _ := app1.Load()
	cfg.Routes = []config.Route{
		{Name: "survivor", Hosts: []string{"survivor.example.com", "survivor2.example.com"}, Backend: be.Listener.Addr().String(), Allowlist: []string{"127.0.0.1/32"}},
	}
	if err := app1.Save(cfg); err != nil {
		t.Fatal(err)
	}

	// Second run, fresh App, same config dir: the route must be back.
	app2 := newTestApp(t, "pw", dir)
	cfg2, err := app2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg2.Routes) != 1 || cfg2.Routes[0].Name != "survivor" {
		t.Fatalf("after restart: %+v", cfg2.Routes)
	}
	base := serveHTTP(t, app2)
	resp := getHost(t, noRedirectClient(), base, "survivor2.example.com", "/")
	if resp.StatusCode != 200 || !strings.Contains(body(t, resp), "persisted") {
		t.Fatalf("persisted route not serving: %d", resp.StatusCode)
	}
}

func TestAppHTTPSWithRouteCert(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "secure") }))
	defer be.Close()
	dir := t.TempDir()
	crt, key := mintCertPEM(t, dir, "site", []string{"https.example.com"})

	app := newTestApp(t, "pw", dir)
	cfg, _ := app.Load()
	cfg.Routes = []config.Route{
		{Name: "site", Hosts: []string{"https.example.com"}, Backend: be.Listener.Addr().String(), TLSCertFile: crt, TLSKeyFile: key},
	}
	if err := app.Save(cfg); err != nil {
		t.Fatal(err)
	}
	base := serveHTTPS(t, app)

	// The handshake must present the route's own certificate (not the
	// fallback): verify the negotiated leaf contains the SNI name.
	raw, err := net.Dial("tcp", strings.TrimPrefix(base, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{ServerName: "https.example.com", InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	leaf := tc.ConnectionState().PeerCertificates[0]
	if !containsName(leaf.DNSNames, "https.example.com") {
		t.Fatalf("SNI cert DNSNames %v missing https.example.com", leaf.DNSNames)
	}
	tc.Close()

	// And a plain request over TLS reaches the backend.
	client := &http.Client{
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequest("GET", base+"/", nil)
	req.Host = "https.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.Contains(body(t, resp), "secure") {
		t.Fatalf("https request: %d", resp.StatusCode)
	}
}

func TestAppWebSocketRoundTrip(t *testing.T) {
	// Backend: a raw TCP server that performs a WS upgrade and echoes bytes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 8192)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
			"\r\n"))
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			conn.Write(buf[:n])
		}
	}()

	dir := t.TempDir()
	app := newTestApp(t, "pw", dir)
	cfg, _ := app.Load()
	cfg.Routes = []config.Route{
		{Name: "ws", Hosts: []string{"ws.example.com"}, Backend: ln.Addr().String()},
	}
	if err := app.Save(cfg); err != nil {
		t.Fatal(err)
	}
	base := serveHTTP(t, app)
	host := strings.TrimPrefix(base, "http://")

	// Raw client: write the upgrade request, expect 101, echo a byte.
	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: ws.example.com\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d, want 101", resp.StatusCode)
	}
	if got := resp.Header.Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade header %q", got)
	}
	// Round-trip over the upgraded connection.
	payload := []byte{0x01, 0x02, 0x03}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Errorf("echo %v, want %v", echo, payload)
	}
	// NOTE: do not wait for the backend goroutine here — it only exits
	// when this client's connection closes (defer below), so waiting
	// would deadlock. The defers close both ends.
}

// ---- small helpers -------------------------------------------------------

func containsName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func newJar(t *testing.T, c *http.Cookie) *cookieJar {
	t.Helper()
	return &cookieJar{cookies: map[string][]*http.Cookie{}}
}

// cookieJar is a minimal http.CookieJar for tests.
type cookieJar struct{ cookies map[string][]*http.Cookie }

func (j *cookieJar) SetCookies(u *url.URL, cs []*http.Cookie) {
	j.cookies[u.Host] = append(j.cookies[u.Host], cs...)
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
	return j.cookies[u.Host]
}
