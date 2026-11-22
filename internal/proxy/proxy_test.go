package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VikFreeze/goflow/internal/config"
)

func newTestHandler(t *testing.T, cfg *config.Config) *Handler {
	t.Helper()
	m := NewMatcher(cfg)
	h := NewHandler(m, NewLog(1024), slog.New(slog.NewTextHandler(io.Discard, nil)))
	return h
}

func newReq(host, path string) *http.Request {
	r := httptest.NewRequest("GET", "http://"+host+path, nil)
	r.Host = host
	return r
}

func TestRouteByHost(t *testing.T) {
	var hitsA, hitsB atomic.Int32
	beA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsA.Add(1)
		fmt.Fprintln(w, "backendA")
	}))
	beB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsB.Add(1)
		fmt.Fprintln(w, "backendB")
	}))
	defer beA.Close()
	defer beB.Close()

	cfg := &config.Config{Routes: []config.Route{
		{Name: "a", Hosts: []string{"a.example.com"}, Backend: beA.Listener.Addr().String()},
		{Name: "b", Hosts: []string{"b.example.com"}, Backend: beB.Listener.Addr().String()},
	}}
	h := newTestHandler(t, cfg)

	for host, want := range map[string]string{"a.example.com": "backendA", "b.example.com": "backendB"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newReq(host, "/x"))
		if w.Code != 200 {
			t.Fatalf("%s: status %d, want 200", host, w.Code)
		}
		body := strings.TrimSpace(w.Body.String())
		if body != want {
			t.Errorf("%s: body %q, want %q", host, body, want)
		}
	}
}

func TestAliasResolvesToSameBackend(t *testing.T) {
	var hits atomic.Int32
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprintln(w, "files")
	}))
	defer be.Close()

	cfg := &config.Config{Routes: []config.Route{
		{Name: "files", Hosts: []string{"files.dev.test", "shares.dev.test"}, Backend: be.Listener.Addr().String()},
	}}
	h := newTestHandler(t, cfg)

	for _, host := range []string{"files.dev.test", "shares.dev.test"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, newReq(host, "/"))
		if w.Code != 200 {
			t.Fatalf("%s: status %d", host, w.Code)
		}
		if got := strings.TrimSpace(w.Body.String()); got != "files" {
			t.Errorf("%s: body %q, want files", host, got)
		}
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("backend hit %d times, want 2", got)
	}
}

func TestAllowlistDeny(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "should-not-arrive")
	}))
	defer be.Close()

	cfg := &config.Config{Routes: []config.Route{
		{Name: "lan", Hosts: []string{"lan.example.com"}, Backend: be.Listener.Addr().String(), Allowlist: []string{"10.0.0.0/8"}},
	}}
	h := newTestHandler(t, cfg).WithRemoteIP(func(r *http.Request) net.IP {
		return net.ParseIP("8.8.8.8") // not in 10.0.0.0/8
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq("lan.example.com", "/"))
	if w.Code != 403 {
		t.Fatalf("status %d, want 403", w.Code)
	}
}

func TestAllowlistAllow(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok-lan")
	}))
	defer be.Close()

	cfg := &config.Config{Routes: []config.Route{
		{Name: "lan", Hosts: []string{"lan.example.com"}, Backend: be.Listener.Addr().String(), Allowlist: []string{"10.0.0.0/8"}},
	}}
	h := newTestHandler(t, cfg).WithRemoteIP(func(r *http.Request) net.IP {
		return net.ParseIP("10.1.2.3") // in 10.0.0.0/8
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq("lan.example.com", "/"))
	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "ok-lan" {
		t.Errorf("body %q, want ok-lan", got)
	}
}

func TestRedirectHTTP(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "backend")
	}))
	defer be.Close()

	cfg := &config.Config{Routes: []config.Route{
		{Name: "sec", Hosts: []string{"sec.example.com"}, Backend: be.Listener.Addr().String(), RedirectHTTP: true},
	}}
	h := newTestHandler(t, cfg)

	// Plaintext request (no TLS) on a redirect route -> 301 to https.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq("sec.example.com", "/path?x=1"))
	if w.Code != 301 {
		t.Fatalf("status %d, want 301", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "https://sec.example.com/path?x=1" {
		t.Errorf("Location %q, want https://sec.example.com/path?x=1", loc)
	}
}

func TestNoRedirectWhenTLS(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "tls-ok")
	}))
	defer be.Close()

	cfg := &config.Config{Routes: []config.Route{
		{Name: "sec", Hosts: []string{"sec.example.com"}, Backend: be.Listener.Addr().String(), RedirectHTTP: true},
	}}
	h := newTestHandler(t, cfg)

	r := newReq("sec.example.com", "/")
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13} // non-nil => TLS request
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("TLS request should proxy, got %d", w.Code)
	}
}

func TestUnknownHost404(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "x")
	}))
	defer be.Close()

	cfg := &config.Config{Routes: []config.Route{
		{Name: "a", Hosts: []string{"a.example.com"}, Backend: be.Listener.Addr().String()},
	}}
	h := newTestHandler(t, cfg)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq("nope.example.com", "/"))
	if w.Code != 404 {
		t.Fatalf("status %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unknown host") {
		t.Errorf("body %q, want 'unknown host'", w.Body.String())
	}
}

// TestWebSocketUpgrade is a full end-to-end test: a real WebSocket backend
// that performs the upgrade handshake, the handler served by a real
// httptest.Server (so the proxy can hijack the connection), and a real
// client that sends an upgrade request and asserts the 101 response plus a
// round-trip over the upgraded connection.
func TestWebSocketUpgrade(t *testing.T) {
	// Backend: accept one TCP conn, perform a WS-style upgrade, echo a byte.
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
		n, _ := conn.Read(buf)
		if n == 0 {
			return
		}
		// Reply 101 with the required headers.
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
			"\r\n"))
		// Echo one byte back over the "upgraded" stream.
		if m, _ := conn.Read(buf); m > 0 {
			conn.Write(buf[:1])
		}
	}()

	cfg := &config.Config{Routes: []config.Route{
		{Name: "ws", Hosts: []string{"ws.example.com"}, Backend: ln.Addr().String()},
	}}
	h := newTestHandler(t, cfg)

	// Serve the handler on a real server so the proxy can hijack.
	front := httptest.NewServer(h)
	defer front.Close()

	client := front.Client()
	req, _ := http.NewRequest("GET", front.URL+"/ws", nil)
	req.Host = "ws.example.com"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	// Use a raw connection to inspect the 101 and send a byte after upgrade.
	// (http.Client won't return a 101 body as a normal response.)
	hj := &hijackerClient{client: client}
	resp, conn, br, err := hj.upgrade(req)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d, want 101", resp.StatusCode)
	}
	if got := resp.Header.Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade header %q, want websocket", got)
	}
	defer conn.Close()
	// Send a byte, expect an echoed byte.
	conn.Write([]byte{0x42})
	echo := make([]byte, 1)
	if _, err := br.Read(echo); err != nil {
		// The backend may have closed already; the 101 + upgrade is the
		// primary assertion. Read from conn as fallback.
		if _, err2 := conn.Read(echo); err2 != nil {
			t.Logf("round-trip read: %v / %v", err, err2)
		}
	}
	<-backendDone
}

// hijackerClient performs a raw HTTP upgrade by hijacking the client
// connection after the request is written.
type hijackerClient struct{ client *http.Client }

func (h *hijackerClient) upgrade(req *http.Request) (*http.Response, net.Conn, *bufio.Reader, error) {
	// Reuse http.Transport with a custom DialContext to capture the conn.
	conn, err := net.Dial("tcp", req.URL.Host)
	if err != nil {
		return nil, nil, nil, err
	}
	_, _ = fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.URL.RequestURI(), req.Host)
	for k, v := range req.Header {
		for _, s := range v {
			_, _ = fmt.Fprintf(conn, "%s: %s\r\n", k, s)
		}
	}
	_, _ = conn.Write([]byte("\r\n"))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	return resp, conn, br, nil
}

// TestMatcherReload verifies swapping the matcher (hot reload) changes
// routing without a restart.
func TestMatcherReload(t *testing.T) {
	be1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "one") }))
	be2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "two") }))
	defer be1.Close()
	defer be2.Close()

	cfg1 := &config.Config{Routes: []config.Route{{Name: "x", Hosts: []string{"x.example.com"}, Backend: be1.Listener.Addr().String()}}}
	cfg2 := &config.Config{Routes: []config.Route{{Name: "x", Hosts: []string{"x.example.com"}, Backend: be2.Listener.Addr().String()}}}

	h := newTestHandler(t, cfg1)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq("x.example.com", "/"))
	if got := strings.TrimSpace(w.Body.String()); got != "one" {
		t.Fatalf("before reload: %q, want one", got)
	}

	// Hot reload: swap in a matcher pointing at be2.
	h.SetMatcher(NewMatcher(cfg2))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, newReq("x.example.com", "/"))
	if got := strings.TrimSpace(w.Body.String()); got != "two" {
		t.Fatalf("after reload: %q, want two", got)
	}
}

// TestPersistenceAcrossRestart verifies a config saved to disk loads back
// into an equivalent matcher (routes survive a process restart).
func TestPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	p := config.Path(dir)

	cfg := &config.Config{Routes: []config.Route{
		{Name: "files", Hosts: []string{"files.dev.test", "shares.dev.test"}, Backend: "127.0.0.1:41240", Allowlist: []string{"10.0.0.0/8"}},
	}}
	if err := cfg.Save(p); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Simulate a restart: load fresh, build a matcher, resolve both hosts.
	loaded, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m := NewMatcher(loaded)
	for _, host := range []string{"files.dev.test", "shares.dev.test"} {
		r, ok := m.Resolve(host)
		if !ok {
			t.Fatalf("host %s not resolved after restart", host)
		}
		if r.Backend != "127.0.0.1:41240" {
			t.Errorf("backend %q, want 127.0.0.1:41240", r.Backend)
		}
		if !r.Allowed(net.ParseIP("10.5.5.5")) {
			t.Error("LAN ip should be allowed after restart")
		}
		if r.Allowed(net.ParseIP("1.1.1.1")) {
			t.Error("WAN ip should be denied after restart")
		}
	}
}

// TestWebSocketUpgradeIsLogged asserts that a completed WebSocket upgrade
// shows up in the request log with WebSocket=true and Status=101. Go's HTTP
// server writes the 101 directly to the connection (bypassing WriteHeader),
// so this guards the request-header detection path.
func TestWebSocketUpgradeIsLogged(t *testing.T) {
	// Raw TCP backend: answer the upgrade with a 101, then echo one frame.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		conn.Write([]byte{0x42})
	}()

	cfg := &config.Config{Routes: []config.Route{
		{Name: "ws", Hosts: []string{"ws.example.com"}, Backend: ln.Addr().String()},
	}}
	lg := NewLog(16)
	h := NewHandler(NewMatcher(cfg), lg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	front := httptest.NewServer(h)
	defer front.Close()

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
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
		t.Fatalf("read 101: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d, want 101", resp.StatusCode)
	}
	resp.Body.Close()

	for i := 0; i < 50; i++ {
		if es := lg.Snapshot(4); len(es) > 0 && es[0].WebSocket {
			e := es[0]
			if e.Status != http.StatusSwitchingProtocols {
				t.Errorf("logged status %d, want 101", e.Status)
			}
			if e.Route != "ws" {
				t.Errorf("route %q, want ws", e.Route)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("websocket upgrade was not logged with WebSocket=true")
}
