package proxy

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/VikFreeze/goflow/internal/config"
)

// Handler is the edge proxy. It resolves the Host to a route, enforces the
// allowlist, optionally redirects HTTP->HTTPS, and forwards to the backend
// with httputil.ReverseProxy (which transparently pipes WebSocket upgrades).
type Handler struct {
	matcher *Matcher
	log     *Log
	logger  *slog.Logger
	proxies map[string]*httputil.ReverseProxy
	pmu     sync.RWMutex
	// remoteIP resolves the client source IP. Defaults to the TCP peer;
	// tests override it to exercise the allowlist with arbitrary sources.
	remoteIP func(*http.Request) net.IP
}

// NewHandler builds a Handler.
func NewHandler(m *Matcher, lg *Log, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		matcher:  m,
		log:      lg,
		logger:   logger,
		proxies:  map[string]*httputil.ReverseProxy{},
		remoteIP: RemoteIP,
	}
}

// WithRemoteIP overrides the source-IP resolver (used by tests).
func (h *Handler) WithRemoteIP(f func(*http.Request) net.IP) *Handler {
	h.remoteIP = f
	return h
}

// SetMatcher swaps the active matcher (hot reload).
func (h *Handler) SetMatcher(m *Matcher) { h.matcher = m }

// Matcher exposes the current matcher.
func (h *Handler) Matcher() *Matcher { return h.matcher }

// Log exposes the request log.
func (h *Handler) Log() *Log { return h.log }

// ServeHTTP implements the edge proxy.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := config.NormaliseHost(r.Host)

	route, ok := h.matcher.Resolve(r.Host)
	if !ok {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(404)
		_, _ = w.Write([]byte("unknown host: " + r.Host + "\n"))
		h.log.Add(Entry{Method: r.Method, Host: host, Path: r.URL.RequestURI(), Status: 404, LatencyMS: ms(start)})
		return
	}

	client := h.remoteIP(r)

	// HTTP -> HTTPS redirect for plaintext requests on a redirect-enabled
	// route. r.TLS is non-nil exactly when the request arrived over TLS.
	if route.RedirectHTTP && r.TLS == nil {
		target := "https://" + r.Host + r.URL.RequestURI()
		w.Header().Set("Location", target)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(301)
		_, _ = w.Write([]byte("moved permanently\n"))
		h.log.Add(Entry{Method: r.Method, Host: host, Path: r.URL.RequestURI(), Status: 301, LatencyMS: ms(start), Redirect: true, Route: route.Name})
		return
	}

	// Source-IP allowlist (LAN-only routes).
	if !route.Allowed(client) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(403)
		_, _ = w.Write([]byte("forbidden: source not in allowlist\n"))
		h.log.Add(Entry{Method: r.Method, Host: host, Path: r.URL.RequestURI(), Backend: route.Backend, Client: ipStr(client), Status: 403, LatencyMS: ms(start), Denied: true, Route: route.Name})
		h.logger.Warn("allowlist denied", "host", host, "client", ipStr(client), "route", route.Name)
		return
	}

	rp := h.reverseProxy(route)
	cw := &captureWriter{ResponseWriter: w}
	rp.ServeHTTP(cw, r)

	entry := Entry{
		Method:    r.Method,
		Host:      host,
		Path:      r.URL.RequestURI(),
		Backend:   route.Backend,
		Client:    ipStr(client),
		Status:    cw.status,
		LatencyMS: ms(start),
		Route:     route.Name,
		WebSocket: cw.isWebSocket(),
	}
	h.log.Add(entry)
	if entry.Status >= 500 {
		h.logger.Error("upstream error", "host", host, "route", route.Name, "backend", route.Backend, "status", entry.Status)
	}
}

// reverseProxy returns a cached ReverseProxy for a route's backend, building
// it on first use.
func (h *Handler) reverseProxy(route *config.Route) *httputil.ReverseProxy {
	be := route.Backend
	h.pmu.RLock()
	rp, ok := h.proxies[be]
	h.pmu.RUnlock()
	if ok {
		return rp
	}

	u, err := url.Parse("http://" + be)
	if err != nil {
		h.logger.Error("bad backend", "backend", be, "err", err)
		u = &url.URL{Scheme: "http", Host: be}
	}

	rp = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			if req.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.logger.Error("proxy error", "host", r.Host, "backend", be, "err", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}

	h.pmu.Lock()
	if existing, ok := h.proxies[be]; ok {
		h.pmu.Unlock()
		return existing
	}
	h.proxies[be] = rp
	h.pmu.Unlock()
	return rp
}

var errNotHijacker = errors.New("underlying ResponseWriter is not a Hijacker")

func ms(start time.Time) int64 { return time.Since(start).Milliseconds() }

func ipStr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// captureWriter wraps a ResponseWriter to record the status code and detect
// WebSocket (101) upgrades for logging.
type captureWriter struct {
	http.ResponseWriter
	status int
}

func (c *captureWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

// Flush supports http.Flusher so streamed responses and WebSocket control
// frames pass through.
func (c *captureWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack supports http.Hijacker so ReverseProxy can hand the raw connection
// to the upgraded (WebSocket) protocol after the 101 response. Without it the
// proxy cannot complete an upgrade and returns 502.
func (c *captureWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := c.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errNotHijacker
}

func (c *captureWriter) isWebSocket() bool {
	return c.status == http.StatusSwitchingProtocols
}
