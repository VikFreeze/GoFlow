package proxy

import (
	"net"
	"net/http"
	"sync"

	"github.com/VikFreeze/goflow/internal/config"
)

// Matcher resolves a request Host to a route. It holds an immutable map of
// normalised hostname -> *config.Route, rebuilt wholesale on every
// configuration change. Because the map is only ever swapped, not mutated,
// readers can snapshot it without holding the lock for long (see Handler).
type Matcher struct {
	mu     sync.RWMutex
	byHost map[string]*config.Route
}

// NewMatcher builds a matcher from a config. Invalid configs are rejected by
// config.Validate before this is reached.
func NewMatcher(cfg *config.Config) *Matcher {
	m := &Matcher{byHost: make(map[string]*config.Route, len(cfg.Routes)*2)}
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		for _, h := range r.Hosts {
			m.byHost[config.NormaliseHost(h)] = r
		}
	}
	return m
}

// Resolve returns the route for a request Host. The host may carry a port;
// it is stripped before matching.
func (m *Matcher) Resolve(host string) (*config.Route, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.byHost[config.NormaliseHost(host)]
	return r, ok
}

// Hosts returns all normalised hostnames in the matcher (for debugging/UI).
func (m *Matcher) Hosts() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.byHost))
	for h := range m.byHost {
		out = append(out, h)
	}
	return out
}

// Count returns the number of distinct routes currently matched.
func (m *Matcher) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := map[*config.Route]bool{}
	for _, r := range m.byHost {
		seen[r] = true
	}
	return len(seen)
}

// RemoteIP extracts the client's source IP from the TCP peer, not from any
// request header. GoFlow is a LAN edge proxy; it does not trust
// X-Forwarded-For (a spoofed header would defeat the allowlist). Tests
// override the resolver via Handler.WithRemoteIP.
func RemoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
