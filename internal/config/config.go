// Package config defines GoFlow's on-disk configuration: the list of routes
// and how they are validated and persisted.
//
// Persistence is a single JSON document written atomically (temp file +
// rename in the same directory). A crash mid-write therefore never leaves a
// corrupt config file. See docs/ARCHITECTURE.md for the rationale behind
// choosing JSON over SQLite.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Config is the persisted state of a GoFlow instance: the ordered list of
// routes. Hostname -> route resolution is derived from this list by the proxy
// package (see proxy.NewMatcher).
type Config struct {
	Routes []Route `json:"routes"`
}

// Route is one virtual host entry. A route may match several hostnames
// (aliases); all of them are resolved to the same Backend.
type Route struct {
	// Name is a stable, human-readable identifier used by the admin UI. It
	// must be unique across routes.
	Name string `json:"name"`

	// Hosts are the hostnames (with optional :port) routed here. The first
	// entry is the primary hostname; the rest are aliases.
	Hosts []string `json:"hosts"`

	// Backend is the upstream "host:port" the route proxies to.
	Backend string `json:"backend"`

	// Allowlist holds CIDR (or single-IP) entries. When non-empty, only
	// clients whose source IP matches one of them are served; every other
	// client gets 403. When empty, the route accepts any source.
	Allowlist []string `json:"allowlist,omitempty"`

	// TLSCertFile / TLSKeyFile are PEM files for this route's certificate.
	// They are resolved relative to the config directory when relative.
	TLSCertFile string `json:"tlsCertFile,omitempty"`
	TLSKeyFile  string `json:"tlsKeyFile,omitempty"`

	// ACME enables automatic certificate issuance for this route's
	// hostnames via Let's Encrypt (HTTP-01). It is implemented but not
	// exercised in the test suite (no public domain); see the README.
	ACME bool `json:"acme,omitempty"`

	// RedirectHTTP causes the plaintext HTTP listener to issue a 301 to the
	// HTTPS URL for any request whose Host matches this route.
	RedirectHTTP bool `json:"redirectHttp,omitempty"`
}

// hostRe matches a hostname label with an optional :port. It deliberately
// disallows wildcards: v1 is exact-match only (see docs/DESIGN.md §3.1).
var hostRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(:\d+)?$`)

// NormaliseHost lower-cases a host and strips its :port so that matching is
// done on the bare hostname. "Files.dev.test:443" ->
// "files.dev.test". An IPv4/IPv6 literal is returned lower-cased with
// its bracket/port removed.
func NormaliseHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if strings.HasPrefix(h, "[") {
		// IPv6 literal: [2001:db8::1]:port
		if i := strings.IndexByte(h, ']'); i >= 0 {
			return h[len("["):i]
		}
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		// Only strip if the part after ':' is all digits (a port), so a
		// bare IPv6 literal without brackets is not mangled.
		if allDigits(h[i+1:]) {
			h = h[:i]
		}
	}
	return h
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Validate checks a single route for correctness, returning a descriptive
// error on the first problem found. Relative TLS cert paths are resolved
// against the process working directory; use ValidateIn to anchor them at
// the config directory instead.
func (r Route) Validate() error {
	if err := r.validateCommon(); err != nil {
		return err
	}
	return r.checkCertFiles("")
}

// ValidateIn is like Validate but resolves relative TLS cert paths against
// baseDir (the config directory) rather than the working directory.
func (r Route) ValidateIn(baseDir string) error {
	if err := r.validateCommon(); err != nil {
		return err
	}
	return r.checkCertFiles(baseDir)
}

// validateCommon checks every field except TLS cert file existence.
func (r Route) validateCommon() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("route: name is required")
	}
	if len(r.Hosts) == 0 {
		return fmt.Errorf("route %q: at least one host is required", r.Name)
	}
	seen := map[string]bool{}
	for _, h := range r.Hosts {
		nh := NormaliseHost(h)
		if nh == "" {
			return fmt.Errorf("route %q: invalid host %q", r.Name, h)
		}
		if !hostRe.MatchString(strings.TrimPrefix(h, "[")) {
			return fmt.Errorf("route %q: host %q is not a valid hostname (no wildcards in v1)", r.Name, h)
		}
		if seen[nh] {
			return fmt.Errorf("route %q: duplicate host %q", r.Name, h)
		}
		seen[nh] = true
	}
	if strings.TrimSpace(r.Backend) == "" {
		return fmt.Errorf("route %q: backend is required", r.Name)
	}
	if _, _, err := net.SplitHostPort(r.Backend); err != nil {
		return fmt.Errorf("route %q: backend %q must be host:port: %w", r.Name, r.Backend, err)
	}
	for _, cidr := range r.Allowlist {
		if _, err := parseCIDR(cidr); err != nil {
			return fmt.Errorf("route %q: bad allowlist entry %q: %w", r.Name, cidr, err)
		}
	}
	return nil
}

// checkCertFiles ensures declared TLS cert files exist, resolving relative
// paths against baseDir (empty = current working directory).
func (r Route) checkCertFiles(baseDir string) error {
	if r.TLSCertFile == "" && r.TLSKeyFile == "" {
		return nil
	}
	if r.TLSCertFile == "" || r.TLSKeyFile == "" {
		return fmt.Errorf("route %q: tlsCertFile and tlsKeyFile must be set together", r.Name)
	}
	if r.ACME {
		// ACME manages the cert; nothing to check on disk.
		return nil
	}
	for _, f := range []string{r.TLSCertFile, r.TLSKeyFile} {
		p := f
		if !filepath.IsAbs(p) && baseDir != "" {
			p = filepath.Join(baseDir, p)
		}
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("route %q: cert file %q: %w", r.Name, f, err)
		}
	}
	return nil
}

// ParseCIDR accepts "a.b.c.d" (a single IP) or "a.b.c.d/m". It returns the
// parsed network.
func ParseCIDR(s string) (*net.IPNet, error) {
	return parseCIDR(s)
}

// parseCIDR accepts "a.b.c.d" (a single IP) or "a.b.c.d/m". It returns the
// parsed network.
func parseCIDR(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("%q is not an IP or CIDR", s)
		}
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		// A bare IP is a host route: /32 or /128.
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// Allowed reports whether clientIP is permitted by this route's allowlist.
// An empty allowlist permits everyone (open route). Otherwise the client
// must fall inside at least one CIDR entry.
func (r Route) Allowed(clientIP net.IP) bool {
	if len(r.Allowlist) == 0 {
		return true
	}
	for _, entry := range r.Allowlist {
		n, err := parseCIDR(entry)
		if err != nil {
			// A malformed entry should have failed Validate(); treat it as
			// non-matching rather than open.
			continue
		}
		if n.Contains(clientIP) {
			return true
		}
	}
	return false
}

// Validate checks the whole config and rejects duplicate route names or
// duplicate hostnames across routes.
func (c *Config) Validate() error {
	return c.ValidateIn("")
}

// ValidateIn is like Validate but anchors relative TLS cert paths at baseDir.
func (c *Config) ValidateIn(baseDir string) error {
	nameSeen := map[string]bool{}
	hostSeen := map[string]string{}
	for _, r := range c.Routes {
		if err := r.ValidateIn(baseDir); err != nil {
			return err
		}
		if nameSeen[r.Name] {
			return fmt.Errorf("duplicate route name %q", r.Name)
		}
		nameSeen[r.Name] = true
		for _, h := range r.Hosts {
			nh := NormaliseHost(h)
			if other, dup := hostSeen[nh]; dup {
				return fmt.Errorf("host %q claimed by both routes %q and %q", nh, other, r.Name)
			}
			hostSeen[nh] = r.Name
		}
	}
	return nil
}

// Load reads a config from a JSON file. A missing file yields an empty,
// valid config (first run) rather than an error.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// Anchor relative TLS cert paths at the config file's directory.
	if err := c.ValidateIn(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save atomically writes the config as indented JSON. It creates the parent
// directory if needed.
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".goflow-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Path returns the canonical config file path inside dir.
func Path(dir string) string { return filepath.Join(dir, "routes.json") }

// LoadAdminHash reads a bcrypt hash from path. A missing file returns ("",
// nil). The hash is the only form the admin password is ever stored in —
// never plaintext.
func LoadAdminHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// SaveAdminHash writes a bcrypt hash atomically with 0600 perms.
func SaveAdminHash(path, hash string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".admin-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(hash + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
