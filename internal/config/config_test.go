package config

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormaliseHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"files.dev.test", "files.dev.test"},
		{"Files.Dev.Test", "files.dev.test"},
		{"files.dev.test:443", "files.dev.test"},
		{"localhost:18080", "localhost"},
		{"192.168.1.5:8080", "192.168.1.5"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"  shares.dev.test ", "shares.dev.test"},
	}
	for _, c := range cases {
		if got := NormaliseHost(c.in); got != c.want {
			t.Errorf("NormaliseHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRouteValidate(t *testing.T) {
	cases := []struct {
		name    string
		r       Route
		wantErr string
	}{
		{"ok", Route{Name: "a", Hosts: []string{"a.example.com"}, Backend: "127.0.0.1:80"}, ""},
		{"ok alias", Route{Name: "a", Hosts: []string{"a.example.com", "b.example.com"}, Backend: "127.0.0.1:80"}, ""},
		{"ok ipv6 backend", Route{Name: "a", Hosts: []string{"a.example.com"}, Backend: "[::1]:80"}, ""},
		{"no name", Route{Hosts: []string{"a.example.com"}, Backend: "127.0.0.1:80"}, "name"},
		{"no hosts", Route{Name: "a", Backend: "127.0.0.1:80"}, "host"},
		{"no backend", Route{Name: "a", Hosts: []string{"a.example.com"}}, "backend"},
		{"bad backend", Route{Name: "a", Hosts: []string{"a.example.com"}, Backend: "nohostport"}, "host:port"},
		{"bad cidr", Route{Name: "a", Hosts: []string{"a.example.com"}, Backend: "127.0.0.1:80", Allowlist: []string{"not-a-cidr"}}, "allowlist"},
		{"wildcard rejected", Route{Name: "a", Hosts: []string{"*.example.com"}, Backend: "127.0.0.1:80"}, "wildcard"},
		{"dup host", Route{Name: "a", Hosts: []string{"x.example.com", "X.example.com"}, Backend: "127.0.0.1:80"}, "duplicate host"},
	}
	for _, c := range cases {
		err := c.r.Validate()
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: want error containing %q, got %v", c.name, c.wantErr, err)
		}
	}
}

func TestConfigValidateDuplicateHost(t *testing.T) {
	c := &Config{Routes: []Route{
		{Name: "a", Hosts: []string{"shared.example.com"}, Backend: "127.0.0.1:1"},
		{Name: "b", Hosts: []string{"shared.example.com"}, Backend: "127.0.0.1:2"},
	}}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "shared.example.com") {
		t.Fatalf("want cross-route duplicate host error, got %v", err)
	}
}

func TestAllowed(t *testing.T) {
	lan := net.ParseIP("192.168.1.50")
	other := net.ParseIP("8.8.8.8")

	cases := []struct {
		name  string
		allow []string
		ip    net.IP
		want  bool
	}{
		{"empty allowlist allows all", nil, other, true},
		{"single ip allow", []string{"192.168.1.50"}, lan, true},
		{"single ip deny", []string{"192.168.1.50"}, other, false},
		{"cidr allow", []string{"192.168.1.0/24"}, lan, true},
		{"cidr deny", []string{"10.0.0.0/8"}, other, false},
		{"multi one matches", []string{"10.0.0.0/8", "192.168.1.0/24"}, lan, true},
		{"multi none match", []string{"10.0.0.0/8", "172.16.0.0/12"}, other, false},
	}
	for _, c := range cases {
		r := Route{Name: "r", Allowlist: c.allow}
		if got := r.Allowed(c.ip); got != c.want {
			t.Errorf("%s: Allowed(%v) = %v, want %v", c.name, c.ip, got, c.want)
		}
	}
}

func TestParseCIDR(t *testing.T) {
	for _, in := range []string{"1.2.3.4", "10.0.0.0/8", "::1", "2001:db8::/32"} {
		if _, err := ParseCIDR(in); err != nil {
			t.Errorf("ParseCIDR(%q) error: %v", in, err)
		}
	}
	if _, err := ParseCIDR("nope"); err == nil {
		t.Error("ParseCIDR(nope) should error")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "routes.json")
	c := &Config{Routes: []Route{
		{
			Name:         "files",
			Hosts:        []string{"files.dev.test", "shares.dev.test"},
			Backend:      "127.0.0.1:41240",
			Allowlist:    []string{"192.168.0.0/16", "10.0.0.0/8"},
			RedirectHTTP: true,
		},
	}}
	if err := c.Save(p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Routes) != 1 {
		t.Fatalf("want 1 route, got %d", len(got.Routes))
	}
	r := got.Routes[0]
	if r.Name != "files" || len(r.Hosts) != 2 || r.Backend != "127.0.0.1:41240" || !r.RedirectHTTP {
		t.Errorf("round-trip mismatch: %+v", r)
	}
	if !r.Allowed(net.ParseIP("192.168.5.5")) {
		t.Error("192.168.5.5 should be allowed after round trip")
	}
	if r.Allowed(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should be denied after round trip")
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("Load(missing) should not error, got %v", err)
	}
	if len(c.Routes) != 0 {
		t.Fatalf("want empty config, got %+v", c)
	}
}

func TestSaveAtomicNoLeftoverTmp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "routes.json")
	c := &Config{}
	if err := c.Save(p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Re-saving must not leave temp files behind.
	for i := 0; i < 5; i++ {
		if err := c.Save(p); err != nil {
			t.Fatalf("Save %d: %v", i, err)
		}
	}
	entries, _ := filepath.Glob(filepath.Join(dir, ".goflow-*.tmp"))
	if len(entries) != 0 {
		t.Errorf("leftover temp files: %v", entries)
	}
}
