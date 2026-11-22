package acme

import (
	"testing"
	"time"
)

func TestChallengeStorePresentLookupCleanup(t *testing.T) {
	s := NewChallengeStore()
	if err := s.Present("a.example.com", "tok1", "auth-abc"); err != nil {
		t.Fatalf("present: %v", err)
	}
	got, ok := s.Lookup("a.example.com", "tok1")
	if !ok || got != "auth-abc" {
		t.Fatalf("lookup = (%q, %v), want (auth-abc, true)", got, ok)
	}
	if err := s.CleanUp("a.example.com", "tok1", "auth-abc"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, ok := s.Lookup("a.example.com", "tok1"); ok {
		t.Error("lookup after cleanup should miss")
	}
	// Cleanup of an unknown entry is a no-op.
	if err := s.CleanUp("a.example.com", "ghost", ""); err != nil {
		t.Fatalf("cleanup ghost: %v", err)
	}
}

func TestChallengeStoreLookupWrongDomain(t *testing.T) {
	s := NewChallengeStore()
	_ = s.Present("a.example.com", "tok", "auth")
	if _, ok := s.Lookup("b.example.com", "tok"); ok {
		t.Error("challenge must be domain-scoped")
	}
}

func TestChallengeStoreExpiredEntryEvicted(t *testing.T) {
	s := NewChallengeStore()
	// Insert an already-expired entry directly (Present uses a 10 min TTL,
	// so reaching expiry through the public API would need real time).
	s.pending["a.example.com"] = map[string]challengeEntry{
		"old": {keyAuth: "auth-old", expiresAt: time.Now().Add(-time.Second)},
	}
	if _, ok := s.Lookup("a.example.com", "old"); ok {
		t.Fatal("expired challenge must not be returned")
	}
	// Eviction must have removed it.
	if len(s.pending["a.example.com"]) != 0 {
		t.Error("expired entry should be evicted from the store")
	}
}

func TestRenewDue(t *testing.T) {
	cases := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"expired", time.Now().Add(-time.Hour), true},
		{"within 30d", time.Now().Add(10 * 24 * time.Hour), true},
		{"just under window", time.Now().Add(RenewBefore - time.Hour), true},
		{"just over window", time.Now().Add(RenewBefore + time.Hour), false},
		{"one year out", time.Now().Add(365 * 24 * time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RenewDue(tc.notAfter); got != tc.want {
				t.Errorf("RenewDue(%v) = %v, want %v", tc.notAfter, got, tc.want)
			}
		})
	}
}

func TestIssuerRequiresEmail(t *testing.T) {
	i := NewIssuer(Options{ConfigDir: t.TempDir()})
	if err := i.Issue(&Route{Name: "r", Hosts: []string{"a.example.com"}}); err == nil {
		t.Fatal("Issue without an email must fail")
	}
}

func TestProviderImplementsLegoProvider(t *testing.T) {
	// Compile-time guarantee that provider satisfies lego's interface
	// (also asserted via var _ at package level; this exercises the
	// Present/CleanUp round-trip through the adapter).
	s := NewChallengeStore()
	p := provider{s: s}
	if err := p.Present("x.example.com", "t", "ka"); err != nil {
		t.Fatalf("present: %v", err)
	}
	if ka, ok := s.Lookup("x.example.com", "t"); !ok || ka != "ka" {
		t.Fatalf("lookup after present = (%q, %v)", ka, ok)
	}
	if err := p.CleanUp("x.example.com", "t", "ka"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
