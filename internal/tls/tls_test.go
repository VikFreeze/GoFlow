package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mintPEM mints a self-signed cert for the given hosts and writes cert/key
// PEM files into dir; it returns the file names and the NotAfter time.
func mintPEM(t *testing.T, dir string, name string, hosts []string) (certFile, keyFile string, notAfter time.Time) {
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
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certFile = filepath.Join(dir, name+".crt")
	keyFile = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, tmpl.NotAfter
}

func TestSelfSigned(t *testing.T) {
	cert, err := SelfSigned([]string{"a.example.com", "b.example.com", "127.0.0.1"})
	if err != nil {
		t.Fatalf("self-signed: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	names := strings.Join(leaf.DNSNames, ",")
	for _, want := range []string{"a.example.com", "b.example.com"} {
		if !strings.Contains(names, want) {
			t.Errorf("DNSNames %q missing %q", names, want)
		}
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v, want 127.0.0.1", leaf.IPAddresses)
	}
	if leaf.NotBefore.After(time.Now()) || leaf.NotAfter.Before(time.Now().Add(364*24*time.Hour)) {
		t.Errorf("bad validity: %v .. %v", leaf.NotBefore, leaf.NotAfter)
	}
}

func TestStoreSNISelection(t *testing.T) {
	dir := t.TempDir()
	_, _, _ = mintPEM(t, dir, "one", []string{"one.example.com"})
	_, _, _ = mintPEM(t, dir, "two", []string{"two.example.com", "two-alias.example.com"})

	s := NewStore(nil)
	c1, err := s.LoadRoute([]string{"one.example.com"}, "one.crt", "one.key", dir)
	if err != nil {
		t.Fatalf("load one: %v", err)
	}
	c2, err := s.LoadRoute([]string{"two.example.com", "two-alias.example.com"}, "two.crt", "two.key", dir)
	if err != nil {
		t.Fatalf("load two: %v", err)
	}
	if c1 == c2 {
		t.Fatal("expected two distinct certificates")
	}

	// Hostname map: each alias of a route resolves to that route's cert.
	cfg := s.TLSConfig()
	cases := []struct {
		sni  string
		want *tls.Certificate
	}{
		{"one.example.com", c1},
		{"two.example.com", c2},
		{"two-alias.example.com", c2},
	}
	for _, tc := range cases {
		got, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: tc.sni})
		if err != nil {
			t.Fatalf("SNI %s: %v", tc.sni, err)
		}
		if got != tc.want {
			t.Errorf("SNI %s returned the wrong certificate", tc.sni)
		}
	}
}

func TestStoreUnknownSNIUsesFallback(t *testing.T) {
	s := NewStore(nil)
	fb, err := SelfSigned([]string{"fallback.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s.SetFallback(fb)
	cfg := s.TLSConfig()
	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.com"})
	if err != nil {
		t.Fatalf("unknown SNI: %v", err)
	}
	if got != fb {
		t.Error("unknown SNI should return the fallback certificate")
	}
}

func TestStoreUnknownSNIWithoutFallbackSelfSigns(t *testing.T) {
	// No fallback set: the handshake still completes via an on-demand
	// self-signed cert, so the listener never crashes on a cold SNI.
	s := NewStore(nil)
	cfg := s.TLSConfig()
	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "cold.example.com"})
	if err != nil {
		t.Fatalf("cold SNI: %v", err)
	}
	if got == nil {
		t.Fatal("expected a certificate for a cold SNI")
	}
}

func TestLoadRouteMissingFilesFallBackToSelfSigned(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(nil)
	cert, err := s.LoadRoute([]string{"dev.example.com"}, "nope.crt", "nope.key", dir)
	if err != nil {
		t.Fatalf("missing files should fall back, got error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected a self-signed fallback certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.IsCA {
		// SelfSigned is self-issued: issuer == subject.
		if leaf.Subject.CommonName != "dev.example.com" {
			t.Errorf("CN %q, want dev.example.com", leaf.Subject.CommonName)
		}
	}
	// And the route's hostname now resolves to that cert.
	cfg := s.TLSConfig()
	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "dev.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got != cert {
		t.Error("fallback cert not registered for the route host")
	}
}

func TestLoadRouteNoTLSDeclared(t *testing.T) {
	s := NewStore(nil)
	cert, err := s.LoadRoute([]string{"plain.example.com"}, "", "", t.TempDir())
	if err != nil {
		t.Fatalf("no TLS declared should be a no-op, got %v", err)
	}
	if cert != nil {
		t.Error("expected nil cert when no files declared")
	}
}

func TestExpiry(t *testing.T) {
	dir := t.TempDir()
	_, _, want := mintPEM(t, dir, "exp", []string{"exp.example.com"})
	s := NewStore(nil)
	if _, err := s.LoadRoute([]string{"exp.example.com"}, "exp.crt", "exp.key", dir); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Expiry("exp.example.com")
	if !ok {
		t.Fatal("Expiry: not found")
	}
	// Certificates store times at second precision; allow a 2s window.
	d := got.Sub(want)
	if d < -2*time.Second || d > 2*time.Second {
		t.Errorf("expiry %v, want ~%v", got, want)
	}
	if _, ok := s.Expiry("missing.example.com"); ok {
		t.Error("Expiry: unknown host should report not found")
	}
}

func TestHostnames(t *testing.T) {
	dir := t.TempDir()
	mintPEM(t, dir, "h", []string{"h.example.com"})
	s := NewStore(nil)
	if _, err := s.LoadRoute([]string{"h.example.com", "h2.example.com"}, "h.crt", "h.key", dir); err != nil {
		t.Fatal(err)
	}
	hosts := s.Hostnames()
	if len(hosts) != 2 {
		t.Errorf("Hostnames = %v, want 2 entries", hosts)
	}
}
