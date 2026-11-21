// Package tls manages GoFlow's server-side certificates: a hostname ->
// certificate map used by the HTTPS listener's GetCertificate callback, with
// per-route PEM loading and a self-signed fallback for development.
//
// Design notes (see docs/ARCHITECTURE.md §4): the HTTPS listener is a single
// :443-equivalent socket. A route's certificate is selected by SNI at
// handshake time, so each route can serve its own certificate on one port.
// When a route declares TLS but has no cert yet, a self-signed certificate
// is generated on demand so `curl -k` works in development; in production the
// ACME issuer (internal/acme) populates the real certificate.
package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store holds the hostname -> certificate mapping and hands out the
// tls.Config the HTTPS listener should use. It is safe for concurrent use.
type Store struct {
	mu   sync.RWMutex
	cert map[string]*tls.Certificate

	// fallback, when set, is returned for any SNI name that has no
	// registered certificate. It is a self-signed cert so the handshake
	// still completes (the client just sees an untrusted cert).
	fallback *tls.Certificate

	logger *slog.Logger
}

// NewStore builds an empty store. logger may be nil (defaults to slog.Default).
func NewStore(logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{
		cert:   map[string]*tls.Certificate{},
		logger: logger,
	}
}

// LoadRoute loads the PEM cert/key files for a single route and registers the
// certificate for every one of the route's hostnames. Relative paths are
// resolved against baseDir. If the files are missing or unreadable, it falls
// back to a self-signed certificate (so a dev deployment is never broken by a
// missing cert) and logs a warning.
//
// It returns the *tls.Certificate that was actually registered so callers
// (the ACME issuer) can inspect its expiry.
func (s *Store) LoadRoute(hosts []string, certFile, keyFile, baseDir string) (*tls.Certificate, error) {
	if certFile == "" || keyFile == "" {
		// No TLS declared for this route; nothing to register.
		return nil, nil
	}
	cert, err := loadPEM(certFile, keyFile, baseDir)
	if err != nil {
		s.logger.Warn("tls: falling back to self-signed",
			"cert", certFile, "key", keyFile, "err", err)
		cert, err = SelfSigned(hosts)
		if err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registerLocked(hosts, cert)
	return cert, nil
}

// SetCert registers a certificate (e.g. one freshly issued by the ACME
// issuer) for the given hostnames, replacing any existing entry.
func (s *Store) SetCert(hosts []string, cert *tls.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registerLocked(hosts, cert)
}

// SetFallback installs the certificate returned for unknown SNI names.
func (s *Store) SetFallback(cert *tls.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fallback = cert
}

// Hostnames returns the sorted set of hostnames with a registered cert (for
// diagnostics / the admin UI).
func (s *Store) Hostnames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.cert))
	for h := range s.cert {
		out = append(out, h)
	}
	return out
}

// Expiry returns the NotAfter of the certificate registered for host, if any.
func (s *Store) Expiry(host string) (time.Time, bool) {
	s.mu.RLock()
	c, ok := s.cert[host]
	s.mu.RUnlock()
	if !ok || len(c.Certificate) == 0 {
		return time.Time{}, false
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return time.Time{}, false
	}
	return leaf.NotAfter, true
}

// TLSConfig returns the *tls.Config for the HTTPS listener. GetCertificate
// selects by SNI; an unknown name returns the fallback (or an error, which
// aborts the handshake cleanly).
func (s *Store) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			s.mu.RLock()
			c, ok := s.cert[host]
			fb := s.fallback
			s.mu.RUnlock()
			if ok {
				return c, nil
			}
			if fb != nil {
				return fb, nil
			}
			// No cert at all yet: mint a throwaway self-signed for the
			// handshake so we never crash the listener.
			c, err := SelfSigned([]string{host, "goflow.local"})
			if err != nil {
				return nil, err
			}
			return c, nil
		},
	}
}

func (s *Store) registerLocked(hosts []string, cert *tls.Certificate) {
	for _, h := range hosts {
		s.cert[h] = cert
	}
}

// loadPEM reads a certificate and private key from PEM files.
func loadPEM(certFile, keyFile, baseDir string) (*tls.Certificate, error) {
	certPEM, err := readFile(certFile, baseDir)
	if err != nil {
		return nil, fmt.Errorf("cert: %w", err)
	}
	keyPEM, err := readFile(keyFile, baseDir)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("x509 key pair: %w", err)
	}
	return &cert, nil
}

func readFile(p, baseDir string) ([]byte, error) {
	if !filepath.IsAbs(p) && baseDir != "" {
		p = filepath.Join(baseDir, p)
	}
	return os.ReadFile(p)
}

// SelfSigned mints a self-signed certificate valid for the given hostnames
// (as IP addresses when they parse as IPs, otherwise DNS names) for one year.
// It is used for development and as a last-resort handshake fallback.
func SelfSigned(hosts []string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randInt(128)
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: firstHost(hosts, "goflow.local")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}

func firstHost(hosts []string, def string) string {
	for _, h := range hosts {
		if h != "" {
			return h
		}
	}
	return def
}

func randInt(bits int) (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	return rand.Int(rand.Reader, limit)
}
