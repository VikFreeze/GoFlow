// Package acme wraps lego to issue and renew Let's Encrypt certificates
// (HTTP-01 challenge) for GoFlow routes.
//
// The HTTP-01 challenge is served by GoFlow itself: the issuer registers a
// challenge store with the HTTP router, and /.well-known/acme-challenge/<token>
// requests are answered with the token's key authorization. This means a
// single :80 listener both proxies traffic and proves domain ownership — no
// separate port is needed (see docs/ARCHITECTURE.md §4).
//
// State is persisted under the config directory so restarts reuse the same
// ACME account and do not re-request already-valid certificates:
//
//	acme-account.json        account key + registration URI
//	acme-certs/<name>.crt    issued cert (PEM, bundle)
//	acme-certs/<name>.key    issued key (PEM)
//
// This is implemented but intentionally NOT exercised against the live
// Let's Encrypt API in tests (there is no public domain, and staging has
// rate limits). Unit tests cover challenge-store and renewal-scheduling
// logic; the README documents the manual procedure for a real issuance.
package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	gtls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	tlsx "github.com/VikFreeze/goflow/internal/tls"
)

// Directory URLs for the two ACME environments. Staging is the correct
// default for development: it does not count against production rate limits.
const (
	ProductionDirectory = lego.LEDirectoryProduction
	StagingDirectory    = lego.LEDirectoryStaging
)

// Route is the subset of a config.Route the issuer needs. It is defined here
// (not imported from internal/config) to keep the dependency direction clean:
// config has no knowledge of ACME.
type Route struct {
	Name  string
	Hosts []string
}

// Options configures an Issuer.
type Options struct {
	Email     string      // ACME account contact
	Directory string      // ACME directory URL; empty = staging
	ConfigDir string      // where account + issued certs are persisted
	Store     *tlsx.Store // certificates are installed here
	Logger    *slog.Logger
}

// Issuer issues and renews certificates for ACME-enabled routes.
type Issuer struct {
	email     string
	dirURL    string
	configDir string
	store     *tlsx.Store
	logger    *slog.Logger

	challenges *ChallengeStore

	mu  sync.Mutex
	acc *account
}

// NewIssuer builds an issuer. It does not contact the ACME server until
// Issue or Run is called.
func NewIssuer(opts Options) *Issuer {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	dir := opts.Directory
	if dir == "" {
		dir = StagingDirectory
	}
	return &Issuer{
		email:      opts.Email,
		dirURL:     dir,
		configDir:  opts.ConfigDir,
		store:      opts.Store,
		logger:     opts.Logger,
		challenges: NewChallengeStore(),
	}
}

// Challenges exposes the challenge store so the HTTP router can answer
// /.well-known/acme-challenge/<token> requests.
func (i *Issuer) Challenges() *ChallengeStore { return i.challenges }

// provider adapts the ChallengeStore to lego's challenge.Provider.
type provider struct{ s *ChallengeStore }

func (p provider) Present(domain, token, keyAuth string) error {
	return p.s.Present(domain, token, keyAuth)
}
func (p provider) CleanUp(domain, token, keyAuth string) error {
	return p.s.CleanUp(domain, token, keyAuth)
}

// Issue obtains (or reuses) a certificate for one route's hostnames and
// installs it into the TLS store. The ACME account is created/loaded on
// first use and persisted so restarts reuse it.
func (i *Issuer) Issue(route *Route) error {
	if i.email == "" {
		return errors.New("acme: no account email configured")
	}
	if len(route.Hosts) == 0 {
		return fmt.Errorf("acme: route %q has no hosts", route.Name)
	}

	// Reuse an existing, still-valid certificate if we have one on disk.
	if cert, notAfter, ok := i.loadIssued(route.Name); ok {
		if !RenewDue(notAfter) {
			i.logger.Info("acme: reusing existing certificate", "route", route.Name, "notAfter", notAfter)
			i.store.SetCert(route.Hosts, cert)
			return nil
		}
		i.logger.Info("acme: certificate expiring soon, reissuing", "route", route.Name)
	}

	acc, err := i.account()
	if err != nil {
		return err
	}
	if err := acc.client.Challenge.SetHTTP01Provider(provider{s: i.challenges}); err != nil {
		return fmt.Errorf("acme: set http-01 provider: %w", err)
	}

	res, err := acc.client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:                        route.Hosts,
		Bundle:                         true,
		AlwaysDeactivateAuthorizations: true,
	})
	if err != nil {
		return fmt.Errorf("acme: obtain for %v: %w", route.Hosts, err)
	}
	if err := i.persistIssued(route.Name, res); err != nil {
		i.logger.Warn("acme: could not persist issued certificate", "route", route.Name, "err", err)
	}
	cert, err := gtls.X509KeyPair(res.Certificate, res.PrivateKey)
	if err != nil {
		return fmt.Errorf("acme: load issued pair: %w", err)
	}
	i.store.SetCert(route.Hosts, &cert)
	i.logger.Info("acme: certificate installed", "route", route.Name, "hosts", route.Hosts)
	return nil
}

const (
	// RenewBefore is how close to expiry a renewal is triggered.
	RenewBefore = 30 * 24 * time.Hour
	// checkInterval is how often the background loop inspects certificates.
	checkInterval = time.Hour
)

// RenewDue reports whether a certificate should be renewed now (expiring
// within RenewBefore, or already expired). Exported for tests.
func RenewDue(notAfter time.Time) bool {
	return time.Until(notAfter) <= RenewBefore
}

// Run issues for all routes (best effort: a failure logs and continues) and
// starts a background renewal loop. The returned stop function halts the
// loop.
func (i *Issuer) Run(routes []*Route) (stop func()) {
	for _, r := range routes {
		if err := i.Issue(r); err != nil {
			i.logger.Error("acme: initial issuance failed", "route", r.Name, "err", err)
		}
	}
	stopCh := make(chan struct{})
	go func() {
		t := time.NewTicker(checkInterval)
		defer t.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-t.C:
				for _, r := range routes {
					i.renewIfNeeded(r)
				}
			}
		}
	}()
	return func() { close(stopCh) }
}

func (i *Issuer) renewIfNeeded(route *Route) {
	_, notAfter, ok := i.loadIssued(route.Name)
	if !ok {
		if err := i.Issue(route); err != nil {
			i.logger.Warn("acme: issuance attempt failed", "route", route.Name, "err", err)
		}
		return
	}
	if !RenewDue(notAfter) {
		return
	}
	i.logger.Info("acme: renewing certificate", "route", route.Name, "notAfter", notAfter)
	if err := i.Issue(route); err != nil {
		i.logger.Error("acme: renewal failed", "route", route.Name, "err", err)
	}
}

// ---- account management -------------------------------------------------

type account struct {
	client *lego.Client
}

type user struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *user) GetEmail() string                        { return u.email }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }
func (u *user) GetRegistration() *registration.Resource { return u.registration }

// accountFile is the persisted ACME account state.
type accountFile struct {
	Email        string `json:"email"`
	KeyPEM       string `json:"key"`
	Registration string `json:"registration,omitempty"`
}

func (i *Issuer) accountPath() string {
	return filepath.Join(i.configDir, "acme-account.json")
}

// account returns the cached ACME account, loading it from disk or creating
// and registering a new one. lego's Register is idempotent: re-registering
// with the same key makes the CA return the existing account (409 is
// handled inside lego).
func (i *Issuer) account() (*account, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.acc != nil {
		return i.acc, nil
	}

	var af accountFile
	if data, err := os.ReadFile(i.accountPath()); err == nil {
		if err := json.Unmarshal(data, &af); err != nil {
			return nil, fmt.Errorf("acme: parse account file: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if af.KeyPEM == "" {
		pemBytes, err := genRSAPem()
		if err != nil {
			return nil, fmt.Errorf("acme: generate account key: %w", err)
		}
		af.KeyPEM = string(pemBytes)
	}
	key, err := parseKeyPEM([]byte(af.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("acme: parse account key: %w", err)
	}

	u := &user{email: af.Email, key: key}
	if af.Registration != "" {
		u.registration = &registration.Resource{URI: af.Registration}
	}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = i.dirURL
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("acme: new client: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("acme: register: %w", err)
	}
	af.Email = i.email
	af.Registration = reg.URI
	if err := i.writeAccountFile(&af); err != nil {
		i.logger.Warn("acme: could not persist account", "err", err)
	}
	i.acc = &account{client: client}
	return i.acc, nil
}

func (i *Issuer) writeAccountFile(af *accountFile) error {
	data, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(i.accountPath(), data, 0o600)
}

// ---- issued certificate persistence -------------------------------------

func (i *Issuer) certsDir() string { return filepath.Join(i.configDir, "acme-certs") }

func (i *Issuer) persistIssued(routeName string, res *certificate.Resource) error {
	if err := os.MkdirAll(i.certsDir(), 0o755); err != nil {
		return err
	}
	if err := atomicWriteFile(filepath.Join(i.certsDir(), routeName+".crt"), res.Certificate, 0o644); err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(i.certsDir(), routeName+".key"), res.PrivateKey, 0o600)
}

// loadIssued reads a previously issued certificate for a route from disk.
func (i *Issuer) loadIssued(routeName string) (*gtls.Certificate, time.Time, bool) {
	crt, err := os.ReadFile(filepath.Join(i.certsDir(), routeName+".crt"))
	if err != nil {
		return nil, time.Time{}, false
	}
	key, err := os.ReadFile(filepath.Join(i.certsDir(), routeName+".key"))
	if err != nil {
		return nil, time.Time{}, false
	}
	cert, err := gtls.X509KeyPair(crt, key)
	if err != nil {
		return nil, time.Time{}, false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, time.Time{}, false
	}
	return &cert, leaf.NotAfter, true
}

// ---- key helpers ---------------------------------------------------------

// parseKeyPEM decodes a PEM private key (PKCS8, EC or RSA).
func parseKeyPEM(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unrecognised private key PEM")
}

// genRSAPem generates an RSA 2048 account key, PEM-encoded (PKCS1).
func genRSAPem() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), nil
}

// atomicWriteFile writes data to path via a temp file + rename so a crash
// mid-write never leaves a partial file.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
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
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

var _ challenge.Provider = provider{}
