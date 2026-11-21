// Package admin implements GoFlow's embedded management UI: a single-admin
// login (password from the environment, bcrypt-hashed at rest, sessions as
// HttpOnly cookies) over server-rendered templates plus a small JSON API for
// route CRUD, reload, and the live request log.
package admin

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// EnvPassword is the environment variable holding the admin password at
// first start. The plaintext is never written to disk — only the bcrypt hash.
const EnvPassword = "GOFLOW_ADMIN_PASSWORD"

// sessionTTL is how long an admin session stays valid before it must be
// re-authenticated.
const sessionTTL = 12 * time.Hour

// Auth holds the admin password hash and the in-memory session table.
type Auth struct {
	hash     []byte
	sessions *SessionStore
	logger   *slog.Logger
}

// Bootstrap resolves the admin password in this order:
//
//  1. The GOFLOW_ADMIN_PASSWORD env var: hashed with bcrypt and written to
//     hashPath (0600) so later starts do not need the env var again.
//  2. An existing hashPath: loaded and used as-is.
//  3. Neither: a random 24-character password is generated, its hash written
//     to hashPath, and the plaintext is returned so it can be shown ONCE in
//     the startup log (never written to any file).
//
// The returned (generated bool) tells the caller to log the generated
// password.
func Bootstrap(hashPath string, logger *slog.Logger) (password string, generated bool, auth *Auth, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	env := os.Getenv(EnvPassword)
	if env != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(env), bcrypt.DefaultCost)
		if err != nil {
			return "", false, nil, fmt.Errorf("bcrypt: %w", err)
		}
		if err := writeHashFile(hashPath, hash); err != nil {
			return "", false, nil, err
		}
		logger.Info("admin: password set from environment, hash stored", "path", hashPath)
		return "", false, newAuth(hash, logger), nil
	}
	if data, err := os.ReadFile(hashPath); err == nil {
		return "", false, newAuth(data, logger), nil
	} else if !os.IsNotExist(err) {
		return "", false, nil, err
	}
	// First run with no env var: generate a password, show it once.
	pw, err := randomPassword(24)
	if err != nil {
		return "", false, nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", false, nil, fmt.Errorf("bcrypt: %w", err)
	}
	if err := writeHashFile(hashPath, hash); err != nil {
		return "", false, nil, err
	}
	logger.Warn("admin: no GOFLOW_ADMIN_PASSWORD set; generated a one-time password — it is logged here once and never stored in plaintext", "password", pw)
	return pw, true, newAuth(hash, logger), nil
}

func writeHashFile(path string, hash []byte) error {
	data := append(hash, '\n')
	if err := atomicWrite(path, data, 0o600); err != nil {
		return fmt.Errorf("write admin hash: %w", err)
	}
	return nil
}

func newAuth(hash []byte, logger *slog.Logger) *Auth {
	return &Auth{
		hash:     hash,
		sessions: NewSessionStore(),
		logger:   logger,
	}
}

// VerifyPassword checks a candidate against the stored bcrypt hash.
func (a *Auth) VerifyPassword(candidate string) bool {
	return bcrypt.CompareHashAndPassword(a.hash, []byte(candidate)) == nil
}

// Begin creates a new session and returns its token.
func (a *Auth) Begin() string {
	return a.sessions.Create(sessionTTL)
}

// Valid reports whether the session token is currently active (and slides
// its expiry).
func (a *Auth) Valid(token string) bool {
	if token == "" {
		return false
	}
	return a.sessions.Valid(token)
}

// End invalidates a session (logout).
func (a *Auth) End(token string) {
	a.sessions.Invalidate(token)
}

// ---- sessions ------------------------------------------------------------

// SessionStore is an in-memory token -> expiry table. It is deliberately not
// persisted: a restart logs everyone out, which is the safer default for an
// admin surface.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
}

// NewSessionStore builds an empty store.
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: map[string]time.Time{}}
}

// Create mints a random 256-bit token with a TTL.
func (s *SessionStore) Create(ttl time.Duration) string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal in practice; fall back to a
		// time-based token rather than panicking a web handler.
		return fmt.Sprintf("sess-%x-%d", time.Now().UnixNano(), os.Getpid())
	}
	tok := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[tok] = time.Now().Add(ttl)
	return tok
}

// Valid reports whether the token is present and unexpired, sliding its
// expiry on success.
func (s *SessionStore) Valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, token)
		return false
	}
	s.sessions[token] = time.Now().Add(sessionTTL)
	return true
}

// Invalidate removes a token.
func (s *SessionStore) Invalidate(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// ---- helpers -------------------------------------------------------------

func randomPassword(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out), nil
}
