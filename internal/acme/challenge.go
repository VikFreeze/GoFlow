package acme

import (
	"sync"
	"time"
)

// ChallengeStore holds pending HTTP-01 challenges: domain -> token ->
// challengeEntry. The ACME CA fetches
// http://<domain>/.well-known/acme-challenge/<token> and expects the key
// authorization as the response body. GoFlow serves that path itself (see
// NewIssuer + cmd wiring), which is what lets a single :80 listener both
// proxy and prove domain ownership.
//
// Entries are stamped with a deadline and evicted lazily so a forgotten
// CleanUp (e.g. a failed issuance) cannot leak memory.
type ChallengeStore struct {
	mu      sync.Mutex
	pending map[string]map[string]challengeEntry
}

type challengeEntry struct {
	keyAuth   string
	expiresAt time.Time
}

// NewChallengeStore builds an empty store.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{pending: map[string]map[string]challengeEntry{}}
}

// Present records a challenge. Called by lego before it tells the CA to
// fetch it.
func (s *ChallengeStore) Present(domain, token, keyAuth string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.pending[domain]
	if !ok {
		m = map[string]challengeEntry{}
		s.pending[domain] = m
	}
	m[token] = challengeEntry{keyAuth: keyAuth, expiresAt: time.Now().Add(10 * time.Minute)}
	return nil
}

// CleanUp removes a challenge after the CA has (or failed to) fetch it.
func (s *ChallengeStore) CleanUp(domain, token, keyAuth string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.pending[domain]; ok {
		delete(m, token)
		if len(m) == 0 {
			delete(s.pending, domain)
		}
	}
	return nil
}

// Lookup returns the key authorization for (domain, token), if present and
// not expired. The router calls this to answer challenge fetches.
func (s *ChallengeStore) Lookup(domain, token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked()
	c, ok := s.pending[domain][token]
	if !ok {
		return "", false
	}
	if time.Now().After(c.expiresAt) {
		delete(s.pending[domain], token)
		return "", false
	}
	return c.keyAuth, true
}

// evictLocked drops expired entries. Caller must hold s.mu.
func (s *ChallengeStore) evictLocked() {
	now := time.Now()
	for d, m := range s.pending {
		for t, c := range m {
			if now.After(c.expiresAt) {
				delete(m, t)
			}
		}
		if len(m) == 0 {
			delete(s.pending, d)
		}
	}
}
