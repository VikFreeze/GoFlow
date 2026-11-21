package proxy

import (
	"sync"
	"time"
)

// Entry is one logged request.
type Entry struct {
	Time      time.Time
	Method    string
	Host      string
	Path      string
	Backend   string
	Client    string
	Status    int
	LatencyMS int64
	WebSocket bool
	Redirect  bool
	Denied    bool
	Route     string
}

// Log is a bounded, mutex-protected ring buffer of recent requests. Appends
// are O(1) and the buffer never grows past n, so the live log view has a
// fixed memory ceiling. It is intentionally in-memory only: the on-disk
// request log was a deliberate non-goal (see docs/ARCHITECTURE.md).
type Log struct {
	mu    sync.Mutex
	buf   []Entry
	idx   int // next write position
	count int // total appended (wrap counter)
}

// NewLog creates a log that retains the most recent n entries.
func NewLog(n int) *Log {
	if n <= 0 {
		n = 512
	}
	return &Log{buf: make([]Entry, n)}
}

// Add records an entry.
func (l *Log) Add(e Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf[l.idx] = e
	l.idx = (l.idx + 1) % len(l.buf)
	if l.count < len(l.buf) {
		l.count++
	}
}

// Snapshot returns the most recent up-to-max entries, newest first.
func (l *Log) Snapshot(max int) []Entry {
	if max <= 0 {
		max = 100
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.count
	if n > len(l.buf) {
		n = len(l.buf)
	}
	out := make([]Entry, 0, n)
	if max > n {
		max = n
	}
	// Walk backwards from the next write position.
	for i := 0; i < max; i++ {
		pos := (l.idx - 1 - i + 2*len(l.buf)) % len(l.buf)
		out = append(out, l.buf[pos])
	}
	return out
}

// Len returns the number of entries currently retained (capped at the
// buffer size).
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}
