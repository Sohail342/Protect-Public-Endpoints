package guard

import (
	"sync"
	"time"
)

// NonceStore is the optional replay cache. Seen records key and reports
// whether it was already present within ttl. A shared implementation (for
// example Redis SET NX PX) is needed when several instances serve traffic.
type NonceStore interface {
	Seen(key string, ttl time.Duration) bool
}

// MemoryStore is a single-process NonceStore.
type MemoryStore struct {
	mu    sync.Mutex
	m     map[string]time.Time
	sweep time.Time
	now   func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{m: map[string]time.Time{}, now: time.Now}
}

func (s *MemoryStore) Seen(key string, ttl time.Duration) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.After(s.sweep) {
		for k, exp := range s.m {
			if now.After(exp) {
				delete(s.m, k)
			}
		}
		s.sweep = now.Add(ttl)
	}
	if exp, ok := s.m[key]; ok && now.Before(exp) {
		return true
	}
	s.m[key] = now.Add(ttl)
	return false
}
