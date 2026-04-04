package auth

import (
	"maps"
	"sync"
	"time"

	coreerr "dappco.re/go/core/log"
)

// ErrSessionNotFound is returned when a session token is not found.
// Usage: compare returned errors against ErrSessionNotFound when branching on failures.
var ErrSessionNotFound = coreerr.E("auth", "session not found", nil)

// SessionStore abstracts session persistence.
// Usage: use SessionStore with the other exported helpers in this package.
type SessionStore interface {
	Get(token string) (*Session, error)
	Set(session *Session) error
	Delete(token string) error
	DeleteByUser(userID string) error
	Cleanup() (int, error) // Remove expired sessions, return count removed
}

// MemorySessionStore is an in-memory SessionStore backed by a map.
// Usage: use MemorySessionStore with the other exported helpers in this package.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewMemorySessionStore creates a new in-memory session store.
// Usage: call NewMemorySessionStore(...) to create a ready-to-use value.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*Session),
	}
}

// Get retrieves a session by token.
// Usage: call Get(...) during the package's normal workflow.
func (m *MemorySessionStore) Get(token string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[token]
	if !exists {
		return nil, ErrSessionNotFound
	}

	// Return a copy to prevent mutation outside the lock
	s := *session
	return &s, nil
}

// Set stores a session, keyed by its token.
// Usage: call Set(...) during the package's normal workflow.
func (m *MemorySessionStore) Set(session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store a copy to prevent external mutation
	s := *session
	m.sessions[session.Token] = &s
	return nil
}

// Delete removes a session by token.
// Usage: call Delete(...) during the package's normal workflow.
func (m *MemorySessionStore) Delete(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[token]; !exists {
		return ErrSessionNotFound
	}

	delete(m.sessions, token)
	return nil
}

// DeleteByUser removes all sessions belonging to the given user.
// Usage: call DeleteByUser(...) during the package's normal workflow.
func (m *MemorySessionStore) DeleteByUser(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	maps.DeleteFunc(m.sessions, func(token string, session *Session) bool {
		return session.UserID == userID
	})
	return nil
}

// Cleanup removes all expired sessions and returns the count removed.
// Usage: call Cleanup(...) during the package's normal workflow.
func (m *MemorySessionStore) Cleanup() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	count := 0
	maps.DeleteFunc(m.sessions, func(token string, session *Session) bool {
		if now.After(session.ExpiresAt) {
			count++
			return true
		}
		return false
	})
	return count, nil
}
