package auth

import (
<<<<<<< HEAD
	"sync"
=======
	"encoding/json"
	"errors"
	"sync" // Note: AX-6 — internal concurrency primitive; structural for SQLite single-writer serialisation.
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
	"time"

	core "dappco.re/go/core"
	"dappco.re/go/store"
)

const sessionGroup = "sessions"

// SQLiteSessionStore is a SessionStore backed by core/store (SQLite KV).
// A mutex serialises all operations because SQLite is single-writer.
// Usage: use SQLiteSessionStore with the other exported helpers in this package.
type SQLiteSessionStore struct {
	mu    sync.Mutex
	store *store.Store
}

// NewSQLiteSessionStore creates a new SQLite-backed session store.
// Use ":memory:" for testing or a file path for persistent storage.
// Usage: call NewSQLiteSessionStore(...) to create a ready-to-use value.
func NewSQLiteSessionStore(dbPath string) (*SQLiteSessionStore, error) {
	s, err := store.New(dbPath)
	if err != nil {
		return nil, err
	}
	return &SQLiteSessionStore{store: s}, nil
}

// Get retrieves a session by token from SQLite.
// Usage: call Get(...) during the package's normal workflow.
func (s *SQLiteSessionStore) Get(token string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	val, err := s.store.Get(sessionGroup, token)
	if err != nil {
		if core.Is(err, store.ErrNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	var session Session
	result := core.JSONUnmarshal([]byte(val), &session)
	if !result.OK {
		err, _ := result.Value.(error)
		return nil, err
	}
	return &session, nil
}

// Set stores a session in SQLite, keyed by its token.
// Usage: call Set(...) during the package's normal workflow.
func (s *SQLiteSessionStore) Set(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := core.JSONMarshal(session)
	if !result.OK {
		err, _ := result.Value.(error)
		return err
	}
	return s.store.Set(sessionGroup, session.Token, string(result.Value.([]byte)))
}

// Delete removes a session by token from SQLite.
// Usage: call Delete(...) during the package's normal workflow.
func (s *SQLiteSessionStore) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check existence first to return ErrSessionNotFound
	_, err := s.store.Get(sessionGroup, token)
	if err != nil {
		if core.Is(err, store.ErrNotFound) {
			return ErrSessionNotFound
		}
		return err
	}
	return s.store.Delete(sessionGroup, token)
}

// DeleteByUser removes all sessions belonging to the given user.
// Usage: call DeleteByUser(...) during the package's normal workflow.
func (s *SQLiteSessionStore) DeleteByUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.store.GetAll(sessionGroup)
	if err != nil {
		return err
	}

	for token, val := range all {
		var session Session
		result := core.JSONUnmarshal([]byte(val), &session)
		if !result.OK {
			continue // Skip malformed entries
		}
		if session.UserID == userID {
			if err := s.store.Delete(sessionGroup, token); err != nil {
				return err
			}
		}
	}
	return nil
}

// Cleanup removes all expired sessions and returns the count removed.
// Usage: call Cleanup(...) during the package's normal workflow.
func (s *SQLiteSessionStore) Cleanup() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.store.GetAll(sessionGroup)
	if err != nil {
		return 0, err
	}

	now := time.Now()
	count := 0
	for token, val := range all {
		var session Session
		result := core.JSONUnmarshal([]byte(val), &session)
		if !result.OK {
			continue // Skip malformed entries
		}
		if now.After(session.ExpiresAt) {
			if err := s.store.Delete(sessionGroup, token); err != nil {
				return count, err
			}
			count++
		}
	}
	return count, nil
}

// Close closes the underlying SQLite store.
// Usage: call Close(...) during the package's normal workflow.
func (s *SQLiteSessionStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.store.Close()
}
