package auth

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"dappco.re/go/core/store"
)

const sessionGroup = "sessions"

// SQLiteSessionStore is a SessionStore backed by core/store (SQLite KV).
// A mutex serialises all operations because SQLite is single-writer.
type SQLiteSessionStore struct {
	mu    sync.Mutex
	store *store.Store
}

// NewSQLiteSessionStore creates a new SQLite-backed session store.
// Use ":memory:" for testing or a file path for persistent storage.
func NewSQLiteSessionStore(dbPath string) (*SQLiteSessionStore, error) {
	s, err := store.New(dbPath)
	if err != nil {
		return nil, err
	}
	return &SQLiteSessionStore{store: s}, nil
}

// Get retrieves a session by token from SQLite.
func (s *SQLiteSessionStore) Get(token string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	val, err := s.store.Get(sessionGroup, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	var session Session
	if err := json.Unmarshal([]byte(val), &session); err != nil {
		return nil, err
	}
	return &session, nil
}

// Set stores a session in SQLite, keyed by its token.
func (s *SQLiteSessionStore) Set(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return s.store.Set(sessionGroup, session.Token, string(data))
}

// Delete removes a session by token from SQLite.
func (s *SQLiteSessionStore) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check existence first to return ErrSessionNotFound
	_, err := s.store.Get(sessionGroup, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrSessionNotFound
		}
		return err
	}
	return s.store.Delete(sessionGroup, token)
}

// DeleteByUser removes all sessions belonging to the given user.
func (s *SQLiteSessionStore) DeleteByUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	all, err := s.store.GetAll(sessionGroup)
	if err != nil {
		return err
	}

	for token, val := range all {
		var session Session
		if err := json.Unmarshal([]byte(val), &session); err != nil {
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
		if err := json.Unmarshal([]byte(val), &session); err != nil {
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
func (s *SQLiteSessionStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.store.Close()
}
