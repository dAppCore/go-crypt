package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	core "dappco.re/go/core"

	"dappco.re/go/crypt/crypt/lthn"
	"dappco.re/go/io"
)

// --- MemorySessionStore ---

func TestSessionStore_MemorySessionStore_GetSetDelete_Good(t *testing.T) {
	store := NewMemorySessionStore()

	session := &Session{
		Token:     "test-token-abc",
		UserID:    "user-123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Set
	err := store.Set(session)
	mustNoError(t, err)

	// Get
	got, err := store.Get("test-token-abc")
	mustNoError(t, err)
	wantEqual(t, session.Token, got.Token)
	wantEqual(t, session.UserID, got.UserID)

	// Delete
	err = store.Delete("test-token-abc")
	mustNoError(t, err)

	// Get after delete should fail
	_, err = store.Get("test-token-abc")
	wantErrorIs(t, err, ErrSessionNotFound)
}

func TestSessionStore_MemorySessionStore_GetNotFound_Bad(t *testing.T) {
	store := NewMemorySessionStore()

	_, err := store.Get("nonexistent-token")
	wantErrorIs(t, err, ErrSessionNotFound)
}

func TestSessionStore_MemorySessionStore_DeleteNotFound_Bad(t *testing.T) {
	store := NewMemorySessionStore()

	err := store.Delete("nonexistent-token")
	wantErrorIs(t, err, ErrSessionNotFound)
}

func TestSessionStore_MemorySessionStore_DeleteByUser_Good(t *testing.T) {
	store := NewMemorySessionStore()

	// Create sessions for two users
	for i := range 3 {
		err := store.Set(&Session{
			Token:     core.Sprintf("user-a-token-%d", i),
			UserID:    "user-a",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		})
		mustNoError(t, err)
	}

	err := store.Set(&Session{
		Token:     "user-b-token",
		UserID:    "user-b",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	mustNoError(t, err)

	// Delete all user-a sessions
	err = store.DeleteByUser("user-a")
	mustNoError(t, err)

	// user-a sessions should be gone
	for i := range 3 {
		_, err := store.Get(core.Sprintf("user-a-token-%d", i))
		wantErrorIs(t, err, ErrSessionNotFound)
	}

	// user-b session should remain
	got, err := store.Get("user-b-token")
	mustNoError(t, err)
	wantEqual(t, "user-b", got.UserID)
}

func TestSessionStore_MemorySessionStore_Cleanup_Good(t *testing.T) {
	store := NewMemorySessionStore()

	// Create expired and valid sessions
	err := store.Set(&Session{
		Token:     "expired-1",
		UserID:    "user",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	mustNoError(t, err)

	err = store.Set(&Session{
		Token:     "expired-2",
		UserID:    "user",
		ExpiresAt: time.Now().Add(-30 * time.Minute),
	})
	mustNoError(t, err)

	err = store.Set(&Session{
		Token:     "valid-1",
		UserID:    "user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	mustNoError(t, err)

	count, err := store.Cleanup()
	mustNoError(t, err)
	wantEqual(t, 2, count)

	// Valid session should remain
	_, err = store.Get("valid-1")
	wantNoError(t, err)

	// Expired sessions should be gone
	_, err = store.Get("expired-1")
	wantErrorIs(t, err, ErrSessionNotFound)
	_, err = store.Get("expired-2")
	wantErrorIs(t, err, ErrSessionNotFound)
}

func TestSessionStore_MemorySessionStore_Concurrent_Good(t *testing.T) {
	store := NewMemorySessionStore()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)

	for i := range n {
		go func(idx int) {
			defer wg.Done()
			token := core.Sprintf("concurrent-token-%d", idx)

			err := store.Set(&Session{
				Token:     token,
				UserID:    core.Sprintf("user-%d", idx%5),
				ExpiresAt: time.Now().Add(1 * time.Hour),
			})
			wantNoError(t, err)

			got, err := store.Get(token)
			wantNoError(t, err)
			wantEqual(t, token, got.Token)
		}(i)
	}

	wg.Wait()
}

// --- SQLiteSessionStore ---

func TestSessionStore_SQLiteSessionStore_GetSetDelete_Good(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	mustNoError(t, err)
	defer store.Close()

	session := &Session{
		Token:     "sqlite-token-abc",
		UserID:    "user-456",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Set
	err = store.Set(session)
	mustNoError(t, err)

	// Get
	got, err := store.Get("sqlite-token-abc")
	mustNoError(t, err)
	wantEqual(t, session.Token, got.Token)
	wantEqual(t, session.UserID, got.UserID)

	// Delete
	err = store.Delete("sqlite-token-abc")
	mustNoError(t, err)

	// Get after delete should fail
	_, err = store.Get("sqlite-token-abc")
	wantErrorIs(t, err, ErrSessionNotFound)
}

func TestSessionStore_SQLiteSessionStore_GetNotFound_Bad(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	mustNoError(t, err)
	defer store.Close()

	_, err = store.Get("nonexistent-token")
	wantErrorIs(t, err, ErrSessionNotFound)
}

func TestSessionStore_SQLiteSessionStore_DeleteNotFound_Bad(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	mustNoError(t, err)
	defer store.Close()

	err = store.Delete("nonexistent-token")
	wantErrorIs(t, err, ErrSessionNotFound)
}

func TestSessionStore_SQLiteSessionStore_DeleteByUser_Good(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	mustNoError(t, err)
	defer store.Close()

	// Create sessions for two users
	for i := range 3 {
		err := store.Set(&Session{
			Token:     core.Sprintf("sqlite-user-a-%d", i),
			UserID:    "user-a",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		})
		mustNoError(t, err)
	}

	err = store.Set(&Session{
		Token:     "sqlite-user-b",
		UserID:    "user-b",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	mustNoError(t, err)

	// Delete all user-a sessions
	err = store.DeleteByUser("user-a")
	mustNoError(t, err)

	// user-a sessions should be gone
	for i := range 3 {
		_, err := store.Get(core.Sprintf("sqlite-user-a-%d", i))
		wantErrorIs(t, err, ErrSessionNotFound)
	}

	// user-b session should remain
	got, err := store.Get("sqlite-user-b")
	mustNoError(t, err)
	wantEqual(t, "user-b", got.UserID)
}

func TestSessionStore_SQLiteSessionStore_Cleanup_Good(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	mustNoError(t, err)
	defer store.Close()

	// Create expired and valid sessions
	err = store.Set(&Session{
		Token:     "sqlite-expired-1",
		UserID:    "user",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	mustNoError(t, err)

	err = store.Set(&Session{
		Token:     "sqlite-expired-2",
		UserID:    "user",
		ExpiresAt: time.Now().Add(-30 * time.Minute),
	})
	mustNoError(t, err)

	err = store.Set(&Session{
		Token:     "sqlite-valid-1",
		UserID:    "user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	mustNoError(t, err)

	count, err := store.Cleanup()
	mustNoError(t, err)
	wantEqual(t, 2, count)

	// Valid session should remain
	_, err = store.Get("sqlite-valid-1")
	wantNoError(t, err)

	// Expired sessions should be gone
	_, err = store.Get("sqlite-expired-1")
	wantErrorIs(t, err, ErrSessionNotFound)
	_, err = store.Get("sqlite-expired-2")
	wantErrorIs(t, err, ErrSessionNotFound)
}

func TestSessionStore_SQLiteSessionStore_Persistence_Good(t *testing.T) {
	dir := t.TempDir()
	dbPath := core.Path(dir, "sessions.db")

	// Write a session
	store1, err := NewSQLiteSessionStore(dbPath)
	mustNoError(t, err)

	session := &Session{
		Token:     "persist-token",
		UserID:    "persist-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	err = store1.Set(session)
	mustNoError(t, err)

	// Close the store
	err = store1.Close()
	mustNoError(t, err)

	// Reopen and verify data persists
	store2, err := NewSQLiteSessionStore(dbPath)
	mustNoError(t, err)
	defer store2.Close()

	got, err := store2.Get("persist-token")
	mustNoError(t, err)
	wantEqual(t, "persist-user", got.UserID)
	wantEqual(t, "persist-token", got.Token)
}

func TestSessionStore_SQLiteSessionStore_Concurrent_Good(t *testing.T) {
	// Use a temp file — :memory: SQLite has concurrency limitations
	dbPath := core.Path(t.TempDir(), "concurrent.db")
	store, err := NewSQLiteSessionStore(dbPath)
	mustNoError(t, err)
	defer store.Close()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)

	for i := range n {
		go func(idx int) {
			defer wg.Done()
			token := core.Sprintf("sqlite-concurrent-%d", idx)

			err := store.Set(&Session{
				Token:     token,
				UserID:    core.Sprintf("user-%d", idx%5),
				ExpiresAt: time.Now().Add(1 * time.Hour),
			})
			wantNoError(t, err)

			got, err := store.Get(token)
			wantNoError(t, err)
			if got != nil {
				wantEqual(t, token, got.Token)
			}
		}(i)
	}

	wg.Wait()
}

// --- Authenticator with SessionStore ---

func TestSessionStore_Authenticator_WithSessionStore_Good(t *testing.T) {
	sqliteStore, err := NewSQLiteSessionStore(":memory:")
	mustNoError(t, err)
	defer sqliteStore.Close()

	m := io.NewMockMedium()
	a := New(m, WithSessionStore(sqliteStore))

	// Register user
	_, err = a.Register("store-test-user", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("store-test-user")

	// Login creates session in SQLite store
	session, err := a.Login(userID, "pass")
	mustNoError(t, err)
	mustNotNil(t, session)

	// Validate session from store
	validated, err := a.ValidateSession(session.Token)
	mustNoError(t, err)
	wantEqual(t, session.Token, validated.Token)
	wantEqual(t, userID, validated.UserID)

	// Refresh session
	refreshed, err := a.RefreshSession(session.Token)
	mustNoError(t, err)
	wantEqual(t, session.Token, refreshed.Token)

	// Revoke session
	err = a.RevokeSession(session.Token)
	mustNoError(t, err)

	// Session should be gone
	_, err = a.ValidateSession(session.Token)
	wantError(t, err)
	wantContains(t, err.Error(), "session not found")
}

func TestSessionStore_Authenticator_DefaultStore_Good(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m)

	// Default store should be MemorySessionStore
	_, ok := a.store.(*MemorySessionStore)
	wantTrue(t, ok, "default store should be MemorySessionStore")
}

func TestSessionStore_Authenticator_StartCleanup_Good(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m, WithSessionTTL(1*time.Millisecond))

	// Register and login to create a session
	_, err := a.Register("cleanup-test", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("cleanup-test")

	session, err := a.Login(userID, "pass")
	mustNoError(t, err)

	// Wait for session to expire
	time.Sleep(5 * time.Millisecond)

	// Start cleanup with a short interval
	ctx := t.Context()

	a.StartCleanup(ctx, 10*time.Millisecond)

	// Wait for at least one cleanup cycle
	time.Sleep(50 * time.Millisecond)

	// Session should have been cleaned up
	_, err = a.ValidateSession(session.Token)
	wantError(t, err)
	wantContains(t, err.Error(), "session not found")
}

func TestSessionStore_Authenticator_StartCleanup_CancelStops_Good(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m)

	ctx, cancel := context.WithCancel(context.Background())
	a.StartCleanup(ctx, 10*time.Millisecond)

	// Cancel should stop the goroutine without panic
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestSessionStore_SQLiteSessionStore_UpdateExisting_Good(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	mustNoError(t, err)
	defer store.Close()

	original := &Session{
		Token:     "update-token",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	err = store.Set(original)
	mustNoError(t, err)

	// Update with new expiry
	updated := &Session{
		Token:     "update-token",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(2 * time.Hour),
	}
	err = store.Set(updated)
	mustNoError(t, err)

	got, err := store.Get("update-token")
	mustNoError(t, err)
	wantTrue(t, got.ExpiresAt.After(original.ExpiresAt),
		"updated session should have later expiry")
}

func TestSessionStore_SQLiteSessionStore_TempFile_Good(t *testing.T) {
	// Verify we can use a real temp file (not :memory:)
	tmpFile := core.Path(t.TempDir(), "go-crypt-test-session-store.db")

	store, err := NewSQLiteSessionStore(tmpFile)
	mustNoError(t, err)

	err = store.Set(&Session{
		Token:     "temp-file-token",
		UserID:    "user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	mustNoError(t, err)

	got, err := store.Get("temp-file-token")
	mustNoError(t, err)
	wantEqual(t, "temp-file-token", got.Token)

	err = store.Close()
	mustNoError(t, err)
}
