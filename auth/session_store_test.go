package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	core "dappco.re/go/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"dappco.re/go/core/crypt/crypt/lthn"
	"dappco.re/go/core/io"
)

// --- MemorySessionStore ---

func TestMemorySessionStore_GetSetDelete_Good(t *testing.T) {
	store := NewMemorySessionStore()

	session := &Session{
		Token:     "test-token-abc",
		UserID:    "user-123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Set
	err := store.Set(session)
	require.NoError(t, err)

	// Get
	got, err := store.Get("test-token-abc")
	require.NoError(t, err)
	assert.Equal(t, session.Token, got.Token)
	assert.Equal(t, session.UserID, got.UserID)

	// Delete
	err = store.Delete("test-token-abc")
	require.NoError(t, err)

	// Get after delete should fail
	_, err = store.Get("test-token-abc")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestMemorySessionStore_GetNotFound_Bad(t *testing.T) {
	store := NewMemorySessionStore()

	_, err := store.Get("nonexistent-token")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestMemorySessionStore_DeleteNotFound_Bad(t *testing.T) {
	store := NewMemorySessionStore()

	err := store.Delete("nonexistent-token")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestMemorySessionStore_DeleteByUser_Good(t *testing.T) {
	store := NewMemorySessionStore()

	// Create sessions for two users
	for i := range 3 {
		err := store.Set(&Session{
			Token:     core.Sprintf("user-a-token-%d", i),
			UserID:    "user-a",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		})
		require.NoError(t, err)
	}

	err := store.Set(&Session{
		Token:     "user-b-token",
		UserID:    "user-b",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	// Delete all user-a sessions
	err = store.DeleteByUser("user-a")
	require.NoError(t, err)

	// user-a sessions should be gone
	for i := range 3 {
		_, err := store.Get(core.Sprintf("user-a-token-%d", i))
		assert.ErrorIs(t, err, ErrSessionNotFound)
	}

	// user-b session should remain
	got, err := store.Get("user-b-token")
	require.NoError(t, err)
	assert.Equal(t, "user-b", got.UserID)
}

func TestMemorySessionStore_Cleanup_Good(t *testing.T) {
	store := NewMemorySessionStore()

	// Create expired and valid sessions
	err := store.Set(&Session{
		Token:     "expired-1",
		UserID:    "user",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	require.NoError(t, err)

	err = store.Set(&Session{
		Token:     "expired-2",
		UserID:    "user",
		ExpiresAt: time.Now().Add(-30 * time.Minute),
	})
	require.NoError(t, err)

	err = store.Set(&Session{
		Token:     "valid-1",
		UserID:    "user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	count, err := store.Cleanup()
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Valid session should remain
	_, err = store.Get("valid-1")
	assert.NoError(t, err)

	// Expired sessions should be gone
	_, err = store.Get("expired-1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	_, err = store.Get("expired-2")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestMemorySessionStore_Concurrent_Good(t *testing.T) {
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
			assert.NoError(t, err)

			got, err := store.Get(token)
			assert.NoError(t, err)
			assert.Equal(t, token, got.Token)
		}(i)
	}

	wg.Wait()
}

// --- SQLiteSessionStore ---

func TestSQLiteSessionStore_GetSetDelete_Good(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	session := &Session{
		Token:     "sqlite-token-abc",
		UserID:    "user-456",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Set
	err = store.Set(session)
	require.NoError(t, err)

	// Get
	got, err := store.Get("sqlite-token-abc")
	require.NoError(t, err)
	assert.Equal(t, session.Token, got.Token)
	assert.Equal(t, session.UserID, got.UserID)

	// Delete
	err = store.Delete("sqlite-token-abc")
	require.NoError(t, err)

	// Get after delete should fail
	_, err = store.Get("sqlite-token-abc")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestSQLiteSessionStore_GetNotFound_Bad(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	_, err = store.Get("nonexistent-token")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestSQLiteSessionStore_DeleteNotFound_Bad(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	err = store.Delete("nonexistent-token")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestSQLiteSessionStore_DeleteByUser_Good(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	// Create sessions for two users
	for i := range 3 {
		err := store.Set(&Session{
			Token:     core.Sprintf("sqlite-user-a-%d", i),
			UserID:    "user-a",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		})
		require.NoError(t, err)
	}

	err = store.Set(&Session{
		Token:     "sqlite-user-b",
		UserID:    "user-b",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	// Delete all user-a sessions
	err = store.DeleteByUser("user-a")
	require.NoError(t, err)

	// user-a sessions should be gone
	for i := range 3 {
		_, err := store.Get(core.Sprintf("sqlite-user-a-%d", i))
		assert.ErrorIs(t, err, ErrSessionNotFound)
	}

	// user-b session should remain
	got, err := store.Get("sqlite-user-b")
	require.NoError(t, err)
	assert.Equal(t, "user-b", got.UserID)
}

func TestSQLiteSessionStore_Cleanup_Good(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	// Create expired and valid sessions
	err = store.Set(&Session{
		Token:     "sqlite-expired-1",
		UserID:    "user",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	require.NoError(t, err)

	err = store.Set(&Session{
		Token:     "sqlite-expired-2",
		UserID:    "user",
		ExpiresAt: time.Now().Add(-30 * time.Minute),
	})
	require.NoError(t, err)

	err = store.Set(&Session{
		Token:     "sqlite-valid-1",
		UserID:    "user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	count, err := store.Cleanup()
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Valid session should remain
	_, err = store.Get("sqlite-valid-1")
	assert.NoError(t, err)

	// Expired sessions should be gone
	_, err = store.Get("sqlite-expired-1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	_, err = store.Get("sqlite-expired-2")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestSQLiteSessionStore_Persistence_Good(t *testing.T) {
	dir := t.TempDir()
	dbPath := core.Path(dir, "sessions.db")

	// Write a session
	store1, err := NewSQLiteSessionStore(dbPath)
	require.NoError(t, err)

	session := &Session{
		Token:     "persist-token",
		UserID:    "persist-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	err = store1.Set(session)
	require.NoError(t, err)

	// Close the store
	err = store1.Close()
	require.NoError(t, err)

	// Reopen and verify data persists
	store2, err := NewSQLiteSessionStore(dbPath)
	require.NoError(t, err)
	defer store2.Close()

	got, err := store2.Get("persist-token")
	require.NoError(t, err)
	assert.Equal(t, "persist-user", got.UserID)
	assert.Equal(t, "persist-token", got.Token)
}

func TestSQLiteSessionStore_Concurrent_Good(t *testing.T) {
	// Use a temp file — :memory: SQLite has concurrency limitations
	dbPath := core.Path(t.TempDir(), "concurrent.db")
	store, err := NewSQLiteSessionStore(dbPath)
	require.NoError(t, err)
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
			assert.NoError(t, err)

			got, err := store.Get(token)
			assert.NoError(t, err)
			if got != nil {
				assert.Equal(t, token, got.Token)
			}
		}(i)
	}

	wg.Wait()
}

// --- Authenticator with SessionStore ---

func TestAuthenticator_WithSessionStore_Good(t *testing.T) {
	sqliteStore, err := NewSQLiteSessionStore(":memory:")
	require.NoError(t, err)
	defer sqliteStore.Close()

	m := io.NewMockMedium()
	a := New(m, WithSessionStore(sqliteStore))

	// Register user
	_, err = a.Register("store-test-user", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("store-test-user")

	// Login creates session in SQLite store
	session, err := a.Login(userID, "pass")
	require.NoError(t, err)
	require.NotNil(t, session)

	// Validate session from store
	validated, err := a.ValidateSession(session.Token)
	require.NoError(t, err)
	assert.Equal(t, session.Token, validated.Token)
	assert.Equal(t, userID, validated.UserID)

	// Refresh session
	refreshed, err := a.RefreshSession(session.Token)
	require.NoError(t, err)
	assert.Equal(t, session.Token, refreshed.Token)

	// Revoke session
	err = a.RevokeSession(session.Token)
	require.NoError(t, err)

	// Session should be gone
	_, err = a.ValidateSession(session.Token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestAuthenticator_DefaultStore_Good(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m)

	// Default store should be MemorySessionStore
	_, ok := a.store.(*MemorySessionStore)
	assert.True(t, ok, "default store should be MemorySessionStore")
}

func TestAuthenticator_StartCleanup_Good(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m, WithSessionTTL(1*time.Millisecond))

	// Register and login to create a session
	_, err := a.Register("cleanup-test", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("cleanup-test")

	session, err := a.Login(userID, "pass")
	require.NoError(t, err)

	// Wait for session to expire
	time.Sleep(5 * time.Millisecond)

	// Start cleanup with a short interval
	ctx := t.Context()

	a.StartCleanup(ctx, 10*time.Millisecond)

	// Wait for at least one cleanup cycle
	time.Sleep(50 * time.Millisecond)

	// Session should have been cleaned up
	_, err = a.ValidateSession(session.Token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestAuthenticator_StartCleanup_CancelStops_Good(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m)

	ctx, cancel := context.WithCancel(context.Background())
	a.StartCleanup(ctx, 10*time.Millisecond)

	// Cancel should stop the goroutine without panic
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestSQLiteSessionStore_UpdateExisting_Good(t *testing.T) {
	store, err := NewSQLiteSessionStore(":memory:")
	require.NoError(t, err)
	defer store.Close()

	original := &Session{
		Token:     "update-token",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	err = store.Set(original)
	require.NoError(t, err)

	// Update with new expiry
	updated := &Session{
		Token:     "update-token",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(2 * time.Hour),
	}
	err = store.Set(updated)
	require.NoError(t, err)

	got, err := store.Get("update-token")
	require.NoError(t, err)
	assert.True(t, got.ExpiresAt.After(original.ExpiresAt),
		"updated session should have later expiry")
}

func TestSQLiteSessionStore_TempFile_Good(t *testing.T) {
	// Verify we can use a real temp file (not :memory:)
	tmpFile := core.Path(t.TempDir(), "go-crypt-test-session-store.db")

	store, err := NewSQLiteSessionStore(tmpFile)
	require.NoError(t, err)

	err = store.Set(&Session{
		Token:     "temp-file-token",
		UserID:    "user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	got, err := store.Get("temp-file-token")
	require.NoError(t, err)
	assert.Equal(t, "temp-file-token", got.Token)

	err = store.Close()
	require.NoError(t, err)
}
