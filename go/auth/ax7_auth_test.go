package auth

import (
	"context"
	"sync"
	"time"

	core "dappco.re/go"
	"dappco.re/go/crypt/crypt/lthn"
	"dappco.re/go/crypt/crypt/pgp"
	"dappco.re/go/io"
)

type ax7HardwareKey struct{}

func (ax7HardwareKey) Sign(data []byte) ([]byte, error) {
	return append([]byte("signed:"), data...), nil
}

func (ax7HardwareKey) Decrypt(ciphertext []byte) ([]byte, error) {
	return append([]byte("plain:"), ciphertext...), nil
}

func (ax7HardwareKey) GetPublicKey() (string, error) {
	return "public-key", nil
}

func (ax7HardwareKey) IsAvailable() bool {
	return true
}

type ax7CleanupErrorStore struct {
	mu    sync.Mutex
	calls int
}

func (s *ax7CleanupErrorStore) Get(string) (*Session, error) {
	return nil, ErrSessionNotFound
}

func (s *ax7CleanupErrorStore) Set(*Session) error {
	return nil
}

func (s *ax7CleanupErrorStore) Delete(string) error {
	return ErrSessionNotFound
}

func (s *ax7CleanupErrorStore) DeleteByUser(string) error {
	return nil
}

func (s *ax7CleanupErrorStore) Cleanup() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return 0, core.NewError("cleanup failed")
}

func (s *ax7CleanupErrorStore) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func ax7Session(token, userID string, expiresAt time.Time) *Session {
	return &Session{Token: token, UserID: userID, ExpiresAt: expiresAt}
}

func ax7SQLiteStore(t *core.T) *SQLiteSessionStore {
	t.Helper()
	store, err := NewSQLiteSessionStore(":memory:")
	core.RequireNoError(t, err)
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

func TestAX7Auth_New_Good(t *core.T) {
	a := New(io.NewMockMedium())
	core.AssertNotNil(t, a)
	core.AssertEqual(t, DefaultChallengeTTL, a.challengeTTL)
	core.AssertEqual(t, DefaultSessionTTL, a.sessionTTL)
}

func TestAX7Auth_New_Bad(t *core.T) {
	a := New(nil)
	core.AssertNotNil(t, a)
	core.AssertNil(t, a.medium)
}

func TestAX7Auth_New_Ugly(t *core.T) {
	medium := io.NewMockMedium()
	core.AssertPanics(t, func() {
		_ = New(medium, nil)
	})
	core.AssertNotNil(t, medium)
}

func TestAX7Auth_WithChallengeTTL_Good(t *core.T) {
	a := New(io.NewMockMedium(), WithChallengeTTL(30*time.Second))
	core.AssertEqual(t, 30*time.Second, a.challengeTTL)
	core.AssertEqual(t, DefaultSessionTTL, a.sessionTTL)
}

func TestAX7Auth_WithChallengeTTL_Bad(t *core.T) {
	a := New(io.NewMockMedium(), WithChallengeTTL(-1*time.Second))
	core.AssertEqual(t, -1*time.Second, a.challengeTTL)
	core.AssertNotNil(t, a.store)
}

func TestAX7Auth_WithChallengeTTL_Ugly(t *core.T) {
	a := New(io.NewMockMedium(), WithChallengeTTL(0))
	core.AssertEqual(t, time.Duration(0), a.challengeTTL)
	core.AssertNotNil(t, a.challenges)
}

func TestAX7Auth_WithSessionTTL_Good(t *core.T) {
	a := New(io.NewMockMedium(), WithSessionTTL(2*time.Hour))
	core.AssertEqual(t, 2*time.Hour, a.sessionTTL)
	core.AssertEqual(t, DefaultChallengeTTL, a.challengeTTL)
}

func TestAX7Auth_WithSessionTTL_Bad(t *core.T) {
	a := New(io.NewMockMedium(), WithSessionTTL(-1*time.Second))
	core.AssertEqual(t, -1*time.Second, a.sessionTTL)
	core.AssertNotNil(t, a.store)
}

func TestAX7Auth_WithSessionTTL_Ugly(t *core.T) {
	a := New(io.NewMockMedium(), WithSessionTTL(0))
	core.AssertEqual(t, time.Duration(0), a.sessionTTL)
	core.AssertNotNil(t, a.challenges)
}

func TestAX7Auth_WithSessionStore_Good(t *core.T) {
	store := NewMemorySessionStore()
	a := New(io.NewMockMedium(), WithSessionStore(store))
	core.AssertEqual(t, store, a.store)
	core.AssertNotNil(t, a.medium)
}

func TestAX7Auth_WithSessionStore_Bad(t *core.T) {
	a := New(io.NewMockMedium(), WithSessionStore(nil))
	_, ok := a.store.(*MemorySessionStore)
	core.AssertTrue(t, ok)
}

func TestAX7Auth_WithSessionStore_Ugly(t *core.T) {
	store := &ax7CleanupErrorStore{}
	a := New(io.NewMockMedium(), WithSessionStore(store))
	core.AssertEqual(t, store, a.store)
	core.AssertEqual(t, 0, store.Calls())
}

func TestAX7Auth_WithHardwareKey_Good(t *core.T) {
	hk := ax7HardwareKey{}
	a := New(io.NewMockMedium(), WithHardwareKey(hk))
	core.AssertNotNil(t, a.hardwareKey)
	core.AssertTrue(t, a.hardwareKey.IsAvailable())
}

func TestAX7Auth_WithHardwareKey_Bad(t *core.T) {
	a := New(io.NewMockMedium(), WithHardwareKey(nil))
	core.AssertNil(t, a.hardwareKey)
	core.AssertNotNil(t, a.store)
}

func TestAX7Auth_WithHardwareKey_Ugly(t *core.T) {
	hk := ax7HardwareKey{}
	a := New(io.NewMockMedium(), WithHardwareKey(hk), WithHardwareKey(nil))
	core.AssertNil(t, a.hardwareKey)
	core.AssertNotNil(t, a.challenges)
}

func TestAX7Auth_NewMemorySessionStore_Good(t *core.T) {
	store := NewMemorySessionStore()
	core.AssertNotNil(t, store)
	core.AssertEqual(t, 0, len(store.sessions))
}

func TestAX7Auth_NewMemorySessionStore_Bad(t *core.T) {
	store := NewMemorySessionStore()
	_, err := store.Get("missing")
	core.AssertError(t, err)
	core.AssertEqual(t, 0, len(store.sessions))
}

func TestAX7Auth_NewMemorySessionStore_Ugly(t *core.T) {
	first := NewMemorySessionStore()
	second := NewMemorySessionStore()
	core.AssertNotNil(t, first.sessions)
	core.AssertTrue(t, first != second)
}

func TestAX7Auth_MemorySessionStore_Set_Good(t *core.T) {
	store := NewMemorySessionStore()
	err := store.Set(ax7Session("token", "user", time.Now().Add(time.Hour)))
	core.AssertNoError(t, err)
	core.AssertEqual(t, 1, len(store.sessions))
}

func TestAX7Auth_MemorySessionStore_Set_Bad(t *core.T) {
	store := NewMemorySessionStore()
	core.AssertPanics(t, func() {
		_ = store.Set(nil)
	})
	core.AssertEqual(t, 0, len(store.sessions))
}

func TestAX7Auth_MemorySessionStore_Set_Ugly(t *core.T) {
	store := NewMemorySessionStore()
	err := store.Set(ax7Session("", "", time.Time{}))
	core.AssertNoError(t, err)
	core.AssertEqual(t, 1, len(store.sessions))
}

func TestAX7Auth_MemorySessionStore_Get_Good(t *core.T) {
	store := NewMemorySessionStore()
	core.RequireNoError(t, store.Set(ax7Session("token", "user", time.Now().Add(time.Hour))))
	session, err := store.Get("token")
	core.AssertNoError(t, err)
	core.AssertEqual(t, "user", session.UserID)
}

func TestAX7Auth_MemorySessionStore_Get_Bad(t *core.T) {
	store := NewMemorySessionStore()
	session, err := store.Get("missing")
	core.AssertError(t, err)
	core.AssertNil(t, session)
}

func TestAX7Auth_MemorySessionStore_Get_Ugly(t *core.T) {
	store := NewMemorySessionStore()
	core.RequireNoError(t, store.Set(ax7Session("token", "user", time.Now().Add(time.Hour))))
	session, err := store.Get("token")
	core.RequireNoError(t, err)
	session.UserID = "changed"
	again, err := store.Get("token")
	core.AssertNoError(t, err)
	core.AssertEqual(t, "user", again.UserID)
}

func TestAX7Auth_MemorySessionStore_Delete_Good(t *core.T) {
	store := NewMemorySessionStore()
	core.RequireNoError(t, store.Set(ax7Session("token", "user", time.Now().Add(time.Hour))))
	err := store.Delete("token")
	core.AssertNoError(t, err)
	core.AssertEqual(t, 0, len(store.sessions))
}

func TestAX7Auth_MemorySessionStore_Delete_Bad(t *core.T) {
	store := NewMemorySessionStore()
	err := store.Delete("missing")
	core.AssertError(t, err)
	core.AssertEqual(t, 0, len(store.sessions))
}

func TestAX7Auth_MemorySessionStore_Delete_Ugly(t *core.T) {
	store := NewMemorySessionStore()
	core.RequireNoError(t, store.Set(ax7Session("", "user", time.Now().Add(time.Hour))))
	err := store.Delete("")
	core.AssertNoError(t, err)
	core.AssertEqual(t, 0, len(store.sessions))
}

func TestAX7Auth_MemorySessionStore_DeleteByUser_Good(t *core.T) {
	store := NewMemorySessionStore()
	core.RequireNoError(t, store.Set(ax7Session("a", "user", time.Now().Add(time.Hour))))
	core.RequireNoError(t, store.Set(ax7Session("b", "other", time.Now().Add(time.Hour))))
	err := store.DeleteByUser("user")
	core.AssertNoError(t, err)
	core.AssertEqual(t, 1, len(store.sessions))
}

func TestAX7Auth_MemorySessionStore_DeleteByUser_Bad(t *core.T) {
	store := NewMemorySessionStore()
	err := store.DeleteByUser("missing")
	core.AssertNoError(t, err)
	core.AssertEqual(t, 0, len(store.sessions))
}

func TestAX7Auth_MemorySessionStore_DeleteByUser_Ugly(t *core.T) {
	store := NewMemorySessionStore()
	core.RequireNoError(t, store.Set(ax7Session("empty", "", time.Now().Add(time.Hour))))
	err := store.DeleteByUser("")
	core.AssertNoError(t, err)
	core.AssertEqual(t, 0, len(store.sessions))
}

func TestAX7Auth_MemorySessionStore_Cleanup_Good(t *core.T) {
	store := NewMemorySessionStore()
	core.RequireNoError(t, store.Set(ax7Session("expired", "user", time.Now().Add(-time.Hour))))
	count, err := store.Cleanup()
	core.AssertNoError(t, err)
	core.AssertEqual(t, 1, count)
}

func TestAX7Auth_MemorySessionStore_Cleanup_Bad(t *core.T) {
	store := NewMemorySessionStore()
	count, err := store.Cleanup()
	core.AssertNoError(t, err)
	core.AssertEqual(t, 0, count)
}

func TestAX7Auth_MemorySessionStore_Cleanup_Ugly(t *core.T) {
	store := NewMemorySessionStore()
	core.RequireNoError(t, store.Set(ax7Session("valid", "user", time.Now().Add(time.Hour))))
	count, err := store.Cleanup()
	core.AssertNoError(t, err)
	core.AssertEqual(t, 0, count)
}

func TestAX7Auth_NewSQLiteSessionStore_Good(t *core.T) {
	store := ax7SQLiteStore(t)
	core.AssertNotNil(t, store)
	core.AssertNotNil(t, store.store)
}

func TestAX7Auth_NewSQLiteSessionStore_Bad(t *core.T) {
	store, err := NewSQLiteSessionStore("")
	core.AssertError(t, err)
	core.AssertNil(t, store)
}

func TestAX7Auth_NewSQLiteSessionStore_Ugly(t *core.T) {
	path := core.Path(t.TempDir(), "sessions.db")
	store, err := NewSQLiteSessionStore(path)
	core.RequireNoError(t, err)
	defer store.Close()
	core.AssertNotNil(t, store.store)
}

func TestAX7Auth_SQLiteSessionStore_Set_Good(t *core.T) {
	store := ax7SQLiteStore(t)
	err := store.Set(ax7Session("token", "user", time.Now().Add(time.Hour)))
	core.AssertNoError(t, err)
	core.AssertNotNil(t, store.store)
}

func TestAX7Auth_SQLiteSessionStore_Set_Bad(t *core.T) {
	store := ax7SQLiteStore(t)
	core.AssertPanics(t, func() {
		_ = store.Set(nil)
	})
	core.AssertNotNil(t, store.store)
}

func TestAX7Auth_SQLiteSessionStore_Set_Ugly(t *core.T) {
	store := ax7SQLiteStore(t)
	core.RequireNoError(t, store.Close())
	err := store.Set(ax7Session("token", "user", time.Now().Add(time.Hour)))
	core.AssertError(t, err)
}

func TestAX7Auth_SQLiteSessionStore_Get_Good(t *core.T) {
	store := ax7SQLiteStore(t)
	core.RequireNoError(t, store.Set(ax7Session("token", "user", time.Now().Add(time.Hour))))
	session, err := store.Get("token")
	core.AssertNoError(t, err)
	core.AssertEqual(t, "user", session.UserID)
}

func TestAX7Auth_SQLiteSessionStore_Get_Bad(t *core.T) {
	store := ax7SQLiteStore(t)
	session, err := store.Get("missing")
	core.AssertError(t, err)
	core.AssertNil(t, session)
}

func TestAX7Auth_SQLiteSessionStore_Get_Ugly(t *core.T) {
	store := ax7SQLiteStore(t)
	core.RequireNoError(t, store.Close())
	session, err := store.Get("token")
	core.AssertError(t, err)
	core.AssertNil(t, session)
}

func TestAX7Auth_SQLiteSessionStore_Delete_Good(t *core.T) {
	store := ax7SQLiteStore(t)
	core.RequireNoError(t, store.Set(ax7Session("token", "user", time.Now().Add(time.Hour))))
	err := store.Delete("token")
	core.AssertNoError(t, err)
}

func TestAX7Auth_SQLiteSessionStore_Delete_Bad(t *core.T) {
	store := ax7SQLiteStore(t)
	err := store.Delete("missing")
	core.AssertError(t, err)
	core.AssertNotNil(t, store.store)
}

func TestAX7Auth_SQLiteSessionStore_Delete_Ugly(t *core.T) {
	store := ax7SQLiteStore(t)
	core.RequireNoError(t, store.Close())
	err := store.Delete("token")
	core.AssertError(t, err)
}

func TestAX7Auth_SQLiteSessionStore_DeleteByUser_Good(t *core.T) {
	store := ax7SQLiteStore(t)
	core.RequireNoError(t, store.Set(ax7Session("a", "user", time.Now().Add(time.Hour))))
	core.RequireNoError(t, store.Set(ax7Session("b", "other", time.Now().Add(time.Hour))))
	err := store.DeleteByUser("user")
	core.AssertNoError(t, err)
}

func TestAX7Auth_SQLiteSessionStore_DeleteByUser_Bad(t *core.T) {
	store := ax7SQLiteStore(t)
	err := store.DeleteByUser("missing")
	core.AssertNoError(t, err)
	core.AssertNotNil(t, store.store)
}

func TestAX7Auth_SQLiteSessionStore_DeleteByUser_Ugly(t *core.T) {
	store := ax7SQLiteStore(t)
	core.RequireNoError(t, store.Close())
	err := store.DeleteByUser("user")
	core.AssertError(t, err)
}

func TestAX7Auth_SQLiteSessionStore_Cleanup_Good(t *core.T) {
	store := ax7SQLiteStore(t)
	core.RequireNoError(t, store.Set(ax7Session("expired", "user", time.Now().Add(-time.Hour))))
	count, err := store.Cleanup()
	core.AssertNoError(t, err)
	core.AssertEqual(t, 1, count)
}

func TestAX7Auth_SQLiteSessionStore_Cleanup_Bad(t *core.T) {
	store := ax7SQLiteStore(t)
	count, err := store.Cleanup()
	core.AssertNoError(t, err)
	core.AssertEqual(t, 0, count)
}

func TestAX7Auth_SQLiteSessionStore_Cleanup_Ugly(t *core.T) {
	store := ax7SQLiteStore(t)
	core.RequireNoError(t, store.Close())
	count, err := store.Cleanup()
	core.AssertError(t, err)
	core.AssertEqual(t, 0, count)
}

func TestAX7Auth_SQLiteSessionStore_Close_Good(t *core.T) {
	store := ax7SQLiteStore(t)
	err := store.Close()
	core.AssertNoError(t, err)
	core.AssertNotNil(t, store.store)
}

func TestAX7Auth_SQLiteSessionStore_Close_Bad(t *core.T) {
	store := ax7SQLiteStore(t)
	core.RequireNoError(t, store.Close())
	err := store.Close()
	core.AssertNoError(t, err)
}

func TestAX7Auth_SQLiteSessionStore_Close_Ugly(t *core.T) {
	var store *SQLiteSessionStore
	core.AssertPanics(t, func() {
		_ = store.Close()
	})
	core.AssertNil(t, store)
}

func TestAX7Auth_Authenticator_IsRevoked_Good(t *core.T) {
	a, _ := newTestAuth()
	_, err := a.Register("revoked-user", "pass")
	core.RequireNoError(t, err)
	userID := lthn.Hash("revoked-user")
	core.RequireNoError(t, a.RevokeKey(userID, "pass", "test"))
	core.AssertTrue(t, a.IsRevoked(userID))
}

func TestAX7Auth_Authenticator_IsRevoked_Bad(t *core.T) {
	a, _ := newTestAuth()
	_, err := a.Register("active-user", "pass")
	core.RequireNoError(t, err)
	userID := lthn.Hash("active-user")
	core.AssertFalse(t, a.IsRevoked(userID))
}

func TestAX7Auth_Authenticator_IsRevoked_Ugly(t *core.T) {
	a, m := newTestAuth()
	userID := lthn.Hash("invalid-rev")
	core.RequireNoError(t, m.EnsureDir("users"))
	core.RequireNoError(t, m.Write(userPath(userID, ".rev"), "{"))
	core.AssertFalse(t, a.IsRevoked(userID))
}

func TestAX7Auth_Authenticator_WriteChallengeFile_Good(t *core.T) {
	a, m := newTestAuth()
	_, err := a.Register("challenge-file", "pass")
	core.RequireNoError(t, err)
	userID := lthn.Hash("challenge-file")
	err = a.WriteChallengeFile(userID, "transfer/challenge.json")
	core.AssertNoError(t, err)
	core.AssertTrue(t, m.IsFile("transfer/challenge.json"))
}

func TestAX7Auth_Authenticator_WriteChallengeFile_Ugly(t *core.T) {
	a, _ := newTestAuth()
	_, err := a.Register("revoked-challenge", "pass")
	core.RequireNoError(t, err)
	userID := lthn.Hash("revoked-challenge")
	core.RequireNoError(t, a.RevokeKey(userID, "pass", "test"))
	err = a.WriteChallengeFile(userID, "transfer/challenge.json")
	core.AssertError(t, err)
}

func TestAX7Auth_Authenticator_ReadResponseFile_Good(t *core.T) {
	a, m := newTestAuth()
	_, err := a.Register("response-file", "pass")
	core.RequireNoError(t, err)
	userID := lthn.Hash("response-file")
	challenge, err := a.CreateChallenge(userID)
	core.RequireNoError(t, err)
	privKey, err := m.Read(userPath(userID, ".key"))
	core.RequireNoError(t, err)
	nonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "pass")
	core.RequireNoError(t, err)
	signature, err := pgp.Sign(nonce, privKey, "pass")
	core.RequireNoError(t, err)
	core.RequireNoError(t, m.Write("transfer/response.sig", string(signature)))
	session, err := a.ReadResponseFile(userID, "transfer/response.sig")
	core.AssertNoError(t, err)
	core.AssertEqual(t, userID, session.UserID)
}

func TestAX7Auth_Authenticator_StartCleanup_Bad(t *core.T) {
	store := NewMemorySessionStore()
	core.RequireNoError(t, store.Set(ax7Session("expired", "user", time.Now().Add(-time.Hour))))
	a := New(io.NewMockMedium(), WithSessionStore(store))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	a.StartCleanup(ctx, time.Hour)
	time.Sleep(5 * time.Millisecond)
	_, err := store.Get("expired")
	core.AssertNoError(t, err)
}

func TestAX7Auth_Authenticator_StartCleanup_Ugly(t *core.T) {
	store := &ax7CleanupErrorStore{}
	a := New(io.NewMockMedium(), WithSessionStore(store))
	ctx := t.Context()
	a.StartCleanup(ctx, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	core.AssertTrue(t, store.Calls() > 0)
}
