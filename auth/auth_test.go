package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"forge.lthn.ai/core/go-crypt/crypt/lthn"
	"forge.lthn.ai/core/go-crypt/crypt/pgp"
	"forge.lthn.ai/core/go-io"
)

// helper creates a fresh Authenticator backed by MockMedium.
func newTestAuth(opts ...Option) (*Authenticator, *io.MockMedium) {
	m := io.NewMockMedium()
	a := New(m, opts...)
	return a, m
}

// --- Register ---

func TestRegister_Good(t *testing.T) {
	a, m := newTestAuth()

	user, err := a.Register("alice", "hunter2")
	require.NoError(t, err)
	require.NotNil(t, user)

	userID := lthn.Hash("alice")

	// Verify all files are stored (new registrations use .hash, not .lthn)
	assert.True(t, m.IsFile(userPath(userID, ".pub")))
	assert.True(t, m.IsFile(userPath(userID, ".key")))
	assert.True(t, m.IsFile(userPath(userID, ".rev")))
	assert.True(t, m.IsFile(userPath(userID, ".json")))
	assert.True(t, m.IsFile(userPath(userID, ".hash")))
	assert.False(t, m.IsFile(userPath(userID, ".lthn")), "new registrations should not create .lthn file")

	// Verify user fields
	assert.NotEmpty(t, user.PublicKey)
	assert.Equal(t, userID, user.KeyID)
	assert.NotEmpty(t, user.Fingerprint)
	assert.True(t, strings.HasPrefix(user.PasswordHash, "$argon2id$"), "password hash should be Argon2id format")
	assert.False(t, user.Created.IsZero())
}

func TestRegister_Bad(t *testing.T) {
	a, _ := newTestAuth()

	// Register first time succeeds
	_, err := a.Register("bob", "pass1")
	require.NoError(t, err)

	// Duplicate registration should fail
	_, err = a.Register("bob", "pass2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user already exists")
}

func TestRegister_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	// Empty username/password should still work (PGP allows it)
	user, err := a.Register("", "")
	require.NoError(t, err)
	require.NotNil(t, user)
}

// --- CreateChallenge ---

func TestCreateChallenge_Good(t *testing.T) {
	a, _ := newTestAuth()

	user, err := a.Register("charlie", "pass")
	require.NoError(t, err)

	challenge, err := a.CreateChallenge(user.KeyID)
	require.NoError(t, err)
	require.NotNil(t, challenge)

	assert.Len(t, challenge.Nonce, nonceBytes)
	assert.NotEmpty(t, challenge.Encrypted)
	assert.True(t, challenge.ExpiresAt.After(time.Now()))
}

func TestCreateChallenge_Bad(t *testing.T) {
	a, _ := newTestAuth()

	// Challenge for non-existent user
	_, err := a.CreateChallenge("nonexistent-user-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestCreateChallenge_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	// Empty userID
	_, err := a.CreateChallenge("")
	assert.Error(t, err)
}

// --- ValidateResponse (full challenge-response flow) ---

func TestValidateResponse_Good(t *testing.T) {
	a, m := newTestAuth()

	// Register user
	_, err := a.Register("dave", "password123")
	require.NoError(t, err)

	userID := lthn.Hash("dave")

	// Create challenge
	challenge, err := a.CreateChallenge(userID)
	require.NoError(t, err)

	// Client-side: decrypt nonce, then sign it
	privKey, err := m.Read(userPath(userID, ".key"))
	require.NoError(t, err)

	decryptedNonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "password123")
	require.NoError(t, err)
	assert.Equal(t, challenge.Nonce, decryptedNonce)

	signedNonce, err := pgp.Sign(decryptedNonce, privKey, "password123")
	require.NoError(t, err)

	// Validate response
	session, err := a.ValidateResponse(userID, signedNonce)
	require.NoError(t, err)
	require.NotNil(t, session)

	assert.NotEmpty(t, session.Token)
	assert.Equal(t, userID, session.UserID)
	assert.True(t, session.ExpiresAt.After(time.Now()))
}

func TestValidateResponse_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("eve", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("eve")

	// No pending challenge
	_, err = a.ValidateResponse(userID, []byte("fake-signature"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no pending challenge")
}

func TestValidateResponse_Ugly(t *testing.T) {
	a, m := newTestAuth(WithChallengeTTL(1 * time.Millisecond))

	_, err := a.Register("frank", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("frank")

	// Create challenge and let it expire
	challenge, err := a.CreateChallenge(userID)
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond)

	// Sign with valid key but expired challenge
	privKey, err := m.Read(userPath(userID, ".key"))
	require.NoError(t, err)

	signedNonce, err := pgp.Sign(challenge.Nonce, privKey, "pass")
	require.NoError(t, err)

	_, err = a.ValidateResponse(userID, signedNonce)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "challenge expired")
}

// --- ValidateSession ---

func TestValidateSession_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("grace", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("grace")

	session, err := a.Login(userID, "pass")
	require.NoError(t, err)

	validated, err := a.ValidateSession(session.Token)
	require.NoError(t, err)
	assert.Equal(t, session.Token, validated.Token)
	assert.Equal(t, userID, validated.UserID)
}

func TestValidateSession_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.ValidateSession("nonexistent-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestValidateSession_Ugly(t *testing.T) {
	a, _ := newTestAuth(WithSessionTTL(1 * time.Millisecond))

	_, err := a.Register("heidi", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("heidi")

	session, err := a.Login(userID, "pass")
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond)

	_, err = a.ValidateSession(session.Token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session expired")
}

// --- RefreshSession ---

func TestRefreshSession_Good(t *testing.T) {
	a, _ := newTestAuth(WithSessionTTL(1 * time.Hour))

	_, err := a.Register("ivan", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("ivan")

	session, err := a.Login(userID, "pass")
	require.NoError(t, err)

	originalExpiry := session.ExpiresAt

	// Small delay to ensure time moves forward
	time.Sleep(2 * time.Millisecond)

	refreshed, err := a.RefreshSession(session.Token)
	require.NoError(t, err)
	assert.True(t, refreshed.ExpiresAt.After(originalExpiry))
}

func TestRefreshSession_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.RefreshSession("nonexistent-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestRefreshSession_Ugly(t *testing.T) {
	a, _ := newTestAuth(WithSessionTTL(1 * time.Millisecond))

	_, err := a.Register("judy", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("judy")

	session, err := a.Login(userID, "pass")
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond)

	_, err = a.RefreshSession(session.Token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session expired")
}

// --- RevokeSession ---

func TestRevokeSession_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("karl", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("karl")

	session, err := a.Login(userID, "pass")
	require.NoError(t, err)

	err = a.RevokeSession(session.Token)
	require.NoError(t, err)

	// Token should no longer be valid
	_, err = a.ValidateSession(session.Token)
	assert.Error(t, err)
}

func TestRevokeSession_Bad(t *testing.T) {
	a, _ := newTestAuth()

	err := a.RevokeSession("nonexistent-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestRevokeSession_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	// Revoke empty token
	err := a.RevokeSession("")
	assert.Error(t, err)
}

// --- DeleteUser ---

func TestDeleteUser_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("larry", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("larry")

	// Also create a session that should be cleaned up
	session, err := a.Login(userID, "pass")
	require.NoError(t, err)

	err = a.DeleteUser(userID)
	require.NoError(t, err)

	// All files should be gone (both new .hash and legacy .lthn)
	assert.False(t, m.IsFile(userPath(userID, ".pub")))
	assert.False(t, m.IsFile(userPath(userID, ".key")))
	assert.False(t, m.IsFile(userPath(userID, ".rev")))
	assert.False(t, m.IsFile(userPath(userID, ".json")))
	assert.False(t, m.IsFile(userPath(userID, ".hash")))
	assert.False(t, m.IsFile(userPath(userID, ".lthn")))

	// Session should be gone (validate returns error)
	_, err = a.ValidateSession(session.Token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestDeleteUser_Bad(t *testing.T) {
	a, _ := newTestAuth()

	// Protected user "server" cannot be deleted
	err := a.DeleteUser("server")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete protected user")
}

func TestDeleteUser_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	// Non-existent user
	err := a.DeleteUser("nonexistent-user-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// --- Login ---

func TestLogin_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("mallory", "secret")
	require.NoError(t, err)
	userID := lthn.Hash("mallory")

	session, err := a.Login(userID, "secret")
	require.NoError(t, err)
	require.NotNil(t, session)

	assert.NotEmpty(t, session.Token)
	assert.Equal(t, userID, session.UserID)
	assert.True(t, session.ExpiresAt.After(time.Now()))
}

func TestLogin_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("nancy", "correct-password")
	require.NoError(t, err)
	userID := lthn.Hash("nancy")

	// Wrong password
	_, err = a.Login(userID, "wrong-password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid password")
}

func TestLogin_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	// Login for non-existent user
	_, err := a.Login("nonexistent-user-id", "pass")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// --- WriteChallengeFile / ReadResponseFile (Air-Gapped) ---

func TestAirGappedFlow_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("oscar", "airgap-pass")
	require.NoError(t, err)
	userID := lthn.Hash("oscar")

	// Write challenge to file
	challengePath := "transfer/challenge.json"
	err = a.WriteChallengeFile(userID, challengePath)
	require.NoError(t, err)
	assert.True(t, m.IsFile(challengePath))

	// Read challenge file to get the encrypted nonce (simulating courier)
	challengeData, err := m.Read(challengePath)
	require.NoError(t, err)

	var challenge Challenge
	err = json.Unmarshal([]byte(challengeData), &challenge)
	require.NoError(t, err)

	// Client-side: decrypt nonce and sign it
	privKey, err := m.Read(userPath(userID, ".key"))
	require.NoError(t, err)

	decryptedNonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "airgap-pass")
	require.NoError(t, err)

	signedNonce, err := pgp.Sign(decryptedNonce, privKey, "airgap-pass")
	require.NoError(t, err)

	// Write signed response to file
	responsePath := "transfer/response.sig"
	err = m.Write(responsePath, string(signedNonce))
	require.NoError(t, err)

	// Server reads response file
	session, err := a.ReadResponseFile(userID, responsePath)
	require.NoError(t, err)
	require.NotNil(t, session)

	assert.NotEmpty(t, session.Token)
	assert.Equal(t, userID, session.UserID)
}

func TestWriteChallengeFile_Bad(t *testing.T) {
	a, _ := newTestAuth()

	// Challenge for non-existent user
	err := a.WriteChallengeFile("nonexistent-user", "challenge.json")
	assert.Error(t, err)
}

func TestReadResponseFile_Bad(t *testing.T) {
	a, _ := newTestAuth()

	// Response file does not exist
	_, err := a.ReadResponseFile("some-user", "nonexistent-file.sig")
	assert.Error(t, err)
}

func TestReadResponseFile_Ugly(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("peggy", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("peggy")

	// Create a challenge
	_, err = a.CreateChallenge(userID)
	require.NoError(t, err)

	// Write garbage to response file
	responsePath := "transfer/bad-response.sig"
	err = m.Write(responsePath, "not-a-valid-signature")
	require.NoError(t, err)

	_, err = a.ReadResponseFile(userID, responsePath)
	assert.Error(t, err)
}

// --- Options ---

func TestWithChallengeTTL_Good(t *testing.T) {
	ttl := 30 * time.Second
	a, _ := newTestAuth(WithChallengeTTL(ttl))
	assert.Equal(t, ttl, a.challengeTTL)
}

func TestWithSessionTTL_Good(t *testing.T) {
	ttl := 2 * time.Hour
	a, _ := newTestAuth(WithSessionTTL(ttl))
	assert.Equal(t, ttl, a.sessionTTL)
}

// --- Full Round-Trip (Online Flow) ---

func TestFullRoundTrip_Good(t *testing.T) {
	a, m := newTestAuth()

	// 1. Register
	user, err := a.Register("quinn", "roundtrip-pass")
	require.NoError(t, err)
	require.NotNil(t, user)

	userID := lthn.Hash("quinn")

	// 2. Create challenge
	challenge, err := a.CreateChallenge(userID)
	require.NoError(t, err)

	// 3. Client decrypts + signs
	privKey, err := m.Read(userPath(userID, ".key"))
	require.NoError(t, err)

	nonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "roundtrip-pass")
	require.NoError(t, err)

	sig, err := pgp.Sign(nonce, privKey, "roundtrip-pass")
	require.NoError(t, err)

	// 4. Server validates, issues session
	session, err := a.ValidateResponse(userID, sig)
	require.NoError(t, err)
	require.NotNil(t, session)

	// 5. Validate session
	validated, err := a.ValidateSession(session.Token)
	require.NoError(t, err)
	assert.Equal(t, session.Token, validated.Token)

	// 6. Refresh session
	refreshed, err := a.RefreshSession(session.Token)
	require.NoError(t, err)
	assert.Equal(t, session.Token, refreshed.Token)

	// 7. Revoke session
	err = a.RevokeSession(session.Token)
	require.NoError(t, err)

	// 8. Session should be invalid now
	_, err = a.ValidateSession(session.Token)
	assert.Error(t, err)
}

// --- Concurrent Access ---

func TestConcurrentSessions_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("ruth", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("ruth")

	// Create multiple sessions concurrently
	const n = 10
	sessions := make(chan *Session, n)
	errs := make(chan error, n)

	for range n {
		go func() {
			s, err := a.Login(userID, "pass")
			if err != nil {
				errs <- err
				return
			}
			sessions <- s
		}()
	}

	for range n {
		select {
		case s := <-sessions:
			require.NotNil(t, s)
			// Validate each session
			_, err := a.ValidateSession(s.Token)
			assert.NoError(t, err)
		case err := <-errs:
			t.Fatalf("concurrent login failed: %v", err)
		}
	}
}

// --- Phase 0 Additions ---

// TestConcurrentSessionCreation_Good verifies that 10 goroutines creating
// sessions simultaneously do not produce data races or errors.
func TestConcurrentSessionCreation_Good(t *testing.T) {
	a, _ := newTestAuth()

	// Register 10 distinct users to avoid contention on a single user record
	const n = 10
	userIDs := make([]string, n)
	for i := range n {
		username := fmt.Sprintf("concurrent-user-%d", i)
		_, err := a.Register(username, "pass")
		require.NoError(t, err)
		userIDs[i] = lthn.Hash(username)
	}

	var wg sync.WaitGroup
	wg.Add(n)
	sessions := make([]*Session, n)
	errs := make([]error, n)

	for i := range n {
		go func(idx int) {
			defer wg.Done()
			s, err := a.Login(userIDs[idx], "pass")
			sessions[idx] = s
			errs[idx] = err
		}(i)
	}

	wg.Wait()

	for i := range n {
		require.NoError(t, errs[i], "goroutine %d failed", i)
		require.NotNil(t, sessions[i], "goroutine %d returned nil session", i)
		// Each session token must be valid
		_, err := a.ValidateSession(sessions[i].Token)
		assert.NoError(t, err, "session from goroutine %d should be valid", i)
	}
}

// TestSessionTokenUniqueness_Good generates 1000 tokens and verifies no collisions.
func TestSessionTokenUniqueness_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("uniqueness-test", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("uniqueness-test")

	const n = 1000
	tokens := make(map[string]bool, n)

	for i := range n {
		session, err := a.Login(userID, "pass")
		require.NoError(t, err)
		require.NotNil(t, session)

		if tokens[session.Token] {
			t.Fatalf("duplicate token detected at iteration %d: %s", i, session.Token)
		}
		tokens[session.Token] = true
	}

	assert.Len(t, tokens, n, "all 1000 tokens should be unique")
}

// TestChallengeExpiryBoundary_Ugly tests validation right at the 5-minute boundary.
// The challenge should still be valid just before expiry and rejected after.
func TestChallengeExpiryBoundary_Ugly(t *testing.T) {
	// Use a very short TTL to test the boundary without sleeping 5 minutes
	ttl := 50 * time.Millisecond
	a, m := newTestAuth(WithChallengeTTL(ttl))

	_, err := a.Register("boundary-user", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("boundary-user")

	// Create a challenge and respond immediately (should succeed)
	challenge, err := a.CreateChallenge(userID)
	require.NoError(t, err)

	privKey, err := m.Read(userPath(userID, ".key"))
	require.NoError(t, err)

	decryptedNonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "pass")
	require.NoError(t, err)

	signedNonce, err := pgp.Sign(decryptedNonce, privKey, "pass")
	require.NoError(t, err)

	session, err := a.ValidateResponse(userID, signedNonce)
	require.NoError(t, err)
	assert.NotNil(t, session)

	// Now create another challenge and let it expire
	challenge2, err := a.CreateChallenge(userID)
	require.NoError(t, err)

	// Wait past the TTL
	time.Sleep(ttl + 10*time.Millisecond)

	decryptedNonce2, err := pgp.Decrypt([]byte(challenge2.Encrypted), privKey, "pass")
	require.NoError(t, err)

	signedNonce2, err := pgp.Sign(decryptedNonce2, privKey, "pass")
	require.NoError(t, err)

	_, err = a.ValidateResponse(userID, signedNonce2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "challenge expired")
}

// TestEmptyPasswordRegistration_Good verifies that empty password registration works.
// PGP key is generated unencrypted in this case.
func TestEmptyPasswordRegistration_Good(t *testing.T) {
	a, m := newTestAuth()

	user, err := a.Register("no-password-user", "")
	require.NoError(t, err)
	require.NotNil(t, user)

	userID := lthn.Hash("no-password-user")

	// Verify all files are stored
	assert.True(t, m.IsFile(userPath(userID, ".pub")))
	assert.True(t, m.IsFile(userPath(userID, ".key")))
	assert.True(t, m.IsFile(userPath(userID, ".json")))

	// Login with empty password should work
	session, err := a.Login(userID, "")
	require.NoError(t, err)
	assert.NotNil(t, session)

	// Challenge-response flow should also work with empty password
	challenge, err := a.CreateChallenge(userID)
	require.NoError(t, err)

	privKey, err := m.Read(userPath(userID, ".key"))
	require.NoError(t, err)

	decryptedNonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "")
	require.NoError(t, err)

	signedNonce, err := pgp.Sign(decryptedNonce, privKey, "")
	require.NoError(t, err)

	crSession, err := a.ValidateResponse(userID, signedNonce)
	require.NoError(t, err)
	assert.NotNil(t, crSession)
}

// TestVeryLongUsername_Ugly verifies behaviour with a 10K character username.
func TestVeryLongUsername_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	longUsername := strings.Repeat("a", 10000)
	user, err := a.Register(longUsername, "pass")
	require.NoError(t, err)
	require.NotNil(t, user)

	// The LTHN hash of the long username should still be a fixed-length identifier
	userID := lthn.Hash(longUsername)
	assert.Len(t, userID, 64, "LTHN hash should always be 64 hex chars (SHA-256)")

	// Login should work
	session, err := a.Login(userID, "pass")
	require.NoError(t, err)
	assert.NotNil(t, session)
}

// TestUnicodeUsernamePassword_Good verifies registration and login with Unicode characters.
func TestUnicodeUsernamePassword_Good(t *testing.T) {
	a, _ := newTestAuth()

	// Japanese + emoji + Chinese + Arabic
	username := "\u65e5\u672c\u8a9e\u30c6\u30b9\u30c8\U0001F680\u4e2d\u6587\u0627\u0644\u0639\u0631\u0628\u064a\u0629"
	password := "\u00fc\u00f1\u00ee\u00e7\u00f6\u00f0\u00ea\u2603\u2764"

	user, err := a.Register(username, password)
	require.NoError(t, err)
	require.NotNil(t, user)

	userID := lthn.Hash(username)

	// Login with correct Unicode password
	session, err := a.Login(userID, password)
	require.NoError(t, err)
	assert.NotNil(t, session)

	// Login with wrong Unicode password should fail
	_, err = a.Login(userID, "wrong-\u00fc\u00f1\u00ee")
	assert.Error(t, err)
}

// TestAirGappedRoundTrip_Good tests the full air-gapped flow:
// WriteChallengeFile -> client signs offline -> ReadResponseFile
func TestAirGappedRoundTrip_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("airgap-roundtrip", "courier-pass")
	require.NoError(t, err)
	userID := lthn.Hash("airgap-roundtrip")

	// Step 1: Server writes challenge file
	challengePath := "airgap/challenge.json"
	err = a.WriteChallengeFile(userID, challengePath)
	require.NoError(t, err)
	assert.True(t, m.IsFile(challengePath))

	// Step 2: Client reads challenge file (simulating courier transport)
	challengeData, err := m.Read(challengePath)
	require.NoError(t, err)

	var challenge Challenge
	err = json.Unmarshal([]byte(challengeData), &challenge)
	require.NoError(t, err)
	assert.NotEmpty(t, challenge.Encrypted)
	assert.True(t, challenge.ExpiresAt.After(time.Now()))

	// Step 3: Client decrypts nonce, signs it, writes response
	privKey, err := m.Read(userPath(userID, ".key"))
	require.NoError(t, err)

	decryptedNonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "courier-pass")
	require.NoError(t, err)
	assert.Equal(t, challenge.Nonce, decryptedNonce)

	signedNonce, err := pgp.Sign(decryptedNonce, privKey, "courier-pass")
	require.NoError(t, err)

	responsePath := "airgap/response.sig"
	err = m.Write(responsePath, string(signedNonce))
	require.NoError(t, err)

	// Step 4: Server reads response file and validates
	session, err := a.ReadResponseFile(userID, responsePath)
	require.NoError(t, err)
	require.NotNil(t, session)

	assert.NotEmpty(t, session.Token)
	assert.Equal(t, userID, session.UserID)
	assert.True(t, session.ExpiresAt.After(time.Now()))

	// Step 5: Session should be valid
	validated, err := a.ValidateSession(session.Token)
	require.NoError(t, err)
	assert.Equal(t, session.Token, validated.Token)
}

// TestRefreshExpiredSession_Bad verifies that refreshing an already-expired session fails.
func TestRefreshExpiredSession_Bad(t *testing.T) {
	a, _ := newTestAuth(WithSessionTTL(1 * time.Millisecond))

	_, err := a.Register("expired-refresh", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("expired-refresh")

	session, err := a.Login(userID, "pass")
	require.NoError(t, err)

	// Wait for session to expire
	time.Sleep(10 * time.Millisecond)

	// Refresh should fail
	_, err = a.RefreshSession(session.Token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session expired")

	// The expired session should now be cleaned up (removed from map)
	_, err = a.ValidateSession(session.Token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

// --- Phase 2: Password Hash Migration ---

// TestRegisterArgon2id_Good verifies that new registrations use Argon2id format.
func TestRegisterArgon2id_Good(t *testing.T) {
	a, m := newTestAuth()

	user, err := a.Register("argon2-user", "strong-pass")
	require.NoError(t, err)

	userID := lthn.Hash("argon2-user")

	// .hash file should exist with Argon2id format
	assert.True(t, m.IsFile(userPath(userID, ".hash")))
	hashContent, err := m.Read(userPath(userID, ".hash"))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(hashContent, "$argon2id$"), "stored hash should be Argon2id")

	// .lthn file should NOT exist for new registrations
	assert.False(t, m.IsFile(userPath(userID, ".lthn")))

	// User struct should have Argon2id hash
	assert.True(t, strings.HasPrefix(user.PasswordHash, "$argon2id$"))
}

// TestLoginArgon2id_Good verifies login works with Argon2id hashed password.
func TestLoginArgon2id_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("login-argon2", "my-password")
	require.NoError(t, err)
	userID := lthn.Hash("login-argon2")

	// Login should succeed with correct password
	session, err := a.Login(userID, "my-password")
	require.NoError(t, err)
	assert.NotEmpty(t, session.Token)
}

// TestLoginArgon2id_Bad verifies wrong password fails with Argon2id hash.
func TestLoginArgon2id_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("login-argon2-bad", "correct")
	require.NoError(t, err)
	userID := lthn.Hash("login-argon2-bad")

	_, err = a.Login(userID, "wrong")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid password")
}

// TestLegacyLTHNMigration_Good verifies that a user registered with the legacy
// LTHN hash format is transparently migrated to Argon2id on successful login.
func TestLegacyLTHNMigration_Good(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m)

	// Simulate a legacy registration by manually writing LTHN-format files
	userID := lthn.Hash("legacy-user")
	_ = m.EnsureDir("users")

	// Generate PGP keypair (same as original Register did)
	kp, err := pgp.CreateKeyPair(userID, userID+"@auth.local", "legacy-pass")
	require.NoError(t, err)

	_ = m.Write(userPath(userID, ".pub"), kp.PublicKey)
	_ = m.Write(userPath(userID, ".key"), kp.PrivateKey)
	_ = m.Write(userPath(userID, ".rev"), "REVOCATION_PLACEHOLDER")

	// Write legacy LTHN hash (this is what old Register did)
	legacyHash := lthn.Hash("legacy-pass")
	_ = m.Write(userPath(userID, ".lthn"), legacyHash)

	// No .hash file should exist yet
	assert.False(t, m.IsFile(userPath(userID, ".hash")))

	// Login with legacy hash should succeed
	session, err := a.Login(userID, "legacy-pass")
	require.NoError(t, err)
	assert.NotEmpty(t, session.Token)

	// After successful login, .hash file should now exist with Argon2id
	assert.True(t, m.IsFile(userPath(userID, ".hash")), "migration should create .hash file")
	newHash, err := m.Read(userPath(userID, ".hash"))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(newHash, "$argon2id$"), "migrated hash should be Argon2id")

	// Subsequent login should use the new Argon2id hash (not LTHN)
	session2, err := a.Login(userID, "legacy-pass")
	require.NoError(t, err)
	assert.NotEmpty(t, session2.Token)
}

// TestLegacyLTHNLogin_Bad verifies wrong password fails for legacy LTHN users.
func TestLegacyLTHNLogin_Bad(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m)

	userID := lthn.Hash("legacy-bad")
	_ = m.EnsureDir("users")

	kp, err := pgp.CreateKeyPair(userID, userID+"@auth.local", "real-pass")
	require.NoError(t, err)

	_ = m.Write(userPath(userID, ".pub"), kp.PublicKey)
	_ = m.Write(userPath(userID, ".key"), kp.PrivateKey)
	_ = m.Write(userPath(userID, ".lthn"), lthn.Hash("real-pass"))

	// Wrong password should fail
	_, err = a.Login(userID, "wrong-pass")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid password")

	// No migration should have occurred
	assert.False(t, m.IsFile(userPath(userID, ".hash")), "failed login should not create .hash file")
}

// --- Phase 2: Key Rotation ---

// TestRotateKeyPair_Good verifies the full key rotation flow:
// register -> login -> rotate -> verify old key can't decrypt -> verify new key works -> sessions invalidated.
func TestRotateKeyPair_Good(t *testing.T) {
	a, m := newTestAuth()

	// Register and login
	_, err := a.Register("rotate-user", "old-pass")
	require.NoError(t, err)
	userID := lthn.Hash("rotate-user")

	session, err := a.Login(userID, "old-pass")
	require.NoError(t, err)

	// Read old public key for comparison
	oldPubKey, err := m.Read(userPath(userID, ".pub"))
	require.NoError(t, err)

	// Rotate keypair
	updatedUser, err := a.RotateKeyPair(userID, "old-pass", "new-pass")
	require.NoError(t, err)
	require.NotNil(t, updatedUser)

	// New public key should differ from old
	newPubKey, err := m.Read(userPath(userID, ".pub"))
	require.NoError(t, err)
	assert.NotEqual(t, oldPubKey, newPubKey, "public key should change after rotation")
	assert.Equal(t, newPubKey, updatedUser.PublicKey)

	// Old password should fail
	_, err = a.Login(userID, "old-pass")
	assert.Error(t, err, "old password should not work after rotation")

	// New password should succeed
	newSession, err := a.Login(userID, "new-pass")
	require.NoError(t, err)
	assert.NotEmpty(t, newSession.Token)

	// Old session should be invalidated
	_, err = a.ValidateSession(session.Token)
	assert.Error(t, err, "old session should be invalidated after rotation")

	// Metadata should be decryptable with new key
	encMeta, err := m.Read(userPath(userID, ".json"))
	require.NoError(t, err)
	newPrivKey, err := m.Read(userPath(userID, ".key"))
	require.NoError(t, err)
	decrypted, err := pgp.Decrypt([]byte(encMeta), newPrivKey, "new-pass")
	require.NoError(t, err)

	var meta User
	err = json.Unmarshal(decrypted, &meta)
	require.NoError(t, err)
	assert.Equal(t, userID, meta.KeyID)
	assert.True(t, strings.HasPrefix(meta.PasswordHash, "$argon2id$"))
}

// TestRotateKeyPair_Bad verifies that rotation fails with wrong old password.
func TestRotateKeyPair_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("rotate-bad", "correct-pass")
	require.NoError(t, err)
	userID := lthn.Hash("rotate-bad")

	// Wrong old password should fail
	_, err = a.RotateKeyPair(userID, "wrong-pass", "new-pass")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt metadata")
}

// TestRotateKeyPair_Ugly verifies rotation for non-existent user.
func TestRotateKeyPair_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.RotateKeyPair("nonexistent-user-id", "old", "new")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// TestRotateKeyPair_OldKeyCannotDecrypt_Good verifies old private key
// cannot decrypt metadata after rotation.
func TestRotateKeyPair_OldKeyCannotDecrypt_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("rotate-crypto", "pass-a")
	require.NoError(t, err)
	userID := lthn.Hash("rotate-crypto")

	// Save old private key
	oldPrivKey, err := m.Read(userPath(userID, ".key"))
	require.NoError(t, err)

	// Rotate
	_, err = a.RotateKeyPair(userID, "pass-a", "pass-b")
	require.NoError(t, err)

	// Old private key should NOT be able to decrypt new metadata
	encMeta, err := m.Read(userPath(userID, ".json"))
	require.NoError(t, err)
	_, err = pgp.Decrypt([]byte(encMeta), oldPrivKey, "pass-a")
	assert.Error(t, err, "old private key should not decrypt metadata after rotation")
}

// --- Phase 2: Key Revocation ---

// TestRevokeKey_Good verifies the full revocation flow:
// register -> login -> revoke -> login fails -> challenge fails -> sessions invalidated.
func TestRevokeKey_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("revoke-user", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("revoke-user")

	// Login to create a session
	session, err := a.Login(userID, "pass")
	require.NoError(t, err)

	// User should not be revoked yet
	assert.False(t, a.IsRevoked(userID))

	// Revoke the key
	err = a.RevokeKey(userID, "pass", "compromised key material")
	require.NoError(t, err)

	// User should now be revoked
	assert.True(t, a.IsRevoked(userID))

	// Verify .rev file contains valid JSON
	revContent, err := m.Read(userPath(userID, ".rev"))
	require.NoError(t, err)
	assert.NotEqual(t, "REVOCATION_PLACEHOLDER", revContent)

	var rev Revocation
	err = json.Unmarshal([]byte(revContent), &rev)
	require.NoError(t, err)
	assert.Equal(t, userID, rev.UserID)
	assert.Equal(t, "compromised key material", rev.Reason)
	assert.False(t, rev.RevokedAt.IsZero())

	// Login should fail for revoked user
	_, err = a.Login(userID, "pass")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key has been revoked")

	// CreateChallenge should fail for revoked user
	_, err = a.CreateChallenge(userID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key has been revoked")

	// Old session should be invalidated
	_, err = a.ValidateSession(session.Token)
	assert.Error(t, err)
}

// TestRevokeKey_Bad verifies revocation fails with wrong password.
func TestRevokeKey_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("revoke-bad", "correct")
	require.NoError(t, err)
	userID := lthn.Hash("revoke-bad")

	err = a.RevokeKey(userID, "wrong", "test reason")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid password")

	// Should NOT be revoked after failed attempt
	assert.False(t, a.IsRevoked(userID))
}

// TestRevokeKey_Ugly verifies revocation for non-existent user.
func TestRevokeKey_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	err := a.RevokeKey("nonexistent-user-id", "pass", "reason")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// TestIsRevoked_Placeholder_Good verifies that the legacy placeholder is not
// treated as a valid revocation.
func TestIsRevoked_Placeholder_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("placeholder-user", "pass")
	require.NoError(t, err)
	userID := lthn.Hash("placeholder-user")

	// New registrations write "REVOCATION_PLACEHOLDER"
	revContent, err := m.Read(userPath(userID, ".rev"))
	require.NoError(t, err)
	assert.Equal(t, "REVOCATION_PLACEHOLDER", revContent)

	// Should NOT be considered revoked
	assert.False(t, a.IsRevoked(userID))
}

// TestIsRevoked_NoRevFile_Good verifies that a missing .rev file returns false.
func TestIsRevoked_NoRevFile_Good(t *testing.T) {
	a, _ := newTestAuth()

	assert.False(t, a.IsRevoked("completely-nonexistent"))
}

// TestRevokeKey_LegacyUser_Good verifies revocation works for a legacy user
// with only a .lthn hash file (no .hash file).
func TestRevokeKey_LegacyUser_Good(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m)

	userID := lthn.Hash("legacy-revoke")
	_ = m.EnsureDir("users")

	kp, err := pgp.CreateKeyPair(userID, userID+"@auth.local", "legacy-pass")
	require.NoError(t, err)

	_ = m.Write(userPath(userID, ".pub"), kp.PublicKey)
	_ = m.Write(userPath(userID, ".key"), kp.PrivateKey)
	_ = m.Write(userPath(userID, ".rev"), "REVOCATION_PLACEHOLDER")
	_ = m.Write(userPath(userID, ".lthn"), lthn.Hash("legacy-pass"))

	// Revoke with LTHN-verified password
	err = a.RevokeKey(userID, "legacy-pass", "decommissioned")
	require.NoError(t, err)

	assert.True(t, a.IsRevoked(userID))
}
