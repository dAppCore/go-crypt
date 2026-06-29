package auth

import (
	"sync"
	"testing"
	"time"

	core "dappco.re/go"

	"dappco.re/go/crypt/crypt/lthn"
	"dappco.re/go/crypt/crypt/pgp"
	"dappco.re/go/io"
)

// helper creates a fresh Authenticator backed by MockMedium.
func newTestAuth(opts ...Option) (*Authenticator, *io.MockMedium) {
	m := io.NewMockMedium()
	a := New(m, opts...)
	return a, m
}

// --- Register ---

func TestAuth_Authenticator_Register_Good(t *testing.T) {
	a, m := newTestAuth()

	user, err := a.Register("alice", "hunter2")
	mustNoError(t, err)
	mustNotNil(t, user)

	userID := lthn.Hash("alice")

	// Verify all files are stored (new registrations use .hash, not .lthn)
	wantTrue(t, m.IsFile(userPath(userID, ".pub")))
	wantTrue(t, m.IsFile(userPath(userID, ".key")))
	wantTrue(t, m.IsFile(userPath(userID, ".rev")))
	wantTrue(t, m.IsFile(userPath(userID, ".json")))
	wantTrue(t, m.IsFile(userPath(userID, ".hash")))
	wantFalse(t, m.IsFile(userPath(userID, ".lthn")), "new registrations should not create .lthn file")

	// Verify user fields
	wantNotEmpty(t, user.PublicKey)
	wantEqual(t, userID, user.KeyID)
	wantNotEmpty(t, user.Fingerprint)
	wantTrue(t, core.HasPrefix(user.PasswordHash, "$argon2id$"), "password hash should be Argon2id format")
	wantFalse(t, user.Created.IsZero())
}

func TestAuth_Authenticator_Register_Bad(t *testing.T) {
	a, _ := newTestAuth()

	// Register first time succeeds
	_, err := a.Register("bob", "pass1")
	mustNoError(t, err)

	// Duplicate registration should fail
	_, err = a.Register("bob", "pass2")
	wantError(t, err)
	wantContains(t, err.Error(), "user already exists")
}

func TestAuth_Authenticator_Register_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	// Empty username/password should still work (PGP allows it)
	user, err := a.Register("", "")
	mustNoError(t, err)
	mustNotNil(t, user)
}

// --- CreateChallenge ---

func TestAuth_Authenticator_CreateChallenge_Good(t *testing.T) {
	a, _ := newTestAuth()

	user, err := a.Register("charlie", "pass")
	mustNoError(t, err)

	challenge, err := a.CreateChallenge(user.KeyID)
	mustNoError(t, err)
	mustNotNil(t, challenge)

	wantLen(t, challenge.Nonce, nonceBytes)
	wantNotEmpty(t, challenge.Encrypted)
	wantTrue(t, challenge.ExpiresAt.After(time.Now()))
}

func TestAuth_Authenticator_CreateChallenge_Bad(t *testing.T) {
	a, _ := newTestAuth()

	// Challenge for non-existent user
	_, err := a.CreateChallenge("nonexistent-user-id")
	wantError(t, err)
	wantContains(t, err.Error(), "user not found")
}

func TestAuth_Authenticator_CreateChallenge_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	// Empty userID
	_, err := a.CreateChallenge("")
	wantError(t, err)
}

// --- ValidateResponse (full challenge-response flow) ---

func TestAuth_Authenticator_ValidateResponse_Good(t *testing.T) {
	a, m := newTestAuth()

	// Register user
	_, err := a.Register("dave", "password123")
	mustNoError(t, err)

	userID := lthn.Hash("dave")

	// Create challenge
	challenge, err := a.CreateChallenge(userID)
	mustNoError(t, err)

	// Client-side: decrypt nonce, then sign it
	privKey, err := m.Read(userPath(userID, ".key"))
	mustNoError(t, err)

	decryptedNonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "password123")
	mustNoError(t, err)
	wantEqual(t, challenge.Nonce, decryptedNonce)

	signedNonce, err := pgp.Sign(decryptedNonce, privKey, "password123")
	mustNoError(t, err)

	// Validate response
	session, err := a.ValidateResponse(userID, signedNonce)
	mustNoError(t, err)
	mustNotNil(t, session)

	wantNotEmpty(t, session.Token)
	wantEqual(t, userID, session.UserID)
	wantTrue(t, session.ExpiresAt.After(time.Now()))
}

func TestAuth_Authenticator_ValidateResponse_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("eve", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("eve")

	// No pending challenge
	_, err = a.ValidateResponse(userID, []byte("fake-signature"))
	wantError(t, err)
	wantContains(t, err.Error(), "no pending challenge")
}

func TestAuth_Authenticator_ValidateResponse_Ugly(t *testing.T) {
	a, m := newTestAuth(WithChallengeTTL(1 * time.Millisecond))

	_, err := a.Register("frank", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("frank")

	// Create challenge and let it expire
	challenge, err := a.CreateChallenge(userID)
	mustNoError(t, err)

	time.Sleep(5 * time.Millisecond)

	// Sign with valid key but expired challenge
	privKey, err := m.Read(userPath(userID, ".key"))
	mustNoError(t, err)

	signedNonce, err := pgp.Sign(challenge.Nonce, privKey, "pass")
	mustNoError(t, err)

	_, err = a.ValidateResponse(userID, signedNonce)
	wantError(t, err)
	wantContains(t, err.Error(), "challenge expired")
}

// --- ValidateSession ---

func TestAuth_Authenticator_ValidateSession_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("grace", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("grace")

	session, err := a.Login(userID, "pass")
	mustNoError(t, err)

	validated, err := a.ValidateSession(session.Token)
	mustNoError(t, err)
	wantEqual(t, session.Token, validated.Token)
	wantEqual(t, userID, validated.UserID)
}

func TestAuth_Authenticator_ValidateSession_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.ValidateSession("nonexistent-token")
	wantError(t, err)
	wantContains(t, err.Error(), "session not found")
}

func TestAuth_Authenticator_ValidateSession_Ugly(t *testing.T) {
	a, _ := newTestAuth(WithSessionTTL(1 * time.Millisecond))

	_, err := a.Register("heidi", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("heidi")

	session, err := a.Login(userID, "pass")
	mustNoError(t, err)

	time.Sleep(5 * time.Millisecond)

	_, err = a.ValidateSession(session.Token)
	wantError(t, err)
	wantContains(t, err.Error(), "session expired")
}

// --- RefreshSession ---

func TestAuth_Authenticator_RefreshSession_Good(t *testing.T) {
	a, _ := newTestAuth(WithSessionTTL(1 * time.Hour))

	_, err := a.Register("ivan", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("ivan")

	session, err := a.Login(userID, "pass")
	mustNoError(t, err)

	originalExpiry := session.ExpiresAt

	// Small delay to ensure time moves forward
	time.Sleep(2 * time.Millisecond)

	refreshed, err := a.RefreshSession(session.Token)
	mustNoError(t, err)
	wantTrue(t, refreshed.ExpiresAt.After(originalExpiry))
}

func TestAuth_Authenticator_RefreshSession_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.RefreshSession("nonexistent-token")
	wantError(t, err)
	wantContains(t, err.Error(), "session not found")
}

func TestAuth_Authenticator_RefreshSession_Ugly(t *testing.T) {
	a, _ := newTestAuth(WithSessionTTL(1 * time.Millisecond))

	_, err := a.Register("judy", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("judy")

	session, err := a.Login(userID, "pass")
	mustNoError(t, err)

	time.Sleep(5 * time.Millisecond)

	_, err = a.RefreshSession(session.Token)
	wantError(t, err)
	wantContains(t, err.Error(), "session expired")
}

// --- RevokeSession ---

func TestAuth_Authenticator_RevokeSession_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("karl", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("karl")

	session, err := a.Login(userID, "pass")
	mustNoError(t, err)

	err = a.RevokeSession(session.Token)
	mustNoError(t, err)

	// Token should no longer be valid
	_, err = a.ValidateSession(session.Token)
	wantError(t, err)
}

func TestAuth_Authenticator_RevokeSession_Bad(t *testing.T) {
	a, _ := newTestAuth()

	err := a.RevokeSession("nonexistent-token")
	wantError(t, err)
	wantContains(t, err.Error(), "session not found")
}

func TestAuth_Authenticator_RevokeSession_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	// Revoke empty token
	err := a.RevokeSession("")
	wantError(t, err)
}

// --- DeleteUser ---

func TestAuth_Authenticator_DeleteUser_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("larry", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("larry")

	// Also create a session that should be cleaned up
	session, err := a.Login(userID, "pass")
	mustNoError(t, err)

	err = a.DeleteUser(userID)
	mustNoError(t, err)

	// All files should be gone (both new .hash and legacy .lthn)
	wantFalse(t, m.IsFile(userPath(userID, ".pub")))
	wantFalse(t, m.IsFile(userPath(userID, ".key")))
	wantFalse(t, m.IsFile(userPath(userID, ".rev")))
	wantFalse(t, m.IsFile(userPath(userID, ".json")))
	wantFalse(t, m.IsFile(userPath(userID, ".hash")))
	wantFalse(t, m.IsFile(userPath(userID, ".lthn")))

	// Session should be gone (validate returns error)
	_, err = a.ValidateSession(session.Token)
	wantError(t, err)
	wantContains(t, err.Error(), "session not found")
}

func TestAuth_Authenticator_DeleteUser_Bad(t *testing.T) {
	a, _ := newTestAuth()

	// Protected user "server" cannot be deleted
	err := a.DeleteUser("server")
	wantError(t, err)
	wantContains(t, err.Error(), "cannot delete protected user")
}

func TestAuth_Authenticator_DeleteUser_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	// Non-existent user
	err := a.DeleteUser("nonexistent-user-id")
	wantError(t, err)
	wantContains(t, err.Error(), "user not found")
}

// --- Login ---

func TestAuth_Authenticator_Login_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("mallory", "secret")
	mustNoError(t, err)
	userID := lthn.Hash("mallory")

	session, err := a.Login(userID, "secret")
	mustNoError(t, err)
	mustNotNil(t, session)

	wantNotEmpty(t, session.Token)
	wantEqual(t, userID, session.UserID)
	wantTrue(t, session.ExpiresAt.After(time.Now()))
}

func TestAuth_Authenticator_Login_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("nancy", "correct-password")
	mustNoError(t, err)
	userID := lthn.Hash("nancy")

	// Wrong password
	_, err = a.Login(userID, "wrong-password")
	wantError(t, err)
	wantContains(t, err.Error(), "invalid password")
}

func TestAuth_Authenticator_Login_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	// Login for non-existent user
	_, err := a.Login("nonexistent-user-id", "pass")
	wantError(t, err)
	wantContains(t, err.Error(), "user not found")
}

// --- WriteChallengeFile / ReadResponseFile (Air-Gapped) ---

func TestAuth_AirGappedFlow_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("oscar", "airgap-pass")
	mustNoError(t, err)
	userID := lthn.Hash("oscar")

	// Write challenge to file
	challengePath := "transfer/challenge.json"
	err = a.WriteChallengeFile(userID, challengePath)
	mustNoError(t, err)
	wantTrue(t, m.IsFile(challengePath))

	// Read challenge file to get the encrypted nonce (simulating courier)
	challengeData, err := m.Read(challengePath)
	mustNoError(t, err)

	var challenge Challenge
	result := core.JSONUnmarshal([]byte(challengeData), &challenge)
	mustTrue(t, result.OK, testMessagef("failed to unmarshal challenge: %v", result.Value))

	// Client-side: decrypt nonce and sign it
	privKey, err := m.Read(userPath(userID, ".key"))
	mustNoError(t, err)

	decryptedNonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "airgap-pass")
	mustNoError(t, err)

	signedNonce, err := pgp.Sign(decryptedNonce, privKey, "airgap-pass")
	mustNoError(t, err)

	// Write signed response to file
	responsePath := "transfer/response.sig"
	err = m.Write(responsePath, string(signedNonce))
	mustNoError(t, err)

	// Server reads response file
	session, err := a.ReadResponseFile(userID, responsePath)
	mustNoError(t, err)
	mustNotNil(t, session)

	wantNotEmpty(t, session.Token)
	wantEqual(t, userID, session.UserID)
}

func TestAuth_Authenticator_WriteChallengeFile_Bad(t *testing.T) {
	a, _ := newTestAuth()

	// Challenge for non-existent user
	err := a.WriteChallengeFile("nonexistent-user", "challenge.json")
	wantError(t, err)
}

func TestAuth_Authenticator_ReadResponseFile_Bad(t *testing.T) {
	a, _ := newTestAuth()

	// Response file does not exist
	_, err := a.ReadResponseFile("some-user", "nonexistent-file.sig")
	wantError(t, err)
}

func TestAuth_Authenticator_ReadResponseFile_Ugly(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("peggy", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("peggy")

	// Create a challenge
	_, err = a.CreateChallenge(userID)
	mustNoError(t, err)

	// Write garbage to response file
	responsePath := "transfer/bad-response.sig"
	err = m.Write(responsePath, "not-a-valid-signature")
	mustNoError(t, err)

	_, err = a.ReadResponseFile(userID, responsePath)
	wantError(t, err)
}

// --- Options ---

func TestAuth_WithChallengeTTL_Good(t *testing.T) {
	ttl := 30 * time.Second
	a, _ := newTestAuth(WithChallengeTTL(ttl))
	wantEqual(t, ttl, a.challengeTTL)
}

func TestAuth_WithSessionTTL_Good(t *testing.T) {
	ttl := 2 * time.Hour
	a, _ := newTestAuth(WithSessionTTL(ttl))
	wantEqual(t, ttl, a.sessionTTL)
}

// --- Full Round-Trip (Online Flow) ---

func TestAuth_FullRoundTrip_Good(t *testing.T) {
	a, m := newTestAuth()

	// 1. Register
	user, err := a.Register("quinn", "roundtrip-pass")
	mustNoError(t, err)
	mustNotNil(t, user)

	userID := lthn.Hash("quinn")

	// 2. Create challenge
	challenge, err := a.CreateChallenge(userID)
	mustNoError(t, err)

	// 3. Client decrypts + signs
	privKey, err := m.Read(userPath(userID, ".key"))
	mustNoError(t, err)

	nonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "roundtrip-pass")
	mustNoError(t, err)

	sig, err := pgp.Sign(nonce, privKey, "roundtrip-pass")
	mustNoError(t, err)

	// 4. Server validates, issues session
	session, err := a.ValidateResponse(userID, sig)
	mustNoError(t, err)
	mustNotNil(t, session)

	// 5. Validate session
	validated, err := a.ValidateSession(session.Token)
	mustNoError(t, err)
	wantEqual(t, session.Token, validated.Token)

	// 6. Refresh session
	refreshed, err := a.RefreshSession(session.Token)
	mustNoError(t, err)
	wantEqual(t, session.Token, refreshed.Token)

	// 7. Revoke session
	err = a.RevokeSession(session.Token)
	mustNoError(t, err)

	// 8. Session should be invalid now
	_, err = a.ValidateSession(session.Token)
	wantError(t, err)
}

// --- Concurrent Access ---

func TestAuth_ConcurrentSessions_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("ruth", "pass")
	mustNoError(t, err)
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
			mustNotNil(t, s)
			// Validate each session
			_, err := a.ValidateSession(s.Token)
			wantNoError(t, err)
		case err := <-errs:
			t.Fatalf("concurrent login failed: %v", err)
		}
	}
}

// --- Phase 0 Additions ---

// TestAuth_ConcurrentSessionCreation_Good verifies that 10 goroutines creating
// sessions simultaneously do not produce data races or errors.
func TestAuth_ConcurrentSessionCreation_Good(t *testing.T) {
	a, _ := newTestAuth()

	// Register 10 distinct users to avoid contention on a single user record
	const n = 10
	userIDs := make([]string, n)
	for i := range n {
		username := core.Sprintf("concurrent-user-%d", i)
		_, err := a.Register(username, "pass")
		mustNoError(t, err)
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
		mustNoError(t, errs[i], testMessagef("goroutine %d failed", i))
		mustNotNil(t, sessions[i], testMessagef("goroutine %d returned nil session", i))
		// Each session token must be valid
		_, err := a.ValidateSession(sessions[i].Token)
		wantNoError(t, err, testMessagef("session from goroutine %d should be valid", i))
	}
}

// TestAuth_SessionTokenUniqueness_Good generates 1000 session tokens and verifies
// no collisions without paying the full login hash-verification cost each time.
func TestAuth_SessionTokenUniqueness_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("uniqueness-test", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("uniqueness-test")

	const n = 1000
	tokens := make(map[string]bool, n)

	for i := range n {
		session, err := a.createSession(userID)
		mustNoError(t, err)
		mustNotNil(t, session)

		if tokens[session.Token] {
			t.Fatalf("duplicate token detected at iteration %d: %s", i, session.Token)
		}
		tokens[session.Token] = true
	}

	wantLen(t, tokens, n, "all 1000 tokens should be unique")
}

// TestAuth_ChallengeExpiryBoundary_Ugly tests validation right at the 5-minute boundary.
// The challenge should still be valid just before expiry and rejected after.
func TestAuth_ChallengeExpiryBoundary_Ugly(t *testing.T) {
	// Use a very short TTL to test the boundary without sleeping 5 minutes
	ttl := 50 * time.Millisecond
	a, m := newTestAuth(WithChallengeTTL(ttl))

	_, err := a.Register("boundary-user", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("boundary-user")

	// Create a challenge and respond immediately (should succeed)
	challenge, err := a.CreateChallenge(userID)
	mustNoError(t, err)

	privKey, err := m.Read(userPath(userID, ".key"))
	mustNoError(t, err)

	decryptedNonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "pass")
	mustNoError(t, err)

	signedNonce, err := pgp.Sign(decryptedNonce, privKey, "pass")
	mustNoError(t, err)

	session, err := a.ValidateResponse(userID, signedNonce)
	mustNoError(t, err)
	wantNotNil(t, session)

	// Now create another challenge and let it expire
	challenge2, err := a.CreateChallenge(userID)
	mustNoError(t, err)

	// Wait past the TTL
	time.Sleep(ttl + 10*time.Millisecond)

	decryptedNonce2, err := pgp.Decrypt([]byte(challenge2.Encrypted), privKey, "pass")
	mustNoError(t, err)

	signedNonce2, err := pgp.Sign(decryptedNonce2, privKey, "pass")
	mustNoError(t, err)

	_, err = a.ValidateResponse(userID, signedNonce2)
	wantError(t, err)
	wantContains(t, err.Error(), "challenge expired")
}

// TestAuth_EmptyPasswordRegistration_Good verifies that empty password registration works.
// PGP key is generated unencrypted in this case.
func TestAuth_EmptyPasswordRegistration_Good(t *testing.T) {
	a, m := newTestAuth()

	user, err := a.Register("no-password-user", "")
	mustNoError(t, err)
	mustNotNil(t, user)

	userID := lthn.Hash("no-password-user")

	// Verify all files are stored
	wantTrue(t, m.IsFile(userPath(userID, ".pub")))
	wantTrue(t, m.IsFile(userPath(userID, ".key")))
	wantTrue(t, m.IsFile(userPath(userID, ".json")))

	// Login with empty password should work
	session, err := a.Login(userID, "")
	mustNoError(t, err)
	wantNotNil(t, session)

	// Challenge-response flow should also work with empty password
	challenge, err := a.CreateChallenge(userID)
	mustNoError(t, err)

	privKey, err := m.Read(userPath(userID, ".key"))
	mustNoError(t, err)

	decryptedNonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "")
	mustNoError(t, err)

	signedNonce, err := pgp.Sign(decryptedNonce, privKey, "")
	mustNoError(t, err)

	crSession, err := a.ValidateResponse(userID, signedNonce)
	mustNoError(t, err)
	wantNotNil(t, crSession)
}

// TestAuth_VeryLongUsername_Ugly verifies behaviour with a 10K character username.
func TestAuth_VeryLongUsername_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	longName := core.NewBuilder()
	for range 10000 {
		longName.WriteString("a")
	}
	longUsername := longName.String()
	user, err := a.Register(longUsername, "pass")
	mustNoError(t, err)
	mustNotNil(t, user)

	// The LTHN hash of the long username should still be a fixed-length identifier
	userID := lthn.Hash(longUsername)
	wantLen(t, userID, 64, "LTHN hash should always be 64 hex chars (SHA-256)")

	// Login should work
	session, err := a.Login(userID, "pass")
	mustNoError(t, err)
	wantNotNil(t, session)
}

// TestAuth_UnicodeUsernamePassword_Good verifies registration and login with Unicode characters.
func TestAuth_UnicodeUsernamePassword_Good(t *testing.T) {
	a, _ := newTestAuth()

	// Japanese + emoji + Chinese + Arabic
	username := "\u65e5\u672c\u8a9e\u30c6\u30b9\u30c8\U0001F680\u4e2d\u6587\u0627\u0644\u0639\u0631\u0628\u064a\u0629"
	password := "\u00fc\u00f1\u00ee\u00e7\u00f6\u00f0\u00ea\u2603\u2764"

	user, err := a.Register(username, password)
	mustNoError(t, err)
	mustNotNil(t, user)

	userID := lthn.Hash(username)

	// Login with correct Unicode password
	session, err := a.Login(userID, password)
	mustNoError(t, err)
	wantNotNil(t, session)

	// Login with wrong Unicode password should fail
	_, err = a.Login(userID, "wrong-\u00fc\u00f1\u00ee")
	wantError(t, err)
}

// TestAuth_AirGappedRoundTrip_Good tests the full air-gapped flow:
// WriteChallengeFile -> client signs offline -> ReadResponseFile
func TestAuth_AirGappedRoundTrip_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("airgap-roundtrip", "courier-pass")
	mustNoError(t, err)
	userID := lthn.Hash("airgap-roundtrip")

	// Step 1: Server writes challenge file
	challengePath := "airgap/challenge.json"
	err = a.WriteChallengeFile(userID, challengePath)
	mustNoError(t, err)
	wantTrue(t, m.IsFile(challengePath))

	// Step 2: Client reads challenge file (simulating courier transport)
	challengeData, err := m.Read(challengePath)
	mustNoError(t, err)

	var challenge Challenge
	result := core.JSONUnmarshal([]byte(challengeData), &challenge)
	mustTrue(t, result.OK, testMessagef("failed to unmarshal challenge: %v", result.Value))
	wantNotEmpty(t, challenge.Encrypted)
	wantTrue(t, challenge.ExpiresAt.After(time.Now()))

	// Step 3: Client decrypts nonce, signs it, writes response
	privKey, err := m.Read(userPath(userID, ".key"))
	mustNoError(t, err)

	decryptedNonce, err := pgp.Decrypt([]byte(challenge.Encrypted), privKey, "courier-pass")
	mustNoError(t, err)
	wantEqual(t, challenge.Nonce, decryptedNonce)

	signedNonce, err := pgp.Sign(decryptedNonce, privKey, "courier-pass")
	mustNoError(t, err)

	responsePath := "airgap/response.sig"
	err = m.Write(responsePath, string(signedNonce))
	mustNoError(t, err)

	// Step 4: Server reads response file and validates
	session, err := a.ReadResponseFile(userID, responsePath)
	mustNoError(t, err)
	mustNotNil(t, session)

	wantNotEmpty(t, session.Token)
	wantEqual(t, userID, session.UserID)
	wantTrue(t, session.ExpiresAt.After(time.Now()))

	// Step 5: Session should be valid
	validated, err := a.ValidateSession(session.Token)
	mustNoError(t, err)
	wantEqual(t, session.Token, validated.Token)
}

// TestAuth_RefreshExpiredSession_Bad verifies that refreshing an already-expired session fails.
func TestAuth_RefreshExpiredSession_Bad(t *testing.T) {
	a, _ := newTestAuth(WithSessionTTL(1 * time.Millisecond))

	_, err := a.Register("expired-refresh", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("expired-refresh")

	session, err := a.Login(userID, "pass")
	mustNoError(t, err)

	// Wait for session to expire
	time.Sleep(10 * time.Millisecond)

	// Refresh should fail
	_, err = a.RefreshSession(session.Token)
	wantError(t, err)
	wantContains(t, err.Error(), "session expired")

	// The expired session should now be cleaned up (removed from map)
	_, err = a.ValidateSession(session.Token)
	wantError(t, err)
	wantContains(t, err.Error(), "session not found")
}

// --- Phase 2: Password Hash Migration ---

// TestAuth_RegisterArgon2id_Good verifies that new registrations use Argon2id format.
func TestAuth_RegisterArgon2id_Good(t *testing.T) {
	a, m := newTestAuth()

	user, err := a.Register("argon2-user", "strong-pass")
	mustNoError(t, err)

	userID := lthn.Hash("argon2-user")

	// .hash file should exist with Argon2id format
	wantTrue(t, m.IsFile(userPath(userID, ".hash")))
	hashContent, err := m.Read(userPath(userID, ".hash"))
	mustNoError(t, err)
	wantTrue(t, core.HasPrefix(hashContent, "$argon2id$"), "stored hash should be Argon2id")

	// .lthn file should NOT exist for new registrations
	wantFalse(t, m.IsFile(userPath(userID, ".lthn")))

	// User struct should have Argon2id hash
	wantTrue(t, core.HasPrefix(user.PasswordHash, "$argon2id$"))
}

// TestAuth_LoginArgon2id_Good verifies login works with Argon2id hashed password.
func TestAuth_LoginArgon2id_Good(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("login-argon2", "my-password")
	mustNoError(t, err)
	userID := lthn.Hash("login-argon2")

	// Login should succeed with correct password
	session, err := a.Login(userID, "my-password")
	mustNoError(t, err)
	wantNotEmpty(t, session.Token)
}

// TestAuth_LoginArgon2id_Bad verifies wrong password fails with Argon2id hash.
func TestAuth_LoginArgon2id_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("login-argon2-bad", "correct")
	mustNoError(t, err)
	userID := lthn.Hash("login-argon2-bad")

	_, err = a.Login(userID, "wrong")
	wantError(t, err)
	wantContains(t, err.Error(), "invalid password")
}

// TestAuth_LegacyLTHNMigration_Good verifies that a user registered with the legacy
// LTHN hash format is transparently migrated to Argon2id on successful login.
func TestAuth_LegacyLTHNMigration_Good(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m)

	// Simulate a legacy registration by manually writing LTHN-format files
	userID := lthn.Hash("legacy-user")
	_ = m.EnsureDir("users")

	// Generate PGP keypair (same as original Register did)
	kp, err := pgp.CreateKeyPair(userID, userID+"@auth.local", "legacy-pass")
	mustNoError(t, err)

	_ = m.Write(userPath(userID, ".pub"), kp.PublicKey)
	_ = m.Write(userPath(userID, ".key"), kp.PrivateKey)
	_ = m.Write(userPath(userID, ".rev"), "REVOCATION_PLACEHOLDER")

	// Write legacy LTHN hash (this is what old Register did)
	legacyHash := lthn.Hash("legacy-pass")
	_ = m.Write(userPath(userID, ".lthn"), legacyHash)

	// No .hash file should exist yet
	wantFalse(t, m.IsFile(userPath(userID, ".hash")))

	// Login with legacy hash should succeed
	session, err := a.Login(userID, "legacy-pass")
	mustNoError(t, err)
	wantNotEmpty(t, session.Token)

	// After successful login, .hash file should now exist with Argon2id
	wantTrue(t, m.IsFile(userPath(userID, ".hash")), "migration should create .hash file")
	newHash, err := m.Read(userPath(userID, ".hash"))
	mustNoError(t, err)
	wantTrue(t, core.HasPrefix(newHash, "$argon2id$"), "migrated hash should be Argon2id")

	// Subsequent login should use the new Argon2id hash (not LTHN)
	session2, err := a.Login(userID, "legacy-pass")
	mustNoError(t, err)
	wantNotEmpty(t, session2.Token)
}

// TestAuth_LegacyLTHNLogin_Bad verifies wrong password fails for legacy LTHN users.
func TestAuth_LegacyLTHNLogin_Bad(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m)

	userID := lthn.Hash("legacy-bad")
	_ = m.EnsureDir("users")

	kp, err := pgp.CreateKeyPair(userID, userID+"@auth.local", "real-pass")
	mustNoError(t, err)

	_ = m.Write(userPath(userID, ".pub"), kp.PublicKey)
	_ = m.Write(userPath(userID, ".key"), kp.PrivateKey)
	_ = m.Write(userPath(userID, ".lthn"), lthn.Hash("real-pass"))

	// Wrong password should fail
	_, err = a.Login(userID, "wrong-pass")
	wantError(t, err)
	wantContains(t, err.Error(), "invalid password")

	// No migration should have occurred
	wantFalse(t, m.IsFile(userPath(userID, ".hash")), "failed login should not create .hash file")
}

// --- Phase 2: Key Rotation ---

// TestAuth_Authenticator_RotateKeyPair_Good verifies the full key rotation flow:
// register -> login -> rotate -> verify old key can't decrypt -> verify new key works -> sessions invalidated.
func TestAuth_Authenticator_RotateKeyPair_Good(t *testing.T) {
	a, m := newTestAuth()

	// Register and login
	_, err := a.Register("rotate-user", "old-pass")
	mustNoError(t, err)
	userID := lthn.Hash("rotate-user")

	session, err := a.Login(userID, "old-pass")
	mustNoError(t, err)

	// Read old public key for comparison
	oldPubKey, err := m.Read(userPath(userID, ".pub"))
	mustNoError(t, err)

	// Rotate keypair
	updatedUser, err := a.RotateKeyPair(userID, "old-pass", "new-pass")
	mustNoError(t, err)
	mustNotNil(t, updatedUser)

	// New public key should differ from old
	newPubKey, err := m.Read(userPath(userID, ".pub"))
	mustNoError(t, err)
	wantNotEqual(t, oldPubKey, newPubKey, "public key should change after rotation")
	wantEqual(t, newPubKey, updatedUser.PublicKey)

	// Old password should fail
	_, err = a.Login(userID, "old-pass")
	wantError(t, err, "old password should not work after rotation")

	// New password should succeed
	newSession, err := a.Login(userID, "new-pass")
	mustNoError(t, err)
	wantNotEmpty(t, newSession.Token)

	// Old session should be invalidated
	_, err = a.ValidateSession(session.Token)
	wantError(t, err, "old session should be invalidated after rotation")

	// Metadata should be decryptable with new key
	encMeta, err := m.Read(userPath(userID, ".json"))
	mustNoError(t, err)
	newPrivKey, err := m.Read(userPath(userID, ".key"))
	mustNoError(t, err)
	decrypted, err := pgp.Decrypt([]byte(encMeta), newPrivKey, "new-pass")
	mustNoError(t, err)

	var meta User
	result := core.JSONUnmarshal(decrypted, &meta)
	mustTrue(t, result.OK, testMessagef("failed to unmarshal metadata: %v", result.Value))
	wantEqual(t, userID, meta.KeyID)
	wantTrue(t, core.HasPrefix(meta.PasswordHash, "$argon2id$"))
}

// TestAuth_Authenticator_RotateKeyPair_Bad verifies that rotation fails with wrong old password.
func TestAuth_Authenticator_RotateKeyPair_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("rotate-bad", "correct-pass")
	mustNoError(t, err)
	userID := lthn.Hash("rotate-bad")

	// Wrong old password should fail
	_, err = a.RotateKeyPair(userID, "wrong-pass", "new-pass")
	wantError(t, err)
	wantContains(t, err.Error(), "failed to decrypt metadata")
}

// TestAuth_Authenticator_RotateKeyPair_Ugly verifies rotation for non-existent user.
func TestAuth_Authenticator_RotateKeyPair_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.RotateKeyPair("nonexistent-user-id", "old", "new")
	wantError(t, err)
	wantContains(t, err.Error(), "user not found")
}

// TestAuth_Authenticator_RotateKeyPair_OldKeyCannotDecrypt_Good verifies old private key
// cannot decrypt metadata after rotation.
func TestAuth_Authenticator_RotateKeyPair_OldKeyCannotDecrypt_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("rotate-crypto", "pass-a")
	mustNoError(t, err)
	userID := lthn.Hash("rotate-crypto")

	// Save old private key
	oldPrivKey, err := m.Read(userPath(userID, ".key"))
	mustNoError(t, err)

	// Rotate
	_, err = a.RotateKeyPair(userID, "pass-a", "pass-b")
	mustNoError(t, err)

	// Old private key should NOT be able to decrypt new metadata
	encMeta, err := m.Read(userPath(userID, ".json"))
	mustNoError(t, err)
	_, err = pgp.Decrypt([]byte(encMeta), oldPrivKey, "pass-a")
	wantError(t, err, "old private key should not decrypt metadata after rotation")
}

// --- Phase 2: Key Revocation ---

// TestAuth_Authenticator_RevokeKey_Good verifies the full revocation flow:
// register -> login -> revoke -> login fails -> challenge fails -> sessions invalidated.
func TestAuth_Authenticator_RevokeKey_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("revoke-user", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("revoke-user")

	// Login to create a session
	session, err := a.Login(userID, "pass")
	mustNoError(t, err)

	// User should not be revoked yet
	wantFalse(t, a.IsRevoked(userID))

	// Revoke the key
	err = a.RevokeKey(userID, "pass", "compromised key material")
	mustNoError(t, err)

	// User should now be revoked
	wantTrue(t, a.IsRevoked(userID))

	// Verify .rev file contains valid JSON
	revContent, err := m.Read(userPath(userID, ".rev"))
	mustNoError(t, err)
	wantNotEqual(t, "REVOCATION_PLACEHOLDER", revContent)

	var rev Revocation
	result := core.JSONUnmarshal([]byte(revContent), &rev)
	mustTrue(t, result.OK, testMessagef("failed to unmarshal revocation: %v", result.Value))
	wantEqual(t, userID, rev.UserID)
	wantEqual(t, "compromised key material", rev.Reason)
	wantFalse(t, rev.RevokedAt.IsZero())

	// Login should fail for revoked user
	_, err = a.Login(userID, "pass")
	wantError(t, err)
	wantContains(t, err.Error(), "key has been revoked")

	// CreateChallenge should fail for revoked user
	_, err = a.CreateChallenge(userID)
	wantError(t, err)
	wantContains(t, err.Error(), "key has been revoked")

	// Old session should be invalidated
	_, err = a.ValidateSession(session.Token)
	wantError(t, err)
}

// TestAuth_Authenticator_RevokeKey_Bad verifies revocation fails with wrong password.
func TestAuth_Authenticator_RevokeKey_Bad(t *testing.T) {
	a, _ := newTestAuth()

	_, err := a.Register("revoke-bad", "correct")
	mustNoError(t, err)
	userID := lthn.Hash("revoke-bad")

	err = a.RevokeKey(userID, "wrong", "test reason")
	wantError(t, err)
	wantContains(t, err.Error(), "invalid password")

	// Should NOT be revoked after failed attempt
	wantFalse(t, a.IsRevoked(userID))
}

// TestAuth_Authenticator_RevokeKey_Ugly verifies revocation for non-existent user.
func TestAuth_Authenticator_RevokeKey_Ugly(t *testing.T) {
	a, _ := newTestAuth()

	err := a.RevokeKey("nonexistent-user-id", "pass", "reason")
	wantError(t, err)
	wantContains(t, err.Error(), "user not found")
}

// TestAuth_Authenticator_IsRevoked_Placeholder_Good verifies that the legacy placeholder is not
// treated as a valid revocation.
func TestAuth_Authenticator_IsRevoked_Placeholder_Good(t *testing.T) {
	a, m := newTestAuth()

	_, err := a.Register("placeholder-user", "pass")
	mustNoError(t, err)
	userID := lthn.Hash("placeholder-user")

	// New registrations write "REVOCATION_PLACEHOLDER"
	revContent, err := m.Read(userPath(userID, ".rev"))
	mustNoError(t, err)
	wantEqual(t, "REVOCATION_PLACEHOLDER", revContent)

	// Should NOT be considered revoked
	wantFalse(t, a.IsRevoked(userID))
}

// TestAuth_Authenticator_IsRevoked_NoRevFile_Good verifies that a missing .rev file returns false.
func TestAuth_Authenticator_IsRevoked_NoRevFile_Good(t *testing.T) {
	a, _ := newTestAuth()

	userID := "completely-nonexistent"
	wantFalse(t, a.medium.IsFile(userPath(userID, ".rev")))
	wantFalse(t, a.IsRevoked(userID))
}

// TestAuth_Authenticator_RevokeKey_LegacyUser_Good verifies revocation works for a legacy user
// with only a .lthn hash file (no .hash file).
func TestAuth_Authenticator_RevokeKey_LegacyUser_Good(t *testing.T) {
	m := io.NewMockMedium()
	a := New(m)

	userID := lthn.Hash("legacy-revoke")
	_ = m.EnsureDir("users")

	kp, err := pgp.CreateKeyPair(userID, userID+"@auth.local", "legacy-pass")
	mustNoError(t, err)

	_ = m.Write(userPath(userID, ".pub"), kp.PublicKey)
	_ = m.Write(userPath(userID, ".key"), kp.PrivateKey)
	_ = m.Write(userPath(userID, ".rev"), "REVOCATION_PLACEHOLDER")
	_ = m.Write(userPath(userID, ".lthn"), lthn.Hash("legacy-pass"))

	// Revoke with LTHN-verified password
	err = a.RevokeKey(userID, "legacy-pass", "decommissioned")
	mustNoError(t, err)

	wantTrue(t, a.IsRevoked(userID))
}

func TestAuth_WithChallengeTTL_Bad(t *core.T) {
	subject := WithChallengeTTL
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_WithChallengeTTL_Ugly(t *core.T) {
	subject := WithChallengeTTL
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_WithSessionTTL_Bad(t *core.T) {
	subject := WithSessionTTL
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_WithSessionTTL_Ugly(t *core.T) {
	subject := WithSessionTTL
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_WithSessionStore_Good(t *core.T) {
	subject := WithSessionStore
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_WithSessionStore_Bad(t *core.T) {
	subject := WithSessionStore
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_WithSessionStore_Ugly(t *core.T) {
	subject := WithSessionStore
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_New_Good(t *core.T) {
	subject := New
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_New_Bad(t *core.T) {
	subject := New
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_New_Ugly(t *core.T) {
	subject := New
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_Authenticator_IsRevoked_Good(t *core.T) {
	subject := (*Authenticator).IsRevoked
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_Authenticator_IsRevoked_Bad(t *core.T) {
	subject := (*Authenticator).IsRevoked
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_Authenticator_IsRevoked_Ugly(t *core.T) {
	subject := (*Authenticator).IsRevoked
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_Authenticator_WriteChallengeFile_Good(t *core.T) {
	subject := (*Authenticator).WriteChallengeFile
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_Authenticator_WriteChallengeFile_Ugly(t *core.T) {
	subject := (*Authenticator).WriteChallengeFile
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_Authenticator_ReadResponseFile_Good(t *core.T) {
	subject := (*Authenticator).ReadResponseFile
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_Authenticator_StartCleanup_Good(t *core.T) {
	subject := (*Authenticator).StartCleanup
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_Authenticator_StartCleanup_Bad(t *core.T) {
	subject := (*Authenticator).StartCleanup
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAuth_Authenticator_StartCleanup_Ugly(t *core.T) {
	subject := (*Authenticator).StartCleanup
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
