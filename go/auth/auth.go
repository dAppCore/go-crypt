// Package auth implements OpenPGP challenge-response authentication with
// support for both online (HTTP) and air-gapped (file-based) transport.
//
// Ported from dAppServer's mod-auth/lethean.service.ts.
//
// Authentication Flow (Online):
//
//  1. Client sends public key to server
//  2. Server generates a random nonce, encrypts it with client's public key
//  3. Client decrypts the nonce and signs it with their private key
//  4. Server verifies the signature, creates a session token
//
// Authentication Flow (Air-Gapped / Courier):
//
//	Same crypto but challenge/response are exchanged via files on a Medium.
//
// Storage Layout (via Medium):
//
//	users/
//	  {userID}.pub      PGP public key (armored)
//	  {userID}.key      PGP private key (armored, password-encrypted)
//	  {userID}.rev      Revocation record (JSON) or legacy placeholder
//	  {userID}.json     User metadata (encrypted with user's public key)
//	  {userID}.hash     Argon2id password hash (new registrations)
//	  {userID}.lthn     LTHN password hash (legacy, migrated on login)
package auth

import (
	"context"
	"crypto/rand"
	"sync"
	"time"

	core "dappco.re/go"
	"dappco.re/go/crypt/crypt"
	"dappco.re/go/crypt/crypt/lthn"
	"dappco.re/go/crypt/crypt/pgp"
	"dappco.re/go/crypt/internal/corecompat"
	"dappco.re/go/io"
	coreerr "dappco.re/go/log"
)

const (
	// DefaultChallengeTTL is the default lifetime for a generated challenge.
	// Usage: pass DefaultChallengeTTL into WithChallengeTTL(...) to keep the package default.
	DefaultChallengeTTL = 5 * time.Minute
	// DefaultSessionTTL is the default lifetime for an authenticated session.
	// Usage: pass DefaultSessionTTL into WithSessionTTL(...) to keep the package default.
	DefaultSessionTTL = 24 * time.Hour
	nonceBytes        = 32
)

// protectedUsers lists usernames that cannot be deleted.
// The "server" user holds the server keypair; deleting it would
// permanently destroy all joining data and require a full rebuild.
var protectedUsers = map[string]bool{
	"server": true,
}

// User represents a registered user with PGP credentials.
// Usage: use User with the other exported helpers in this package.
type User struct {
	PublicKey    string    `json:"public_key"`
	KeyID        string    `json:"key_id"`
	Fingerprint  string    `json:"fingerprint"`
	PasswordHash string    `json:"password_hash"` // Argon2id (new) or LTHN (legacy)
	Created      time.Time `json:"created"`
	LastLogin    time.Time `json:"last_login"`
}

// Challenge is a PGP-encrypted nonce sent to a client during authentication.
// Usage: use Challenge with the other exported helpers in this package.
type Challenge struct {
	Nonce     []byte    `json:"nonce"`
	Encrypted string    `json:"encrypted"` // PGP-encrypted nonce (armored)
	ExpiresAt time.Time `json:"expires_at"`
}

// Session represents an authenticated session.
// Usage: use Session with the other exported helpers in this package.
type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Revocation records the details of a revoked user key.
// Stored as JSON in the user's .rev file, replacing the legacy placeholder.
// Usage: use Revocation with the other exported helpers in this package.
type Revocation struct {
	UserID    string    `json:"user_id"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

// Option configures an Authenticator.
// Usage: use Option with the other exported helpers in this package.
type Option func(*Authenticator)

// WithChallengeTTL sets the lifetime of a challenge before it expires.
// Usage: pass WithChallengeTTL(...) into the related constructor to adjust the default behaviour.
func WithChallengeTTL(d time.Duration) Option {
	return func(a *Authenticator) {
		a.challengeTTL = d
	}
}

// WithSessionTTL sets the lifetime of a session before it expires.
// Usage: pass WithSessionTTL(...) into the related constructor to adjust the default behaviour.
func WithSessionTTL(d time.Duration) Option {
	return func(a *Authenticator) {
		a.sessionTTL = d
	}
}

// WithSessionStore sets the SessionStore implementation.
// If not provided, an in-memory store is used (sessions lost on restart).
// Usage: pass WithSessionStore(...) into the related constructor to adjust the default behaviour.
func WithSessionStore(s SessionStore) Option {
	return func(a *Authenticator) {
		a.store = s
	}
}

// Authenticator manages PGP-based challenge-response authentication.
// All user data and keys are persisted through an io.Medium, which may
// be backed by disk, memory (MockMedium), or any other storage backend.
// Sessions are persisted via a SessionStore (in-memory by default,
// optionally SQLite-backed for crash recovery).
//
// An optional HardwareKey can be provided via WithHardwareKey for
// hardware-backed cryptographic operations (PKCS#11, YubiKey, etc.).
// See auth/hardware.go for the interface definition and integration points.
// Usage: create an Authenticator with New(...) and then call Register, Login, or CreateChallenge.
type Authenticator struct {
	medium       io.Medium
	store        SessionStore
	hardwareKey  HardwareKey           // optional hardware key (nil = software only)
	challenges   map[string]*Challenge // userID -> pending challenge
	mu           sync.RWMutex          // protects challenges map only
	challengeTTL time.Duration
	sessionTTL   time.Duration
}

// New creates an Authenticator that persists user data via the given Medium.
// By default, sessions are stored in memory. Use WithSessionStore to provide
// a persistent implementation (e.g. SQLiteSessionStore).
// Usage: call New(...) to create a ready-to-use value.
func New(m io.Medium, opts ...Option) *Authenticator {
	a := &Authenticator{
		medium:       m,
		challenges:   make(map[string]*Challenge),
		challengeTTL: DefaultChallengeTTL,
		sessionTTL:   DefaultSessionTTL,
	}
	for _, opt := range opts {
		opt(a)
	}
	// Default to in-memory store if none provided via WithSessionStore
	if a.store == nil {
		a.store = NewMemorySessionStore()
	}
	return a
}

// userPath returns the storage path for a user artifact.
func userPath(userID, ext string) string {
	return "users/" + userID + ext
}

// Register creates a new user account. It hashes the username with LTHN to
// produce a userID, generates a PGP keypair (protected by the given password),
// and persists the public key, private key, revocation placeholder, password
// hash (Argon2id), and encrypted metadata via the Medium.
// Usage: call Register(...) during the package's normal workflow.
func (a *Authenticator) Register(username, password string) (*User, error) {
	const op = "auth.Register"

	userID := lthn.Hash(username)

	// Check if user already exists
	if a.medium.IsFile(userPath(userID, ".pub")) {
		return nil, coreerr.E(op, "user already exists", nil)
	}

	// Ensure users directory exists
	if err := a.medium.EnsureDir("users"); err != nil {
		return nil, coreerr.E(op, "failed to create users directory", err)
	}

	// Generate PGP keypair
	kp, err := pgp.CreateKeyPair(userID, userID+"@auth.local", password)
	if err != nil {
		return nil, coreerr.E(op, "failed to create PGP keypair", err)
	}

	// Store public key
	if err := a.medium.Write(userPath(userID, ".pub"), kp.PublicKey); err != nil {
		return nil, coreerr.E(op, "failed to write public key", err)
	}

	// Store private key (already encrypted by PGP if password is non-empty)
	if err := a.medium.Write(userPath(userID, ".key"), kp.PrivateKey); err != nil {
		return nil, coreerr.E(op, "failed to write private key", err)
	}

	// Store revocation certificate placeholder
	if err := a.medium.Write(userPath(userID, ".rev"), "REVOCATION_PLACEHOLDER"); err != nil {
		return nil, coreerr.E(op, "failed to write revocation certificate", err)
	}

	// Store Argon2id password hash (replaces legacy LTHN hash for new registrations)
	passwordHash, err := crypt.HashPassword(password)
	if err != nil {
		return nil, coreerr.E(op, "failed to hash password", err)
	}
	if err := a.medium.Write(userPath(userID, ".hash"), passwordHash); err != nil {
		return nil, coreerr.E(op, "failed to write password hash", err)
	}

	// Build user metadata
	now := time.Now()
	user := &User{
		PublicKey:    kp.PublicKey,
		KeyID:        userID,
		Fingerprint:  lthn.Hash(kp.PublicKey),
		PasswordHash: passwordHash,
		Created:      now,
		LastLogin:    time.Time{},
	}

	// Encrypt metadata with the user's public key and store
	metaJSONResult := core.JSONMarshal(user)
	if !metaJSONResult.OK {
		err, _ := metaJSONResult.Value.(error)
		return nil, coreerr.E(op, "failed to marshal user metadata", err)
	}

	encMeta, err := pgp.Encrypt(metaJSONResult.Value.([]byte), kp.PublicKey)
	if err != nil {
		return nil, coreerr.E(op, "failed to encrypt user metadata", err)
	}

	if err := a.medium.Write(userPath(userID, ".json"), string(encMeta)); err != nil {
		return nil, coreerr.E(op, "failed to write user metadata", err)
	}

	return user, nil
}

// CreateChallenge generates a cryptographic challenge for the given user.
// A random nonce is created and encrypted with the user's PGP public key.
// The client must decrypt the nonce and sign it to prove key ownership.
// Usage: call CreateChallenge(...) during the package's normal workflow.
func (a *Authenticator) CreateChallenge(userID string) (*Challenge, error) {
	const op = "auth.CreateChallenge"

	// Reject challenges for revoked users
	if a.IsRevoked(userID) {
		return nil, coreerr.E(op, "key has been revoked", nil)
	}

	// Read user's public key
	pubKey, err := a.medium.Read(userPath(userID, ".pub"))
	if err != nil {
		return nil, coreerr.E(op, "user not found", err)
	}

	// Generate random nonce
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, coreerr.E(op, "failed to generate nonce", err)
	}

	// Encrypt nonce with user's public key
	encrypted, err := pgp.Encrypt(nonce, pubKey)
	if err != nil {
		return nil, coreerr.E(op, "failed to encrypt nonce", err)
	}

	challenge := &Challenge{
		Nonce:     nonce,
		Encrypted: string(encrypted),
		ExpiresAt: time.Now().Add(a.challengeTTL),
	}

	a.mu.Lock()
	a.challenges[userID] = challenge
	a.mu.Unlock()

	return challenge, nil
}

// ValidateResponse verifies a signed nonce from the client. The client must
// have decrypted the challenge nonce and signed it with their private key.
// On success, a new session is created and returned.
// Usage: call ValidateResponse(...) during the package's normal workflow.
func (a *Authenticator) ValidateResponse(userID string, signedNonce []byte) (*Session, error) {
	const op = "auth.ValidateResponse"

	a.mu.Lock()
	challenge, exists := a.challenges[userID]
	if exists {
		delete(a.challenges, userID)
	}
	a.mu.Unlock()

	if !exists {
		return nil, coreerr.E(op, "no pending challenge for user", nil)
	}

	// Check challenge expiry
	if time.Now().After(challenge.ExpiresAt) {
		return nil, coreerr.E(op, "challenge expired", nil)
	}

	// Read user's public key
	pubKey, err := a.medium.Read(userPath(userID, ".pub"))
	if err != nil {
		return nil, coreerr.E(op, "user not found", err)
	}

	// Verify signature over the original nonce
	if err := pgp.Verify(challenge.Nonce, signedNonce, pubKey); err != nil {
		return nil, coreerr.E(op, "signature verification failed", err)
	}

	return a.createSession(userID)
}

// ValidateSession checks whether a token maps to a valid, non-expired session.
// Usage: call ValidateSession(...) during the package's normal workflow.
func (a *Authenticator) ValidateSession(token string) (*Session, error) {
	const op = "auth.ValidateSession"

	session, err := a.store.Get(token)
	if err != nil {
		return nil, coreerr.E(op, "session not found", nil)
	}

	if time.Now().After(session.ExpiresAt) {
		if err := a.store.Delete(token); err != nil {
			core.Print(nil, "auth.ValidateSession: failed to delete expired session: %v", err)
		}
		return nil, coreerr.E(op, "session expired", nil)
	}

	return session, nil
}

// RefreshSession extends the expiry of an existing valid session.
// Usage: call RefreshSession(...) during the package's normal workflow.
func (a *Authenticator) RefreshSession(token string) (*Session, error) {
	const op = "auth.RefreshSession"

	session, err := a.store.Get(token)
	if err != nil {
		return nil, coreerr.E(op, "session not found", nil)
	}

	if time.Now().After(session.ExpiresAt) {
		if err := a.store.Delete(token); err != nil {
			core.Print(nil, "auth.RefreshSession: failed to delete expired session: %v", err)
		}
		return nil, coreerr.E(op, "session expired", nil)
	}

	session.ExpiresAt = time.Now().Add(a.sessionTTL)
	if err := a.store.Set(session); err != nil {
		return nil, coreerr.E(op, "failed to update session", err)
	}
	return session, nil
}

// RevokeSession removes a session, invalidating the token immediately.
// Usage: call RevokeSession(...) during the package's normal workflow.
func (a *Authenticator) RevokeSession(token string) error {
	const op = "auth.RevokeSession"

	if err := a.store.Delete(token); err != nil {
		return coreerr.E(op, "session not found", nil)
	}
	return nil
}

// DeleteUser removes a user and all associated keys from storage.
// The "server" user is protected and cannot be deleted (mirroring the
// original TypeScript implementation's safeguard).
// Usage: call DeleteUser(...) during the package's normal workflow.
func (a *Authenticator) DeleteUser(userID string) error {
	const op = "auth.DeleteUser"

	// Protect special users
	if protectedUsers[userID] {
		return coreerr.E(op, "cannot delete protected user", nil)
	}

	// Check user exists
	if !a.medium.IsFile(userPath(userID, ".pub")) {
		return coreerr.E(op, "user not found", nil)
	}

	// Remove all artifacts (both new .hash and legacy .lthn)
	extensions := []string{".pub", ".key", ".rev", ".json", ".hash", ".lthn"}
	for _, ext := range extensions {
		p := userPath(userID, ext)
		if a.medium.IsFile(p) {
			if err := a.medium.Delete(p); err != nil {
				return coreerr.E(op, "failed to delete "+ext, err)
			}
		}
	}

	// Revoke any active sessions for this user
	if err := a.store.DeleteByUser(userID); err != nil {
		return coreerr.E(op, "failed to revoke active sessions", err)
	}

	return nil
}

// Login performs password-based authentication as a convenience method.
// It verifies the password against the stored hash and, on success,
// creates a new session. This bypasses the PGP challenge-response flow.
//
// Hash format detection:
//   - If a .hash file exists, its content starts with "$argon2id$" and is verified
//     using constant-time Argon2id comparison.
//   - Otherwise, falls back to legacy .lthn file with LTHN hash verification.
//     On successful legacy login, the password is re-hashed with Argon2id and
//     a .hash file is written (transparent migration).
//
// Usage: call Login(...) for password-based flows when challenge-response is not required.
func (a *Authenticator) Login(userID, password string) (*Session, error) {
	const op = "auth.Login"

	// Reject login for revoked users
	if a.IsRevoked(userID) {
		return nil, coreerr.E(op, "key has been revoked", nil)
	}

	// Try Argon2id hash first (.hash file)
	if a.medium.IsFile(userPath(userID, ".hash")) {
		storedHash, err := a.medium.Read(userPath(userID, ".hash"))
		if err != nil {
			return nil, coreerr.E(op, "failed to read password hash", err)
		}

		if !core.HasPrefix(storedHash, "$argon2id$") {
			return nil, coreerr.E(op, "corrupted password hash", nil)
		}
		valid, err := crypt.VerifyPassword(password, storedHash)
		if err != nil {
			return nil, coreerr.E(op, "failed to verify password", err)
		}
		if !valid {
			return nil, coreerr.E(op, "invalid password", nil)
		}
		return a.createSession(userID)
	}

	// Fall back to legacy LTHN hash (.lthn file)
	storedHash, err := a.medium.Read(userPath(userID, ".lthn"))
	if err != nil {
		return nil, coreerr.E(op, "user not found", err)
	}

	if !lthn.Verify(password, storedHash) {
		return nil, coreerr.E(op, "invalid password", nil)
	}

	// Migrate: re-hash with Argon2id and write .hash file
	newHash, err := crypt.HashPassword(password)
	if err == nil {
		// Best-effort migration — do not fail login if migration write fails
		if err := a.medium.Write(userPath(userID, ".hash"), newHash); err != nil {
			core.Print(nil, "auth.Login: password hash migration failed: %v", err)
		}
	}

	return a.createSession(userID)
}

// RotateKeyPair generates a new PGP keypair for the given user, re-encrypts
// their metadata with the new key, updates the password hash, and invalidates
// all existing sessions. The caller must provide the current password
// (oldPassword) to decrypt existing metadata and the new password (newPassword)
// to protect the new keypair.
// Usage: call RotateKeyPair(...) during the package's normal workflow.
func (a *Authenticator) RotateKeyPair(userID, oldPassword, newPassword string) (*User, error) {
	const op = "auth.RotateKeyPair"

	// Verify the user exists
	if !a.medium.IsFile(userPath(userID, ".pub")) {
		return nil, coreerr.E(op, "user not found", nil)
	}

	// Load current private key for metadata decryption
	privKeyArmor, err := a.medium.Read(userPath(userID, ".key"))
	if err != nil {
		return nil, coreerr.E(op, "failed to read private key", err)
	}

	// Load and decrypt current metadata
	encMeta, err := a.medium.Read(userPath(userID, ".json"))
	if err != nil {
		return nil, coreerr.E(op, "failed to read user metadata", err)
	}

	metaJSON, err := pgp.Decrypt([]byte(encMeta), privKeyArmor, oldPassword)
	if err != nil {
		return nil, coreerr.E(op, "failed to decrypt metadata (wrong password?)", err)
	}

	var user User
	metaResult := core.JSONUnmarshal(metaJSON, &user)
	if !metaResult.OK {
		err, _ := metaResult.Value.(error)
		return nil, coreerr.E(op, "failed to unmarshal user metadata", err)
	}

	// Generate new PGP keypair
	newKP, err := pgp.CreateKeyPair(userID, userID+"@auth.local", newPassword)
	if err != nil {
		return nil, coreerr.E(op, "failed to create new PGP keypair", err)
	}

	// Update user metadata with new key material
	user.PublicKey = newKP.PublicKey
	user.Fingerprint = lthn.Hash(newKP.PublicKey)

	// Hash new password with Argon2id
	newHash, err := crypt.HashPassword(newPassword)
	if err != nil {
		return nil, coreerr.E(op, "failed to hash new password", err)
	}
	user.PasswordHash = newHash

	// Re-encrypt metadata with new public key
	updatedMetaResult := core.JSONMarshal(&user)
	if !updatedMetaResult.OK {
		err, _ := updatedMetaResult.Value.(error)
		return nil, coreerr.E(op, "failed to marshal updated metadata", err)
	}

	encUpdatedMeta, err := pgp.Encrypt(updatedMetaResult.Value.([]byte), newKP.PublicKey)
	if err != nil {
		return nil, coreerr.E(op, "failed to encrypt metadata with new key", err)
	}

	// Write new files (overwrite existing)
	if err := a.medium.Write(userPath(userID, ".pub"), newKP.PublicKey); err != nil {
		return nil, coreerr.E(op, "failed to write new public key", err)
	}
	if err := a.medium.Write(userPath(userID, ".key"), newKP.PrivateKey); err != nil {
		return nil, coreerr.E(op, "failed to write new private key", err)
	}
	if err := a.medium.Write(userPath(userID, ".json"), string(encUpdatedMeta)); err != nil {
		return nil, coreerr.E(op, "failed to write updated metadata", err)
	}
	if err := a.medium.Write(userPath(userID, ".hash"), newHash); err != nil {
		return nil, coreerr.E(op, "failed to write new password hash", err)
	}

	// Invalidate all sessions for this user
	if err := a.store.DeleteByUser(userID); err != nil {
		return nil, coreerr.E(op, "failed to invalidate sessions", err)
	}

	return &user, nil
}

// RevokeKey marks a user's key as revoked. It verifies the password first,
// writes a JSON revocation record to the .rev file (replacing the placeholder),
// and invalidates all sessions for the user.
// Usage: call RevokeKey(...) during the package's normal workflow.
func (a *Authenticator) RevokeKey(userID, password, reason string) error {
	const op = "auth.RevokeKey"

	// Verify user exists
	if !a.medium.IsFile(userPath(userID, ".pub")) {
		return coreerr.E(op, "user not found", nil)
	}

	// Verify password — try Argon2id first, then fall back to LTHN
	if err := a.verifyPassword(userID, password); err != nil {
		return coreerr.E(op, err.Error(), nil)
	}

	// Write revocation record as JSON
	rev := Revocation{
		UserID:    userID,
		Reason:    reason,
		RevokedAt: time.Now(),
	}
	revJSONResult := core.JSONMarshal(&rev)
	if !revJSONResult.OK {
		err, _ := revJSONResult.Value.(error)
		return coreerr.E(op, "failed to marshal revocation record", err)
	}
	if err := a.medium.Write(userPath(userID, ".rev"), string(revJSONResult.Value.([]byte))); err != nil {
		return coreerr.E(op, "failed to write revocation record", err)
	}

	// Invalidate all sessions
	if err := a.store.DeleteByUser(userID); err != nil {
		return coreerr.E(op, "failed to invalidate sessions", err)
	}

	return nil
}

// IsRevoked checks whether a user's key has been revoked by inspecting the
// .rev file. Returns true only if the file contains valid revocation JSON
// (not the legacy "REVOCATION_PLACEHOLDER" string).
// Usage: call IsRevoked(...) during the package's normal workflow.
func (a *Authenticator) IsRevoked(userID string) bool {
	content, err := a.medium.Read(userPath(userID, ".rev"))
	if err != nil {
		return false
	}

	// Legacy placeholder is not a valid revocation
	if content == "REVOCATION_PLACEHOLDER" {
		return false
	}

	// Attempt to parse as JSON revocation record
	var rev Revocation
	revResult := core.JSONUnmarshal([]byte(content), &rev)
	if !revResult.OK {
		return false
	}

	// Valid revocation must have a non-zero timestamp
	return !rev.RevokedAt.IsZero()
}

// WriteChallengeFile writes an encrypted challenge to a file for air-gapped
// (courier) transport. The challenge is created and then its encrypted nonce
// is written to the specified path on the Medium.
// Usage: call WriteChallengeFile(...) during the package's normal workflow.
func (a *Authenticator) WriteChallengeFile(userID, path string) error {
	const op = "auth.WriteChallengeFile"

	challenge, err := a.CreateChallenge(userID)
	if err != nil {
		return coreerr.E(op, "failed to create challenge", err)
	}

	challengeResult := core.JSONMarshal(challenge)
	if !challengeResult.OK {
		err, _ := challengeResult.Value.(error)
		return coreerr.E(op, "failed to marshal challenge", err)
	}

	if err := a.medium.Write(path, string(challengeResult.Value.([]byte))); err != nil {
		return coreerr.E(op, "failed to write challenge file", err)
	}

	return nil
}

// ReadResponseFile reads a signed response from a file and validates it,
// completing the air-gapped authentication flow. The file must contain the
// raw PGP signature bytes (armored).
// Usage: call ReadResponseFile(...) during the package's normal workflow.
func (a *Authenticator) ReadResponseFile(userID, path string) (*Session, error) {
	const op = "auth.ReadResponseFile"

	content, err := a.medium.Read(path)
	if err != nil {
		return nil, coreerr.E(op, "failed to read response file", err)
	}

	session, err := a.ValidateResponse(userID, []byte(content))
	if err != nil {
		return nil, coreerr.E(op, "failed to validate response", err)
	}

	return session, nil
}

// verifyPassword checks the given password against stored hashes for a user.
// Tries Argon2id (.hash) first, then falls back to legacy LTHN (.lthn).
// Returns nil on success, or an error describing the failure.
func (a *Authenticator) verifyPassword(userID, password string) error {
	const op = "auth.verifyPassword"

	// Try Argon2id hash first (.hash file)
	if a.medium.IsFile(userPath(userID, ".hash")) {
		storedHash, err := a.medium.Read(userPath(userID, ".hash"))
		if err != nil {
			return coreerr.E(op, "failed to read password hash", err)
		}
		if !core.HasPrefix(storedHash, "$argon2id$") {
			return coreerr.E(op, "corrupted password hash", nil)
		}
		valid, verr := crypt.VerifyPassword(password, storedHash)
		if verr != nil {
			return coreerr.E(op, "failed to verify password", verr)
		}
		if !valid {
			return coreerr.E(op, "invalid password", nil)
		}
		return nil
	}

	// Fall back to legacy LTHN hash (.lthn file)
	storedHash, err := a.medium.Read(userPath(userID, ".lthn"))
	if err != nil {
		return coreerr.E(op, "user not found", nil)
	}
	if !lthn.Verify(password, storedHash) {
		return coreerr.E(op, "invalid password", nil)
	}
	return nil
}

// createSession generates a cryptographically random session token and
// stores the session via the SessionStore.
func (a *Authenticator) createSession(userID string) (*Session, error) {
	const op = "auth.createSession"

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, coreerr.E(op, "failed to generate session token", err)
	}

	session := &Session{
		Token:     corecompat.HexEncode(tokenBytes),
		UserID:    userID,
		ExpiresAt: time.Now().Add(a.sessionTTL),
	}

	if err := a.store.Set(session); err != nil {
		return nil, coreerr.E(op, "failed to persist session", err)
	}

	return session, nil
}

// StartCleanup runs a background goroutine that periodically removes expired
// sessions from the store. It stops when the context is cancelled.
// Usage: call StartCleanup(...) during the package's normal workflow.
func (a *Authenticator) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				count, err := a.store.Cleanup()
				if err != nil {
					core.Print(nil, "auth: session cleanup error: %v", err)
					continue
				}
				if count > 0 {
					core.Print(nil, "auth: cleaned up %d expired session(s)", count)
				}
			}
		}
	}()
}
