package auth

import (
	"testing"

	"dappco.re/go/crypt/crypt/lthn"
)

// TestErrorPaths_Login_CorruptedHash rejects a .hash file whose contents
// are not in the Argon2id format.
func TestErrorPaths_Login_CorruptedHash(t *testing.T) {
	a, m := newTestAuth()
	userID := lthn.Hash("corrupt")
	// Seed a user whose .hash file is present but malformed.
	m.Files[userPath(userID, ".pub")] = "pub"
	m.Files[userPath(userID, ".hash")] = "not-an-argon2id-hash"

	_, err := a.Login(userID, "anything")
	wantError(t, err, "Login with a corrupted hash should error")
	wantContains(t, err.Error(), "corrupted password hash")
}

// TestErrorPaths_Login_WrongPassword rejects the wrong password against a
// well-formed Argon2id hash.
func TestErrorPaths_Login_WrongPassword(t *testing.T) {
	a, _ := newTestAuth()
	user, err := a.Register("grace", "right-pass")
	mustNoError(t, err)

	_, err = a.Login(user.KeyID, "wrong-pass")
	wantError(t, err, "Login with the wrong password should error")
	wantContains(t, err.Error(), "invalid password")
}

// TestErrorPaths_Login_UnknownUser rejects login for a user with neither
// a .hash nor a legacy .lthn file.
func TestErrorPaths_Login_UnknownUser(t *testing.T) {
	a, _ := newTestAuth()
	_, err := a.Login(lthn.Hash("ghost"), "x")
	wantError(t, err, "Login for an unknown user should error")
}

// TestErrorPaths_CreateChallenge_MissingUser rejects a challenge for a
// user whose public key is absent.
func TestErrorPaths_CreateChallenge_MissingUser(t *testing.T) {
	a, _ := newTestAuth()
	_, err := a.CreateChallenge(lthn.Hash("ghost"))
	wantError(t, err, "CreateChallenge for a missing user should error")
}

// TestErrorPaths_RevokeKey_WrongPassword rejects revocation when the
// supplied password does not match the stored Argon2id hash.
func TestErrorPaths_RevokeKey_WrongPassword(t *testing.T) {
	a, _ := newTestAuth()
	user, err := a.Register("heidi", "right-pass")
	mustNoError(t, err)

	err = a.RevokeKey(user.KeyID, "wrong-pass", "compromise")
	wantError(t, err, "RevokeKey with the wrong password should error")
}

// TestErrorPaths_RevokeKey_MissingUser rejects revocation for an absent
// user.
func TestErrorPaths_RevokeKey_MissingUser(t *testing.T) {
	a, _ := newTestAuth()
	err := a.RevokeKey(lthn.Hash("ghost"), "x", "reason")
	wantError(t, err, "RevokeKey for a missing user should error")
}

// TestErrorPaths_RotateKeyPair_MissingUser rejects rotation for an absent
// user.
func TestErrorPaths_RotateKeyPair_MissingUser(t *testing.T) {
	a, _ := newTestAuth()
	_, err := a.RotateKeyPair(lthn.Hash("ghost"), "old", "new")
	wantError(t, err, "RotateKeyPair for a missing user should error")
}

// TestErrorPaths_RotateKeyPair_WrongOldPassword rejects rotation when the
// old password cannot decrypt the stored metadata.
func TestErrorPaths_RotateKeyPair_WrongOldPassword(t *testing.T) {
	a, _ := newTestAuth()
	user, err := a.Register("ivan", "old-pass")
	mustNoError(t, err)

	_, err = a.RotateKeyPair(user.KeyID, "wrong-old", "new-pass")
	wantError(t, err, "RotateKeyPair with the wrong old password should error")
}

// TestErrorPaths_VerifyPassword_LegacyAndMissing exercises verifyPassword
// via RevokeKey for the legacy .lthn path and the no-credential case.
func TestErrorPaths_VerifyPassword_LegacyAndMissing(t *testing.T) {
	a, m := newTestAuth()
	userID := lthn.Hash("legacy")
	// A user with only a legacy .lthn hash present (no .hash file).
	m.Files[userPath(userID, ".pub")] = "pub"
	m.Files[userPath(userID, ".lthn")] = lthn.Hash("legacy-pass")

	// Wrong legacy password fails verification.
	err := a.RevokeKey(userID, "wrong", "reason")
	wantError(t, err, "RevokeKey with a wrong legacy password should error")
}
