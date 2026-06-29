package pgp

import (
	"testing"
)

const notAKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnonsense\n-----END PGP PUBLIC KEY BLOCK-----\n"

// TestErrorPaths_Encrypt_BadPublicKey rejects an unparsable public key.
func TestErrorPaths_Encrypt_BadPublicKey(t *testing.T) {
	_, err := Encrypt([]byte("data"), notAKey)
	wantError(t, err, "Encrypt with an unreadable public key should error")
	_, err = Encrypt([]byte("data"), "")
	wantError(t, err, "Encrypt with an empty public key should error")
}

// TestErrorPaths_Decrypt_BadPrivateKey rejects an unparsable private key.
func TestErrorPaths_Decrypt_BadPrivateKey(t *testing.T) {
	_, err := Decrypt([]byte("data"), notAKey, "")
	wantError(t, err, "Decrypt with an unreadable private key should error")
}

// TestErrorPaths_Decrypt_WrongPassword rejects the wrong password on a
// password-protected key, and a non-armored message body.
func TestErrorPaths_Decrypt_WrongPassword(t *testing.T) {
	kp, err := CreateKeyPair("Secure", "secure@example.com", "right-pass")
	mustNoError(t, err, "create key pair")
	ct, err := Encrypt([]byte("secret"), kp.PublicKey)
	mustNoError(t, err, "encrypt")

	_, err = Decrypt(ct, kp.PrivateKey, "wrong-pass")
	wantError(t, err, "Decrypt with the wrong key password should error")
}

// TestErrorPaths_Decrypt_GarbageMessage rejects a non-PGP message body.
func TestErrorPaths_Decrypt_GarbageMessage(t *testing.T) {
	kp, err := CreateKeyPair("User", "user@example.com", "")
	mustNoError(t, err, "create key pair")
	_, err = Decrypt([]byte("not an armored pgp message"), kp.PrivateKey, "")
	wantError(t, err, "Decrypt of a non-armored body should error")
}

// TestErrorPaths_Sign_BadPrivateKey rejects an unparsable private key.
func TestErrorPaths_Sign_BadPrivateKey(t *testing.T) {
	_, err := Sign([]byte("data"), notAKey, "")
	wantError(t, err, "Sign with an unreadable private key should error")
}

// TestErrorPaths_Sign_WrongPassword rejects the wrong password on a
// password-protected signing key.
func TestErrorPaths_Sign_WrongPassword(t *testing.T) {
	kp, err := CreateKeyPair("Signer", "signer@example.com", "key-pass")
	mustNoError(t, err, "create key pair")
	_, err = Sign([]byte("data"), kp.PrivateKey, "wrong-pass")
	wantError(t, err, "Sign with the wrong key password should error")
}

// TestErrorPaths_Verify_BadPublicKey rejects an unparsable public key.
func TestErrorPaths_Verify_BadPublicKey(t *testing.T) {
	err := Verify([]byte("data"), []byte("sig"), notAKey)
	wantError(t, err, "Verify with an unreadable public key should error")
}

// TestErrorPaths_Verify_BadSignature rejects a garbage signature and a
// signature over different data.
func TestErrorPaths_Verify_BadSignature(t *testing.T) {
	kp, err := CreateKeyPair("Signer", "signer@example.com", "")
	mustNoError(t, err, "create key pair")
	sig, err := Sign([]byte("original"), kp.PrivateKey, "")
	mustNoError(t, err, "sign")

	// Garbage signature.
	err = Verify([]byte("original"), []byte("garbage"), kp.PublicKey)
	wantError(t, err, "Verify of a garbage signature should error")

	// Valid signature over a different payload.
	err = Verify([]byte("tampered"), sig, kp.PublicKey)
	wantError(t, err, "Verify against tampered data should error")
}

// TestErrorPaths_CreateKeyPair_PasswordRoundTrip exercises the
// password-protected serialisation path (serializeEncryptedEntity) and
// confirms the resulting key pair encrypts/decrypts end to end.
func TestErrorPaths_CreateKeyPair_PasswordRoundTrip(t *testing.T) {
	const pass = "envelope-pass"
	kp, err := CreateKeyPair("Boxed", "boxed@example.com", pass)
	mustNoError(t, err, "create password-protected key pair")
	wantNotEqual(t, "", kp.PrivateKey, "private key armored")

	ct, err := Encrypt([]byte("payload"), kp.PublicKey)
	mustNoError(t, err, "encrypt to boxed key")
	pt, err := Decrypt(ct, kp.PrivateKey, pass)
	mustNoError(t, err, "decrypt with password")
	wantEqual(t, []byte("payload"), pt, "round-trip restores payload")
}
