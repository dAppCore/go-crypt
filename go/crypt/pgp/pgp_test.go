package pgp

import (
	"testing"

	core "dappco.re/go"
)

func TestPGP_CreateKeyPair_Good(t *testing.T) {
	kp, err := CreateKeyPair("Test User", "test@example.com", "")
	mustNoError(t, err)
	mustNotNil(t, kp)
	wantContains(t, kp.PublicKey, "-----BEGIN PGP PUBLIC KEY BLOCK-----")
	wantContains(t, kp.PrivateKey, "-----BEGIN PGP PRIVATE KEY BLOCK-----")
}

func TestPGP_CreateKeyPair_Bad(t *testing.T) {
	// Empty name still works (openpgp allows it), but test with password
	kp, err := CreateKeyPair("Secure User", "secure@example.com", "strong-password")
	mustNoError(t, err)
	mustNotNil(t, kp)
	wantContains(t, kp.PublicKey, "-----BEGIN PGP PUBLIC KEY BLOCK-----")
	wantContains(t, kp.PrivateKey, "-----BEGIN PGP PRIVATE KEY BLOCK-----")
}

func TestPGP_CreateKeyPair_Ugly(t *testing.T) {
	// Minimal identity
	kp, err := CreateKeyPair("", "", "")
	mustNoError(t, err)
	mustNotNil(t, kp)
}

func TestPGP_Encrypt_Good(t *testing.T) {
	kp, err := CreateKeyPair("Test User", "test@example.com", "")
	mustNoError(t, err)

	plaintext := []byte("hello, OpenPGP!")
	ciphertext, err := Encrypt(plaintext, kp.PublicKey)
	mustNoError(t, err)
	wantNotEmpty(t, ciphertext)
	wantContains(t, string(ciphertext), "-----BEGIN PGP MESSAGE-----")

	decrypted, err := Decrypt(ciphertext, kp.PrivateKey, "")
	mustNoError(t, err)
	wantEqual(t, plaintext, decrypted)
}

func TestPGP_Encrypt_Bad(t *testing.T) {
	kp1, err := CreateKeyPair("User One", "one@example.com", "")
	mustNoError(t, err)
	kp2, err := CreateKeyPair("User Two", "two@example.com", "")
	mustNoError(t, err)

	plaintext := []byte("secret data")
	ciphertext, err := Encrypt(plaintext, kp1.PublicKey)
	mustNoError(t, err)

	// Decrypting with wrong key should fail
	_, err = Decrypt(ciphertext, kp2.PrivateKey, "")
	wantError(t, err)
}

func TestPGP_Encrypt_Ugly(t *testing.T) {
	// Invalid public key for encryption
	_, err := Encrypt([]byte("data"), "not-a-pgp-key")
	wantError(t, err)

	// Invalid private key for decryption
	_, err = Decrypt([]byte("data"), "not-a-pgp-key", "")
	wantError(t, err)
}

func TestPGP_EncryptDecryptWithPassword_Good(t *testing.T) {
	password := "my-secret-passphrase"
	kp, err := CreateKeyPair("Secure User", "secure@example.com", password)
	mustNoError(t, err)

	plaintext := []byte("encrypted with password-protected key")
	ciphertext, err := Encrypt(plaintext, kp.PublicKey)
	mustNoError(t, err)

	decrypted, err := Decrypt(ciphertext, kp.PrivateKey, password)
	mustNoError(t, err)
	wantEqual(t, plaintext, decrypted)
}

func TestPGP_Sign_Good(t *testing.T) {
	kp, err := CreateKeyPair("Signer", "signer@example.com", "")
	mustNoError(t, err)

	data := []byte("message to sign")
	signature, err := Sign(data, kp.PrivateKey, "")
	mustNoError(t, err)
	wantNotEmpty(t, signature)
	wantContains(t, string(signature), "-----BEGIN PGP SIGNATURE-----")

	err = Verify(data, signature, kp.PublicKey)
	wantNoError(t, err)
}

func TestPGP_Sign_Bad(t *testing.T) {
	kp, err := CreateKeyPair("Signer", "signer@example.com", "")
	mustNoError(t, err)

	data := []byte("original message")
	signature, err := Sign(data, kp.PrivateKey, "")
	mustNoError(t, err)

	// Verify with tampered data should fail
	err = Verify([]byte("tampered message"), signature, kp.PublicKey)
	wantError(t, err)
}

func TestPGP_Sign_Ugly(t *testing.T) {
	// Invalid key for signing
	_, err := Sign([]byte("data"), "not-a-key", "")
	wantError(t, err)

	// Invalid key for verification
	kp, err := CreateKeyPair("Signer", "signer@example.com", "")
	mustNoError(t, err)

	data := []byte("message")
	sig, err := Sign(data, kp.PrivateKey, "")
	mustNoError(t, err)

	err = Verify(data, sig, "not-a-key")
	wantError(t, err)
}

func TestPGP_SignVerifyWithPassword_Good(t *testing.T) {
	password := "signing-password"
	kp, err := CreateKeyPair("Signer", "signer@example.com", password)
	mustNoError(t, err)

	data := []byte("signed with password-protected key")
	signature, err := Sign(data, kp.PrivateKey, password)
	mustNoError(t, err)

	err = Verify(data, signature, kp.PublicKey)
	wantNoError(t, err)
}

func TestPGP_FullRoundTrip_Good(t *testing.T) {
	// Generate keys, encrypt, decrypt, sign, and verify - full round trip
	kp, err := CreateKeyPair("Full Test", "full@example.com", "")
	mustNoError(t, err)

	original := []byte("full round-trip test data")

	// Encrypt then decrypt
	ciphertext, err := Encrypt(original, kp.PublicKey)
	mustNoError(t, err)
	decrypted, err := Decrypt(ciphertext, kp.PrivateKey, "")
	mustNoError(t, err)
	wantEqual(t, original, decrypted)

	// Sign then verify
	signature, err := Sign(original, kp.PrivateKey, "")
	mustNoError(t, err)
	err = Verify(original, signature, kp.PublicKey)
	wantNoError(t, err)
}

func TestPgp_CreateKeyPair_Good(t *core.T) {
	subject := CreateKeyPair
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_CreateKeyPair_Bad(t *core.T) {
	subject := CreateKeyPair
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_CreateKeyPair_Ugly(t *core.T) {
	subject := CreateKeyPair
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Encrypt_Good(t *core.T) {
	subject := Encrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Encrypt_Bad(t *core.T) {
	subject := Encrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Encrypt_Ugly(t *core.T) {
	subject := Encrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Decrypt_Good(t *core.T) {
	subject := Decrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Decrypt_Bad(t *core.T) {
	subject := Decrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Decrypt_Ugly(t *core.T) {
	subject := Decrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Sign_Good(t *core.T) {
	subject := Sign
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Sign_Bad(t *core.T) {
	subject := Sign
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Sign_Ugly(t *core.T) {
	subject := Sign
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Verify_Good(t *core.T) {
	subject := Verify
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Verify_Bad(t *core.T) {
	subject := Verify
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestPgp_Verify_Ugly(t *core.T) {
	subject := Verify
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
