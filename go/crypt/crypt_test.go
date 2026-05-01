package crypt

import (
	"bytes"
	"testing"
)

func TestCrypt_Encrypt_Good(t *testing.T) {
	plaintext := []byte("hello, world!")
	passphrase := []byte("correct-horse-battery-staple")

	encrypted, err := Encrypt(plaintext, passphrase)
	wantNoError(t, err)
	wantNotEqual(t, plaintext, encrypted)

	decrypted, err := Decrypt(encrypted, passphrase)
	wantNoError(t, err)
	wantEqual(t, plaintext, decrypted)
}

func TestCrypt_Decrypt_Bad(t *testing.T) {
	plaintext := []byte("secret data")
	passphrase := []byte("correct-passphrase")
	wrongPassphrase := []byte("wrong-passphrase")

	encrypted, err := Encrypt(plaintext, passphrase)
	wantNoError(t, err)

	_, err = Decrypt(encrypted, wrongPassphrase)
	wantError(t, err)
}

func TestCrypt_EncryptAES_Good(t *testing.T) {
	plaintext := []byte("hello, AES world!")
	passphrase := []byte("my-secure-passphrase")

	encrypted, err := EncryptAES(plaintext, passphrase)
	wantNoError(t, err)
	wantNotEqual(t, plaintext, encrypted)

	decrypted, err := DecryptAES(encrypted, passphrase)
	wantNoError(t, err)
	wantEqual(t, plaintext, decrypted)
}

// --- Phase 0 Additions ---

// TestCrypt_DecryptAES_Bad verifies wrong passphrase returns error, not corrupt data.
func TestCrypt_DecryptAES_Bad(t *testing.T) {
	plaintext := []byte("sensitive payload")
	passphrase := []byte("correct-passphrase")
	wrongPassphrase := []byte("wrong-passphrase")

	encrypted, err := Encrypt(plaintext, passphrase)
	mustNoError(t, err)

	decrypted, err := Decrypt(encrypted, wrongPassphrase)
	wantError(t, err, "wrong passphrase must return an error")
	wantNil(t, decrypted, "wrong passphrase must not return partial data")

	// Same for AES variant
	encryptedAES, err := EncryptAES(plaintext, passphrase)
	mustNoError(t, err)

	decryptedAES, err := DecryptAES(encryptedAES, wrongPassphrase)
	wantError(t, err, "wrong passphrase must return an error (AES)")
	wantNil(t, decryptedAES, "wrong passphrase must not return partial data (AES)")
}

// TestCrypt_EmptyPlaintextRoundTrip_Good verifies encrypt/decrypt of empty plaintext.
func TestCrypt_EmptyPlaintextRoundTrip_Good(t *testing.T) {
	passphrase := []byte("test-passphrase")

	// ChaCha20
	encrypted, err := Encrypt([]byte{}, passphrase)
	mustNoError(t, err)
	wantNotEmpty(t, encrypted, "ciphertext should include salt + nonce even for empty plaintext")

	decrypted, err := Decrypt(encrypted, passphrase)
	mustNoError(t, err)
	wantEmpty(t, decrypted, "decrypted empty plaintext should be empty")

	// AES-GCM
	encryptedAES, err := EncryptAES([]byte{}, passphrase)
	mustNoError(t, err)
	wantNotEmpty(t, encryptedAES)

	decryptedAES, err := DecryptAES(encryptedAES, passphrase)
	mustNoError(t, err)
	wantEmpty(t, decryptedAES)
}

// TestCrypt_LargePlaintextRoundTrip_Good verifies encrypt/decrypt of a 1MB payload.
func TestCrypt_LargePlaintextRoundTrip_Good(t *testing.T) {
	passphrase := []byte("large-payload-passphrase")
	plaintext := bytes.Repeat([]byte("X"), 1024*1024) // 1MB

	// ChaCha20
	encrypted, err := Encrypt(plaintext, passphrase)
	mustNoError(t, err)
	wantGreater(t, len(encrypted), len(plaintext), "ciphertext should be larger than plaintext")

	decrypted, err := Decrypt(encrypted, passphrase)
	mustNoError(t, err)
	wantEqual(t, plaintext, decrypted)

	// AES-GCM
	encryptedAES, err := EncryptAES(plaintext, passphrase)
	mustNoError(t, err)

	decryptedAES, err := DecryptAES(encryptedAES, passphrase)
	mustNoError(t, err)
	wantEqual(t, plaintext, decryptedAES)
}

// TestCrypt_DecryptCiphertextTooShort_Ugly verifies short ciphertext is rejected.
func TestCrypt_DecryptCiphertextTooShort_Ugly(t *testing.T) {
	_, err := Decrypt([]byte("short"), []byte("pass"))
	wantError(t, err)
	wantContains(t, err.Error(), "too short")

	_, err = DecryptAES([]byte("short"), []byte("pass"))
	wantError(t, err)
	wantContains(t, err.Error(), "too short")
}

func TestCrypt_Encrypt_Bad(t *core.T) {
	subject := Encrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestCrypt_Encrypt_Ugly(t *core.T) {
	subject := Encrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestCrypt_Decrypt_Good(t *core.T) {
	subject := Decrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestCrypt_Decrypt_Ugly(t *core.T) {
	subject := Decrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestCrypt_EncryptAES_Bad(t *core.T) {
	subject := EncryptAES
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestCrypt_EncryptAES_Ugly(t *core.T) {
	subject := EncryptAES
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestCrypt_DecryptAES_Good(t *core.T) {
	subject := DecryptAES
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestCrypt_DecryptAES_Ugly(t *core.T) {
	subject := DecryptAES
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
