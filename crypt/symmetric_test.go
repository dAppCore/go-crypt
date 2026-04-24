package crypt

import (
	// Note: intrinsic crypto primitive -- no core.* equivalent (go-crypt implements core crypto; cannot self-depend).
	"crypto/rand"
	"testing"
)

func TestSymmetric_ChaCha20_Good(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	wantNoError(t, err)

	plaintext := []byte("ChaCha20-Poly1305 test data")

	encrypted, err := ChaCha20Encrypt(plaintext, key)
	wantNoError(t, err)
	wantNotEqual(t, plaintext, encrypted)

	decrypted, err := ChaCha20Decrypt(encrypted, key)
	wantNoError(t, err)
	wantEqual(t, plaintext, decrypted)
}

func TestSymmetric_ChaCha20_Bad(t *testing.T) {
	key := make([]byte, 32)
	wrongKey := make([]byte, 32)
	_, _ = rand.Read(key)
	_, _ = rand.Read(wrongKey)

	plaintext := []byte("secret message")

	encrypted, err := ChaCha20Encrypt(plaintext, key)
	wantNoError(t, err)

	_, err = ChaCha20Decrypt(encrypted, wrongKey)
	wantError(t, err)
}

func TestSymmetric_AESGCM_Good(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	wantNoError(t, err)

	plaintext := []byte("AES-256-GCM test data")

	encrypted, err := AESGCMEncrypt(plaintext, key)
	wantNoError(t, err)
	wantNotEqual(t, plaintext, encrypted)

	decrypted, err := AESGCMDecrypt(encrypted, key)
	wantNoError(t, err)
	wantEqual(t, plaintext, decrypted)
}

// --- Phase 0 Additions ---

// TestSymmetric_AESGCM_Bad_WrongKey verifies wrong key returns error, not corrupt data.
func TestSymmetric_AESGCM_Bad_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	wrongKey := make([]byte, 32)
	_, _ = rand.Read(key)
	_, _ = rand.Read(wrongKey)

	plaintext := []byte("secret data for AES")
	encrypted, err := AESGCMEncrypt(plaintext, key)
	wantNoError(t, err)

	decrypted, err := AESGCMDecrypt(encrypted, wrongKey)
	wantError(t, err, "wrong key must return error")
	wantNil(t, decrypted, "wrong key must not return partial data")
}

// TestSymmetric_ChaCha20EmptyPlaintext_Good verifies empty plaintext round-trip at low level.
func TestSymmetric_ChaCha20EmptyPlaintext_Good(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	wantNoError(t, err)

	encrypted, err := ChaCha20Encrypt([]byte{}, key)
	wantNoError(t, err)
	wantNotEmpty(t, encrypted, "ciphertext should include nonce + auth tag")

	decrypted, err := ChaCha20Decrypt(encrypted, key)
	wantNoError(t, err)
	wantEmpty(t, decrypted)
}

// TestSymmetric_AESGCMEmptyPlaintext_Good verifies empty plaintext round-trip at low level.
func TestSymmetric_AESGCMEmptyPlaintext_Good(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	wantNoError(t, err)

	encrypted, err := AESGCMEncrypt([]byte{}, key)
	wantNoError(t, err)
	wantNotEmpty(t, encrypted)

	decrypted, err := AESGCMDecrypt(encrypted, key)
	wantNoError(t, err)
	wantEmpty(t, decrypted)
}

// TestSymmetric_ChaCha20LargePayload_Good verifies 1MB encrypt/decrypt round-trip.
func TestSymmetric_ChaCha20LargePayload_Good(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	plaintext := make([]byte, 1024*1024) // 1MB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, err := ChaCha20Encrypt(plaintext, key)
	wantNoError(t, err)

	decrypted, err := ChaCha20Decrypt(encrypted, key)
	wantNoError(t, err)
	wantEqual(t, plaintext, decrypted)
}

// TestSymmetric_AESGCMLargePayload_Good verifies 1MB encrypt/decrypt round-trip.
func TestSymmetric_AESGCMLargePayload_Good(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	plaintext := make([]byte, 1024*1024) // 1MB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, err := AESGCMEncrypt(plaintext, key)
	wantNoError(t, err)

	decrypted, err := AESGCMDecrypt(encrypted, key)
	wantNoError(t, err)
	wantEqual(t, plaintext, decrypted)
}
