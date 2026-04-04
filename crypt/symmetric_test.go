package crypt

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSymmetric_ChaCha20_Good(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	assert.NoError(t, err)

	plaintext := []byte("ChaCha20-Poly1305 test data")

	encrypted, err := ChaCha20Encrypt(plaintext, key)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, encrypted)

	decrypted, err := ChaCha20Decrypt(encrypted, key)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestSymmetric_ChaCha20_Bad(t *testing.T) {
	key := make([]byte, 32)
	wrongKey := make([]byte, 32)
	_, _ = rand.Read(key)
	_, _ = rand.Read(wrongKey)

	plaintext := []byte("secret message")

	encrypted, err := ChaCha20Encrypt(plaintext, key)
	assert.NoError(t, err)

	_, err = ChaCha20Decrypt(encrypted, wrongKey)
	assert.Error(t, err)
}

func TestSymmetric_AESGCM_Good(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	assert.NoError(t, err)

	plaintext := []byte("AES-256-GCM test data")

	encrypted, err := AESGCMEncrypt(plaintext, key)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, encrypted)

	decrypted, err := AESGCMDecrypt(encrypted, key)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
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
	assert.NoError(t, err)

	decrypted, err := AESGCMDecrypt(encrypted, wrongKey)
	assert.Error(t, err, "wrong key must return error")
	assert.Nil(t, decrypted, "wrong key must not return partial data")
}

// TestSymmetric_ChaCha20EmptyPlaintext_Good verifies empty plaintext round-trip at low level.
func TestSymmetric_ChaCha20EmptyPlaintext_Good(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	assert.NoError(t, err)

	encrypted, err := ChaCha20Encrypt([]byte{}, key)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted, "ciphertext should include nonce + auth tag")

	decrypted, err := ChaCha20Decrypt(encrypted, key)
	assert.NoError(t, err)
	assert.Empty(t, decrypted)
}

// TestSymmetric_AESGCMEmptyPlaintext_Good verifies empty plaintext round-trip at low level.
func TestSymmetric_AESGCMEmptyPlaintext_Good(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	assert.NoError(t, err)

	encrypted, err := AESGCMEncrypt([]byte{}, key)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := AESGCMDecrypt(encrypted, key)
	assert.NoError(t, err)
	assert.Empty(t, decrypted)
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
	assert.NoError(t, err)

	decrypted, err := ChaCha20Decrypt(encrypted, key)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
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
	assert.NoError(t, err)

	decrypted, err := AESGCMDecrypt(encrypted, key)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
