package crypt

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrypt_EncryptDecrypt_Good(t *testing.T) {
	plaintext := []byte("hello, world!")
	passphrase := []byte("correct-horse-battery-staple")

	encrypted, err := Encrypt(plaintext, passphrase)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, encrypted)

	decrypted, err := Decrypt(encrypted, passphrase)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestCrypt_EncryptDecrypt_Bad(t *testing.T) {
	plaintext := []byte("secret data")
	passphrase := []byte("correct-passphrase")
	wrongPassphrase := []byte("wrong-passphrase")

	encrypted, err := Encrypt(plaintext, passphrase)
	assert.NoError(t, err)

	_, err = Decrypt(encrypted, wrongPassphrase)
	assert.Error(t, err)
}

func TestCrypt_EncryptDecryptAES_Good(t *testing.T) {
	plaintext := []byte("hello, AES world!")
	passphrase := []byte("my-secure-passphrase")

	encrypted, err := EncryptAES(plaintext, passphrase)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, encrypted)

	decrypted, err := DecryptAES(encrypted, passphrase)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// --- Phase 0 Additions ---

// TestCrypt_WrongPassphraseDecrypt_Bad verifies wrong passphrase returns error, not corrupt data.
func TestCrypt_WrongPassphraseDecrypt_Bad(t *testing.T) {
	plaintext := []byte("sensitive payload")
	passphrase := []byte("correct-passphrase")
	wrongPassphrase := []byte("wrong-passphrase")

	encrypted, err := Encrypt(plaintext, passphrase)
	require.NoError(t, err)

	decrypted, err := Decrypt(encrypted, wrongPassphrase)
	assert.Error(t, err, "wrong passphrase must return an error")
	assert.Nil(t, decrypted, "wrong passphrase must not return partial data")

	// Same for AES variant
	encryptedAES, err := EncryptAES(plaintext, passphrase)
	require.NoError(t, err)

	decryptedAES, err := DecryptAES(encryptedAES, wrongPassphrase)
	assert.Error(t, err, "wrong passphrase must return an error (AES)")
	assert.Nil(t, decryptedAES, "wrong passphrase must not return partial data (AES)")
}

// TestCrypt_EmptyPlaintextRoundTrip_Good verifies encrypt/decrypt of empty plaintext.
func TestCrypt_EmptyPlaintextRoundTrip_Good(t *testing.T) {
	passphrase := []byte("test-passphrase")

	// ChaCha20
	encrypted, err := Encrypt([]byte{}, passphrase)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted, "ciphertext should include salt + nonce even for empty plaintext")

	decrypted, err := Decrypt(encrypted, passphrase)
	require.NoError(t, err)
	assert.Empty(t, decrypted, "decrypted empty plaintext should be empty")

	// AES-GCM
	encryptedAES, err := EncryptAES([]byte{}, passphrase)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedAES)

	decryptedAES, err := DecryptAES(encryptedAES, passphrase)
	require.NoError(t, err)
	assert.Empty(t, decryptedAES)
}

// TestCrypt_LargePlaintextRoundTrip_Good verifies encrypt/decrypt of a 1MB payload.
func TestCrypt_LargePlaintextRoundTrip_Good(t *testing.T) {
	passphrase := []byte("large-payload-passphrase")
	plaintext := bytes.Repeat([]byte("X"), 1024*1024) // 1MB

	// ChaCha20
	encrypted, err := Encrypt(plaintext, passphrase)
	require.NoError(t, err)
	assert.Greater(t, len(encrypted), len(plaintext), "ciphertext should be larger than plaintext")

	decrypted, err := Decrypt(encrypted, passphrase)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// AES-GCM
	encryptedAES, err := EncryptAES(plaintext, passphrase)
	require.NoError(t, err)

	decryptedAES, err := DecryptAES(encryptedAES, passphrase)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decryptedAES)
}

// TestCrypt_DecryptCiphertextTooShort_Ugly verifies short ciphertext is rejected.
func TestCrypt_DecryptCiphertextTooShort_Ugly(t *testing.T) {
	_, err := Decrypt([]byte("short"), []byte("pass"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")

	_, err = DecryptAES([]byte("short"), []byte("pass"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}
