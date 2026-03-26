package chachapoly

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockReader is a reader that returns an error.
type mockReader struct{}

func (r *mockReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestEncryptDecrypt_Good(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 1
	}

	plaintext := []byte("Hello, world!")
	ciphertext, err := Encrypt(plaintext, key)
	assert.NoError(t, err)

	decrypted, err := Decrypt(ciphertext, key)
	assert.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestEncrypt_Bad_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Wrong size
	plaintext := []byte("test")
	_, err := Encrypt(plaintext, key)
	assert.Error(t, err)
}

func TestDecrypt_Bad_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1 // Different key

	plaintext := []byte("secret")
	ciphertext, err := Encrypt(plaintext, key1)
	assert.NoError(t, err)

	_, err = Decrypt(ciphertext, key2)
	assert.Error(t, err) // Should fail authentication
}

func TestDecrypt_Bad_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("secret")
	ciphertext, err := Encrypt(plaintext, key)
	assert.NoError(t, err)

	// Tamper with the ciphertext
	ciphertext[0] ^= 0xff

	_, err = Decrypt(ciphertext, key)
	assert.Error(t, err)
}

func TestEncrypt_Good_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("")
	ciphertext, err := Encrypt(plaintext, key)
	assert.NoError(t, err)

	decrypted, err := Decrypt(ciphertext, key)
	assert.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestDecrypt_Bad_ShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	shortCiphertext := []byte("short")

	_, err := Decrypt(shortCiphertext, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestCiphertextDiffersFromPlaintext_Good(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("Hello, world!")
	ciphertext, err := Encrypt(plaintext, key)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)
}

func TestEncrypt_Bad_NonceError(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("test")

	// Replace the rand.Reader with our mock reader
	oldReader := rand.Reader
	rand.Reader = &mockReader{}
	defer func() { rand.Reader = oldReader }()

	_, err := Encrypt(plaintext, key)
	assert.Error(t, err)
}

func TestDecrypt_Bad_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Wrong size
	ciphertext := []byte("test")
	_, err := Decrypt(ciphertext, key)
	assert.Error(t, err)
}
