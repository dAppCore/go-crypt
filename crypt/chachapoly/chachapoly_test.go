package chachapoly

import (
	"crypto/rand"
	"testing"

	core "dappco.re/go/core"
)

// mockReader is a reader that returns an error.
type mockReader struct{}

func (r *mockReader) Read(p []byte) (n int, err error) {
	return 0, core.NewError("read error")
}

func TestChachapoly_EncryptDecrypt_Good(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 1
	}

	plaintext := []byte("Hello, world!")
	ciphertext, err := Encrypt(plaintext, key)
	wantNoError(t, err)

	decrypted, err := Decrypt(ciphertext, key)
	wantNoError(t, err)

	wantEqual(t, plaintext, decrypted)
}

func TestChachapoly_Encrypt_Bad_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Wrong size
	plaintext := []byte("test")
	_, err := Encrypt(plaintext, key)
	wantError(t, err)
}

func TestChachapoly_Decrypt_Bad_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1 // Different key

	plaintext := []byte("secret")
	ciphertext, err := Encrypt(plaintext, key1)
	wantNoError(t, err)

	_, err = Decrypt(ciphertext, key2)
	wantError(t, err) // Should fail authentication
}

func TestChachapoly_Decrypt_Bad_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("secret")
	ciphertext, err := Encrypt(plaintext, key)
	wantNoError(t, err)

	// Tamper with the ciphertext
	ciphertext[0] ^= 0xff

	_, err = Decrypt(ciphertext, key)
	wantError(t, err)
}

func TestChachapoly_Encrypt_Good_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("")
	ciphertext, err := Encrypt(plaintext, key)
	wantNoError(t, err)

	decrypted, err := Decrypt(ciphertext, key)
	wantNoError(t, err)

	wantEqual(t, plaintext, decrypted)
}

func TestChachapoly_Decrypt_Bad_ShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	shortCiphertext := []byte("short")

	_, err := Decrypt(shortCiphertext, key)
	wantError(t, err)
	wantContains(t, err.Error(), "too short")
}

func TestChachapoly_CiphertextDiffersFromPlaintext_Good(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("Hello, world!")
	ciphertext, err := Encrypt(plaintext, key)
	wantNoError(t, err)
	wantNotEqual(t, plaintext, ciphertext)
}

func TestChachapoly_Encrypt_Bad_NonceError(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("test")

	// Replace the rand.Reader with our mock reader
	oldReader := rand.Reader
	rand.Reader = &mockReader{}
	defer func() { rand.Reader = oldReader }()

	_, err := Encrypt(plaintext, key)
	wantError(t, err)
}

func TestChachapoly_Decrypt_Bad_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Wrong size
	ciphertext := []byte("test")
	_, err := Decrypt(ciphertext, key)
	wantError(t, err)
}
