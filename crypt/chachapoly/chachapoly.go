package chachapoly

import (
	"crypto/rand"
	"io"

	core "dappco.re/go/core"
	coreerr "dappco.re/go/core/log"

	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt encrypts data using ChaCha20-Poly1305.
// Usage: call Encrypt(...) during the package's normal workflow.
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using ChaCha20-Poly1305.
// Usage: call Decrypt(...) during the package's normal workflow.
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	minLen := aead.NonceSize() + aead.Overhead()
	if len(ciphertext) < minLen {
		return nil, coreerr.E("chachapoly.Decrypt", core.Sprintf("ciphertext too short: got %d bytes, need at least %d bytes", len(ciphertext), minLen), nil)
	}

	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if len(decrypted) == 0 {
		return []byte{}, nil
	}

	return decrypted, nil
}
