package chachapoly

import (
	enchantrixchacha "forge.lthn.ai/Snider/Enchantrix/pkg/crypt/std/chachapoly"
)

// Encrypt encrypts data using ChaCha20-Poly1305.
// Usage: call Encrypt(...) during the package's normal workflow.
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	return enchantrixchacha.Encrypt(plaintext, key)
}

// Decrypt decrypts data using ChaCha20-Poly1305.
// Usage: call Decrypt(...) during the package's normal workflow.
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	return enchantrixchacha.Decrypt(ciphertext, key)
}
