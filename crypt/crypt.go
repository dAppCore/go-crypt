package crypt

import (
	coreerr "dappco.re/go/core/log"
)

// Encrypt encrypts data with a passphrase using ChaCha20-Poly1305.
// A random salt is generated and prepended to the output.
// Format: salt (16 bytes) + nonce (24 bytes) + ciphertext.
// Usage: call Encrypt(...) during the package's normal workflow.
func Encrypt(plaintext, passphrase []byte) ([]byte, error) {
	salt, err := generateSalt(argon2SaltLen)
	if err != nil {
		return nil, coreerr.E("crypt.Encrypt", "failed to generate salt", err)
	}

	key := DeriveKey(passphrase, salt, argon2KeyLen)

	encrypted, err := ChaCha20Encrypt(plaintext, key)
	if err != nil {
		return nil, coreerr.E("crypt.Encrypt", "failed to encrypt", err)
	}

	// Prepend salt to the encrypted data (which already has nonce prepended)
	result := make([]byte, 0, len(salt)+len(encrypted))
	result = append(result, salt...)
	result = append(result, encrypted...)
	return result, nil
}

// Decrypt decrypts data encrypted with Encrypt.
// Expects format: salt (16 bytes) + nonce (24 bytes) + ciphertext.
// Usage: call Decrypt(...) during the package's normal workflow.
func Decrypt(ciphertext, passphrase []byte) ([]byte, error) {
	if len(ciphertext) < argon2SaltLen {
		return nil, coreerr.E("crypt.Decrypt", "ciphertext too short", nil)
	}

	salt := ciphertext[:argon2SaltLen]
	encrypted := ciphertext[argon2SaltLen:]

	key := DeriveKey(passphrase, salt, argon2KeyLen)

	plaintext, err := ChaCha20Decrypt(encrypted, key)
	if err != nil {
		return nil, coreerr.E("crypt.Decrypt", "failed to decrypt", err)
	}

	return plaintext, nil
}

// EncryptAES encrypts data using AES-256-GCM with a passphrase.
// A random salt is generated and prepended to the output.
// Format: salt (16 bytes) + nonce (12 bytes) + ciphertext.
// Usage: call EncryptAES(...) during the package's normal workflow.
func EncryptAES(plaintext, passphrase []byte) ([]byte, error) {
	salt, err := generateSalt(argon2SaltLen)
	if err != nil {
		return nil, coreerr.E("crypt.EncryptAES", "failed to generate salt", err)
	}

	key := DeriveKey(passphrase, salt, argon2KeyLen)

	encrypted, err := AESGCMEncrypt(plaintext, key)
	if err != nil {
		return nil, coreerr.E("crypt.EncryptAES", "failed to encrypt", err)
	}

	result := make([]byte, 0, len(salt)+len(encrypted))
	result = append(result, salt...)
	result = append(result, encrypted...)
	return result, nil
}

// DecryptAES decrypts data encrypted with EncryptAES.
// Expects format: salt (16 bytes) + nonce (12 bytes) + ciphertext.
// Usage: call DecryptAES(...) during the package's normal workflow.
func DecryptAES(ciphertext, passphrase []byte) ([]byte, error) {
	if len(ciphertext) < argon2SaltLen {
		return nil, coreerr.E("crypt.DecryptAES", "ciphertext too short", nil)
	}

	salt := ciphertext[:argon2SaltLen]
	encrypted := ciphertext[argon2SaltLen:]

	key := DeriveKey(passphrase, salt, argon2KeyLen)

	plaintext, err := AESGCMDecrypt(encrypted, key)
	if err != nil {
		return nil, coreerr.E("crypt.DecryptAES", "failed to decrypt", err)
	}

	return plaintext, nil
}
