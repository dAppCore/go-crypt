package crypt

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// BenchmarkArgon2Derive measures Argon2id key derivation (32-byte key).
func BenchmarkArgon2Derive(b *testing.B) {
	passphrase := []byte("benchmark-passphrase")
	salt := make([]byte, argon2SaltLen)
	_, _ = rand.Read(salt)

	b.ResetTimer()
	for range b.N {
		_ = DeriveKey(passphrase, salt, argon2KeyLen)
	}
}

// BenchmarkChaCha20Encrypt_1KB measures ChaCha20-Poly1305 encryption of 1KB.
func BenchmarkChaCha20Encrypt_1KB(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	plaintext := make([]byte, 1024)
	_, _ = rand.Read(plaintext)

	b.ResetTimer()
	b.SetBytes(1024)
	for range b.N {
		_, _ = ChaCha20Encrypt(plaintext, key)
	}
}

// BenchmarkChaCha20Encrypt_1MB measures ChaCha20-Poly1305 encryption of 1MB.
func BenchmarkChaCha20Encrypt_1MB(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	plaintext := make([]byte, 1024*1024)
	_, _ = rand.Read(plaintext)

	b.ResetTimer()
	b.SetBytes(1024 * 1024)
	for range b.N {
		_, _ = ChaCha20Encrypt(plaintext, key)
	}
}

// BenchmarkAESGCMEncrypt_1KB measures AES-256-GCM encryption of 1KB.
func BenchmarkAESGCMEncrypt_1KB(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	plaintext := make([]byte, 1024)
	_, _ = rand.Read(plaintext)

	b.ResetTimer()
	b.SetBytes(1024)
	for range b.N {
		_, _ = AESGCMEncrypt(plaintext, key)
	}
}

// BenchmarkAESGCMEncrypt_1MB measures AES-256-GCM encryption of 1MB.
func BenchmarkAESGCMEncrypt_1MB(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	plaintext := make([]byte, 1024*1024)
	_, _ = rand.Read(plaintext)

	b.ResetTimer()
	b.SetBytes(1024 * 1024)
	for range b.N {
		_, _ = AESGCMEncrypt(plaintext, key)
	}
}

// BenchmarkHMACSHA256_1KB measures HMAC-SHA256 of a 1KB message.
func BenchmarkHMACSHA256_1KB(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	message := make([]byte, 1024)
	_, _ = rand.Read(message)

	b.ResetTimer()
	b.SetBytes(1024)
	for range b.N {
		_ = HMACSHA256(message, key)
	}
}

// BenchmarkVerifyHMACSHA256 measures HMAC verification (constant-time compare).
func BenchmarkVerifyHMACSHA256(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	message := make([]byte, 1024)
	_, _ = rand.Read(message)
	mac := HMACSHA256(message, key)

	b.ResetTimer()
	for range b.N {
		_ = VerifyHMAC(message, key, mac, sha256.New)
	}
}
