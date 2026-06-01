package rsa

import (
	"testing"
)

// TestFallback_ZeroValueService drives the enchantrix() nil-inner
// fallback: a zero-value &Service{} (no inner) must still produce a
// working backend so operations succeed.
func TestFallback_ZeroValueService(t *testing.T) {
	s := &Service{} // inner == nil -> enchantrix() returns a fresh backend
	pub, priv, err := s.GenerateKeyPair(2048)
	mustNoError(t, err, "GenerateKeyPair on a zero-value service")
	wantNotEmpty(t, pub, "public key")
	wantNotEmpty(t, priv, "private key")

	ct, err := s.Encrypt(pub, []byte("payload"), nil)
	mustNoError(t, err, "Encrypt on a zero-value service")
	pt, err := s.Decrypt(priv, ct, nil)
	mustNoError(t, err, "Decrypt on a zero-value service")
	wantEqual(t, []byte("payload"), pt, "round-trip restores payload")
}

// TestFallback_Encrypt_BadPublicKey rejects an unparsable public key.
func TestFallback_Encrypt_BadPublicKey(t *testing.T) {
	s := NewService()
	_, err := s.Encrypt([]byte("not-a-key"), []byte("data"), nil)
	wantError(t, err, "Encrypt with a malformed public key should error")
}

// TestFallback_Decrypt_BadPrivateKey rejects an unparsable private key.
func TestFallback_Decrypt_BadPrivateKey(t *testing.T) {
	s := NewService()
	_, err := s.Decrypt([]byte("not-a-key"), []byte("ciphertext"), nil)
	wantError(t, err, "Decrypt with a malformed private key should error")
}
