package rsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	core "dappco.re/go/core"
)

// mockReader is a reader that returns an error.
type mockReader struct{}

func (r *mockReader) Read(p []byte) (n int, err error) {
	return 0, core.NewError("read error")
}

func TestRSA_RSA_Good(t *testing.T) {
	s := NewService()

	// Generate a new key pair
	pubKey, privKey, err := s.GenerateKeyPair(2048)
	wantNoError(t, err)
	wantNotEmpty(t, pubKey)
	wantNotEmpty(t, privKey)

	// Encrypt and decrypt a message
	message := []byte("Hello, World!")
	ciphertext, err := s.Encrypt(pubKey, message, nil)
	wantNoError(t, err)
	plaintext, err := s.Decrypt(privKey, ciphertext, nil)
	wantNoError(t, err)
	wantEqual(t, message, plaintext)
}

func TestRSA_RSA_Bad(t *testing.T) {
	s := NewService()

	// Decrypt with wrong key
	pubKey, _, err := s.GenerateKeyPair(2048)
	wantNoError(t, err)
	_, otherPrivKey, err := s.GenerateKeyPair(2048)
	wantNoError(t, err)
	message := []byte("Hello, World!")
	ciphertext, err := s.Encrypt(pubKey, message, nil)
	wantNoError(t, err)
	_, err = s.Decrypt(otherPrivKey, ciphertext, nil)
	wantError(t, err)

	// Key size too small
	_, _, err = s.GenerateKeyPair(512)
	wantError(t, err)
}

func TestRSA_RSA_Ugly(t *testing.T) {
	s := NewService()

	// Malformed keys and messages
	_, err := s.Encrypt([]byte("not-a-key"), []byte("message"), nil)
	wantError(t, err)
	_, err = s.Decrypt([]byte("not-a-key"), []byte("message"), nil)
	wantError(t, err)
	_, err = s.Encrypt([]byte("-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ/6j/y7/r/9/z/8/f/+/v7+/v7+/v7+\nv/7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v4=\n-----END PUBLIC KEY-----"), []byte("message"), nil)
	wantError(t, err)
	_, err = s.Decrypt([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIBOQIBAAJBAL/6j/y7/r/9/z/8/f/+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nv/7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v4CAwEAAQJB\nAL/6j/y7/r/9/z/8/f/+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nv/7+/v7+/v7+/v7+/v7+/v7+/v7+/v4CgYEA/f8/vLv+v/3/P/z9//7+/v7+/v7+\nvv7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v4C\ngYEA/f8/vLv+v/3/P/z9//7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nvv7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v4CgYEA/f8/vLv+v/3/P/z9//7+/v7+\nvv7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nv/4CgYEA/f8/vLv+v/3/P/z9//7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nvv7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v4CgYEA/f8/vLv+v/3/P/z9//7+/v7+\nvv7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nv/4=\n-----END RSA PRIVATE KEY-----"), []byte("message"), nil)
	wantError(t, err)

	// Key generation with broken reader — Go 1.26+ rsa.GenerateKey may
	// recover from reader errors internally, so we only verify it doesn't panic.
	oldReader := rand.Reader
	rand.Reader = &mockReader{}
	t.Cleanup(func() { rand.Reader = oldReader })
	_, _, _ = s.GenerateKeyPair(2048)

	// Encrypt with non-RSA key
	rand.Reader = oldReader // Restore reader for this test
	ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wantNoError(t, err)
	ecdsaPubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPrivKey.PublicKey)
	wantNoError(t, err)
	ecdsaPubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: ecdsaPubKeyBytes,
	})
	_, err = s.Encrypt(ecdsaPubKeyPEM, []byte("message"), nil)
	wantError(t, err)
	rand.Reader = &mockReader{} // Set it back for the next test

	// Encrypt message too long
	rand.Reader = oldReader // Restore reader for this test
	pubKey, _, err := s.GenerateKeyPair(2048)
	wantNoError(t, err)
	message := make([]byte, 2048)
	_, err = s.Encrypt(pubKey, message, nil)
	wantError(t, err)
	rand.Reader = &mockReader{} // Set it back
}
