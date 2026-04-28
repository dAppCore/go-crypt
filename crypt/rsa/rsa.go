package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"

	core "dappco.re/go"
	coreerr "dappco.re/go/log"
)

// Service provides RSA functionality.
// Usage: use Service with the other exported helpers in this package.
type Service struct{}

// NewService creates and returns a new Service instance for performing RSA-related operations.
// Usage: call NewService(...) to create a ready-to-use value.
func NewService() *Service {
	return &Service{}
}

// GenerateKeyPair creates a new RSA key pair.
// Usage: call GenerateKeyPair(...) during the package's normal workflow.
func (s *Service) GenerateKeyPair(bits int) (publicKey, privateKey []byte, err error) {
	const op = "rsa.GenerateKeyPair"

	if bits < 2048 {
		return nil, nil, coreerr.E(op, core.Sprintf("key size too small: %d (minimum 2048)", bits), nil)
	}
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, coreerr.E(op, "failed to generate private key", err)
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, coreerr.E(op, "failed to marshal public key", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return pubKeyPEM, privKeyPEM, nil
}

// Encrypt encrypts data with a public key.
// Usage: call Encrypt(...) during the package's normal workflow.
func (s *Service) Encrypt(publicKey, data, label []byte) ([]byte, error) {
	const op = "rsa.Encrypt"

	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, coreerr.E(op, "failed to decode public key", nil)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, coreerr.E(op, "failed to parse public key", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, coreerr.E(op, "not an RSA public key", nil)
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, data, label)
	if err != nil {
		return nil, coreerr.E(op, "failed to encrypt data", err)
	}

	return ciphertext, nil
}

// Decrypt decrypts data with a private key.
// Usage: call Decrypt(...) during the package's normal workflow.
func (s *Service) Decrypt(privateKey, ciphertext, label []byte) ([]byte, error) {
	const op = "rsa.Decrypt"

	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, coreerr.E(op, "failed to decode private key", nil)
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, coreerr.E(op, "failed to parse private key", err)
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, label)
	if err != nil {
		return nil, coreerr.E(op, "failed to decrypt data", err)
	}

	return plaintext, nil
}
