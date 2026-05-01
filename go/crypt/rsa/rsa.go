package rsa

import (
	enchantrixrsa "forge.lthn.ai/Snider/Enchantrix/pkg/crypt/std/rsa"
)

// Service provides RSA functionality.
// Usage: use Service with the other exported helpers in this package.
type Service struct {
	inner *enchantrixrsa.Service
}

// NewService creates and returns a new Service instance for performing RSA-related operations.
// Usage: call NewService(...) to create a ready-to-use value.
func NewService() *Service {
	return &Service{inner: enchantrixrsa.NewService()}
}

// GenerateKeyPair creates a new RSA key pair.
// Usage: call GenerateKeyPair(...) during the package's normal workflow.
func (s *Service) GenerateKeyPair(bits int) (publicKey, privateKey []byte, err error) {
	return s.enchantrix().GenerateKeyPair(bits)
}

// Encrypt encrypts data with a public key.
// Usage: call Encrypt(...) during the package's normal workflow.
func (s *Service) Encrypt(publicKey, data, label []byte) ([]byte, error) {
	return s.enchantrix().Encrypt(publicKey, data, label)
}

// Decrypt decrypts data with a private key.
// Usage: call Decrypt(...) during the package's normal workflow.
func (s *Service) Decrypt(privateKey, ciphertext, label []byte) ([]byte, error) {
	return s.enchantrix().Decrypt(privateKey, ciphertext, label)
}

func (s *Service) enchantrix() *enchantrixrsa.Service {
	if s != nil && s.inner != nil {
		return s.inner
	}
	return enchantrixrsa.NewService()
}
