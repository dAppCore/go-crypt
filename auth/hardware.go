// Package auth — hardware key integration points.
//
// This file defines the HardwareKey interface for future PKCS#11 / YubiKey
// integration. No concrete implementations exist yet; this is a contract-only
// definition that allows Authenticator to be wired up with hardware-backed
// cryptographic operations.
//
// Integration points in auth.go (search for "hardwareKey"):
//   - CreateChallenge: could use HardwareKey.Decrypt instead of PGP
//   - ValidateResponse: could use HardwareKey.Sign for challenge signing
//   - Register: could use HardwareKey.GetPublicKey to store the HW public key
//   - Login: could use HardwareKey.Sign for password-less auth
package auth

// HardwareKey defines the contract for hardware-backed cryptographic operations.
// Implementations should wrap PKCS#11 tokens, YubiKeys, TPM modules, or
// similar tamper-resistant devices.
//
// All methods must be safe for concurrent use.
// Usage: implement HardwareKey and pass it to WithHardwareKey(...) to wire hardware-backed auth into New(...).
type HardwareKey interface {
	// Sign produces a cryptographic signature over the given data using the
	// hardware-stored private key. The signature format depends on the
	// underlying device (e.g. ECDSA, RSA-PSS, EdDSA).
	Sign(data []byte) ([]byte, error)

	// Decrypt decrypts ciphertext using the hardware-stored private key.
	// The ciphertext format must match what the device expects (e.g. RSA-OAEP).
	Decrypt(ciphertext []byte) ([]byte, error)

	// GetPublicKey returns the PEM or armored public key corresponding to the
	// hardware-stored private key.
	GetPublicKey() (string, error)

	// IsAvailable reports whether the hardware key device is currently
	// connected and operational. Callers should check this before attempting
	// Sign or Decrypt to provide graceful fallback behaviour.
	IsAvailable() bool
}

// WithHardwareKey configures the Authenticator to use a hardware key for
// cryptographic operations where supported. When set, the Authenticator may
// delegate signing, decryption, and public key retrieval to the hardware
// device instead of using software PGP keys.
//
// This is a forward-looking option — integration points are documented in
// auth.go but not yet wired up.
// Usage: pass WithHardwareKey(...) into New(...) to enable a HardwareKey implementation.
func WithHardwareKey(hk HardwareKey) Option {
	return func(a *Authenticator) {
		a.hardwareKey = hk
	}
}
