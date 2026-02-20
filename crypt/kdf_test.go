package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveKey_Good(t *testing.T) {
	passphrase := []byte("test-passphrase")
	salt := []byte("1234567890123456") // 16 bytes

	key1 := DeriveKey(passphrase, salt, 32)
	key2 := DeriveKey(passphrase, salt, 32)

	assert.Len(t, key1, 32)
	assert.Equal(t, key1, key2, "same inputs should produce same output")

	// Different passphrase should produce different key
	key3 := DeriveKey([]byte("different-passphrase"), salt, 32)
	assert.NotEqual(t, key1, key3)
}

func TestDeriveKeyScrypt_Good(t *testing.T) {
	passphrase := []byte("test-passphrase")
	salt := []byte("1234567890123456")

	key, err := DeriveKeyScrypt(passphrase, salt, 32)
	assert.NoError(t, err)
	assert.Len(t, key, 32)

	// Deterministic
	key2, err := DeriveKeyScrypt(passphrase, salt, 32)
	assert.NoError(t, err)
	assert.Equal(t, key, key2)
}

func TestHKDF_Good(t *testing.T) {
	secret := []byte("input-keying-material")
	salt := []byte("optional-salt")
	info := []byte("context-info")

	key1, err := HKDF(secret, salt, info, 32)
	assert.NoError(t, err)
	assert.Len(t, key1, 32)

	// Deterministic
	key2, err := HKDF(secret, salt, info, 32)
	assert.NoError(t, err)
	assert.Equal(t, key1, key2)

	// Different info should produce different key
	key3, err := HKDF(secret, salt, []byte("different-info"), 32)
	assert.NoError(t, err)
	assert.NotEqual(t, key1, key3)
}

// --- Phase 0 Additions ---

// TestKeyDerivationDeterminism_Good verifies same passphrase + salt always yields same key.
func TestKeyDerivationDeterminism_Good(t *testing.T) {
	passphrase := []byte("determinism-test-passphrase")
	salt := []byte("1234567890123456") // 16 bytes

	key1 := DeriveKey(passphrase, salt, 32)
	key2 := DeriveKey(passphrase, salt, 32)
	key3 := DeriveKey(passphrase, salt, 32)

	assert.Equal(t, key1, key2, "same inputs must produce identical keys")
	assert.Equal(t, key2, key3, "derivation must be fully deterministic")

	// Different salt must produce different key
	differentSalt := []byte("6543210987654321")
	key4 := DeriveKey(passphrase, differentSalt, 32)
	assert.NotEqual(t, key1, key4, "different salt must produce different key")

	// scrypt determinism
	scryptKey1, err := DeriveKeyScrypt(passphrase, salt, 32)
	assert.NoError(t, err)
	scryptKey2, err := DeriveKeyScrypt(passphrase, salt, 32)
	assert.NoError(t, err)
	assert.Equal(t, scryptKey1, scryptKey2, "scrypt must also be deterministic")
}

// TestHKDFDifferentInfoStrings_Good verifies different info strings produce different keys.
func TestHKDFDifferentInfoStrings_Good(t *testing.T) {
	secret := []byte("shared-secret-material")
	salt := []byte("common-salt")

	infoStrings := []string{
		"encryption",
		"authentication",
		"signing",
		"key-derivation",
		"",
	}

	keys := make(map[string][]byte, len(infoStrings))
	for _, info := range infoStrings {
		key, err := HKDF(secret, salt, []byte(info), 32)
		assert.NoError(t, err)
		assert.Len(t, key, 32)
		keys[info] = key
	}

	// Verify all keys are unique
	for i, info1 := range infoStrings {
		for j, info2 := range infoStrings {
			if i != j {
				assert.NotEqual(t, keys[info1], keys[info2],
					"HKDF with info %q and %q must produce different keys", info1, info2)
			}
		}
	}
}

// TestHKDFNilSalt_Good verifies HKDF works with nil salt.
func TestHKDFNilSalt_Good(t *testing.T) {
	secret := []byte("input-keying-material")
	info := []byte("context")

	key, err := HKDF(secret, nil, info, 32)
	assert.NoError(t, err)
	assert.Len(t, key, 32)
}
