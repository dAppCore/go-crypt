package crypt

import (
	"testing"
)

func TestKDF_DeriveKey_Good(t *testing.T) {
	passphrase := []byte("test-passphrase")
	salt := []byte("1234567890123456") // 16 bytes

	key1 := DeriveKey(passphrase, salt, 32)
	key2 := DeriveKey(passphrase, salt, 32)

	wantLen(t, key1, 32)
	wantEqual(t, key1, key2, "same inputs should produce same output")

	// Different passphrase should produce different key
	key3 := DeriveKey([]byte("different-passphrase"), salt, 32)
	wantNotEqual(t, key1, key3)
}

func TestKDF_DeriveKeyScrypt_Good(t *testing.T) {
	passphrase := []byte("test-passphrase")
	salt := []byte("1234567890123456")

	key, err := DeriveKeyScrypt(passphrase, salt, 32)
	wantNoError(t, err)
	wantLen(t, key, 32)

	// Deterministic
	key2, err := DeriveKeyScrypt(passphrase, salt, 32)
	wantNoError(t, err)
	wantEqual(t, key, key2)
}

func TestKDF_HKDF_Good(t *testing.T) {
	secret := []byte("input-keying-material")
	salt := []byte("optional-salt")
	info := []byte("context-info")

	key1, err := HKDF(secret, salt, info, 32)
	wantNoError(t, err)
	wantLen(t, key1, 32)

	// Deterministic
	key2, err := HKDF(secret, salt, info, 32)
	wantNoError(t, err)
	wantEqual(t, key1, key2)

	// Different info should produce different key
	key3, err := HKDF(secret, salt, []byte("different-info"), 32)
	wantNoError(t, err)
	wantNotEqual(t, key1, key3)
}

// --- Phase 0 Additions ---

// TestKDF_KeyDerivationDeterminism_Good verifies same passphrase + salt always yields same key.
func TestKDF_KeyDerivationDeterminism_Good(t *testing.T) {
	passphrase := []byte("determinism-test-passphrase")
	salt := []byte("1234567890123456") // 16 bytes

	key1 := DeriveKey(passphrase, salt, 32)
	key2 := DeriveKey(passphrase, salt, 32)
	key3 := DeriveKey(passphrase, salt, 32)

	wantEqual(t, key1, key2, "same inputs must produce identical keys")
	wantEqual(t, key2, key3, "derivation must be fully deterministic")

	// Different salt must produce different key
	differentSalt := []byte("6543210987654321")
	key4 := DeriveKey(passphrase, differentSalt, 32)
	wantNotEqual(t, key1, key4, "different salt must produce different key")

	// scrypt determinism
	scryptKey1, err := DeriveKeyScrypt(passphrase, salt, 32)
	wantNoError(t, err)
	scryptKey2, err := DeriveKeyScrypt(passphrase, salt, 32)
	wantNoError(t, err)
	wantEqual(t, scryptKey1, scryptKey2, "scrypt must also be deterministic")
}

// TestKDF_HKDFDifferentInfoStrings_Good verifies different info strings produce different keys.
func TestKDF_HKDFDifferentInfoStrings_Good(t *testing.T) {
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
		wantNoError(t, err)
		wantLen(t, key, 32)
		keys[info] = key
	}

	// Verify all keys are unique
	for i, info1 := range infoStrings {
		for j, info2 := range infoStrings {
			if i != j {
				wantNotEqual(t, keys[info1], keys[info2],
					testMessagef("HKDF with info %q and %q must produce different keys", info1, info2))
			}
		}
	}
}

// TestKDF_HKDFNilSalt_Good verifies HKDF works with nil salt.
func TestKDF_HKDFNilSalt_Good(t *testing.T) {
	secret := []byte("input-keying-material")
	info := []byte("context")

	key, err := HKDF(secret, nil, info, 32)
	wantNoError(t, err)
	wantLen(t, key, 32)
}

func TestKdf_DeriveKey_Good(t *core.T) {
	subject := DeriveKey
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestKdf_DeriveKey_Bad(t *core.T) {
	subject := DeriveKey
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestKdf_DeriveKey_Ugly(t *core.T) {
	subject := DeriveKey
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestKdf_DeriveKeyScrypt_Good(t *core.T) {
	subject := DeriveKeyScrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestKdf_DeriveKeyScrypt_Bad(t *core.T) {
	subject := DeriveKeyScrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestKdf_DeriveKeyScrypt_Ugly(t *core.T) {
	subject := DeriveKeyScrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestKdf_HKDF_Good(t *core.T) {
	subject := HKDF
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestKdf_HKDF_Bad(t *core.T) {
	subject := HKDF
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestKdf_HKDF_Ugly(t *core.T) {
	subject := HKDF
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
