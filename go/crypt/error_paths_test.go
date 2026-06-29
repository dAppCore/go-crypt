package crypt

import (
	"testing"
)

// --- symmetric error paths ----------------------------------------------

// TestErrorPaths_AESGCMEncrypt_BadKeyLength rejects keys that are not a
// valid AES size (16/24/32 bytes).
func TestErrorPaths_AESGCMEncrypt_BadKeyLength(t *testing.T) {
	_, err := AESGCMEncrypt([]byte("data"), []byte("short-key"))
	wantError(t, err, "AES encrypt with an invalid key length should error")
}

// TestErrorPaths_AESGCMDecrypt_BadKeyLength rejects an invalid key.
func TestErrorPaths_AESGCMDecrypt_BadKeyLength(t *testing.T) {
	_, err := AESGCMDecrypt(make([]byte, 64), []byte("short-key"))
	wantError(t, err, "AES decrypt with an invalid key length should error")
}

// TestErrorPaths_AESGCMDecrypt_TooShort rejects ciphertext shorter than
// the GCM nonce.
func TestErrorPaths_AESGCMDecrypt_TooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := AESGCMDecrypt([]byte{0x01, 0x02}, key)
	wantError(t, err, "AES decrypt of sub-nonce-length ciphertext should error")
}

// TestErrorPaths_AESGCMDecrypt_Tampered rejects a flipped tag byte.
func TestErrorPaths_AESGCMDecrypt_Tampered(t *testing.T) {
	key := make([]byte, 32)
	ct, err := AESGCMEncrypt([]byte("payload"), key)
	wantNoError(t, err, "seed encrypt")
	ct[len(ct)-1] ^= 0xFF
	_, err = AESGCMDecrypt(ct, key)
	wantError(t, err, "AES decrypt of tampered ciphertext should error")
}

// --- passphrase envelope error paths ------------------------------------

// TestErrorPaths_Decrypt_TooShort rejects an envelope shorter than the
// salt prefix.
func TestErrorPaths_Decrypt_TooShort(t *testing.T) {
	_, err := Decrypt([]byte{0x01}, []byte("pass"))
	wantError(t, err, "Decrypt of a sub-salt-length envelope should error")
}

// TestErrorPaths_DecryptAES_TooShort rejects an envelope shorter than the
// salt prefix.
func TestErrorPaths_DecryptAES_TooShort(t *testing.T) {
	_, err := DecryptAES([]byte{0x01}, []byte("pass"))
	wantError(t, err, "DecryptAES of a sub-salt-length envelope should error")
}

// TestErrorPaths_Decrypt_WrongPassphrase rejects an envelope decrypted
// with the wrong key.
func TestErrorPaths_Decrypt_WrongPassphrase(t *testing.T) {
	ct, err := Encrypt([]byte("secret"), []byte("right"))
	wantNoError(t, err, "seed encrypt")
	_, err = Decrypt(ct, []byte("wrong"))
	wantError(t, err, "Decrypt under the wrong passphrase should error")
}

// TestErrorPaths_DecryptAES_WrongPassphrase rejects a wrong key.
func TestErrorPaths_DecryptAES_WrongPassphrase(t *testing.T) {
	ct, err := EncryptAES([]byte("secret"), []byte("right"))
	wantNoError(t, err, "seed encrypt")
	_, err = DecryptAES(ct, []byte("wrong"))
	wantError(t, err, "DecryptAES under the wrong passphrase should error")
}

// --- checksum file error paths ------------------------------------------

// TestErrorPaths_SHA256File_Missing surfaces an open error for a missing
// file.
func TestErrorPaths_SHA256File_Missing(t *testing.T) {
	_, err := SHA256File("/no/such/file-256.bin")
	wantError(t, err, "SHA256File on a missing file should error")
}

// TestErrorPaths_SHA512File_Missing surfaces an open error for a missing
// file.
func TestErrorPaths_SHA512File_Missing(t *testing.T) {
	_, err := SHA512File("/no/such/file-512.bin")
	wantError(t, err, "SHA512File on a missing file should error")
}

// --- KDF error paths ----------------------------------------------------

// TestErrorPaths_DeriveKeyScrypt_Good derives a key with the hardcoded
// recommended scrypt parameters. The function's error branch is not
// reachable through the public API (N/r/p are fixed and valid; only an
// out-of-range keyLen could fail, and a negative keyLen panics inside
// scrypt.Key before any error is returned) — see the surfacing note.
func TestErrorPaths_DeriveKeyScrypt_Good(t *testing.T) {
	key, err := DeriveKeyScrypt([]byte("pass"), make([]byte, 16), 32)
	wantNoError(t, err, "scrypt derivation with valid params should succeed")
	wantLen(t, key, 32, "derived key length")
}

// TestErrorPaths_HKDF_Oversized rejects a key length beyond the
// HKDF-SHA256 ceiling (255 * 32 = 8160 bytes).
func TestErrorPaths_HKDF_Oversized(t *testing.T) {
	_, err := HKDF([]byte("secret"), nil, nil, 8161)
	wantError(t, err, "HKDF beyond the SHA-256 output ceiling should error")
}

// --- argon2 hash-string parse error paths -------------------------------

// TestErrorPaths_VerifyPassword_MalformedHash drives each VerifyPassword
// parse-error branch with a deliberately malformed encoded string.
func TestErrorPaths_VerifyPassword_MalformedHash(t *testing.T) {
	cases := map[string]string{
		"wrong field count":       "$argon2id$v=19$m=65536,t=3,p=4",
		"bad version prefix":      "$argon2id$X=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"non-numeric version":     "$argon2id$v=xx$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"unsupported version":     "$argon2id$v=99$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"bad param count":         "$argon2id$v=19$m=65536,t=3$c2FsdA$aGFzaA",
		"bad memory prefix":       "$argon2id$v=19$X=65536,t=3,p=4$c2FsdA$aGFzaA",
		"non-numeric memory":      "$argon2id$v=19$m=abc,t=3,p=4$c2FsdA$aGFzaA",
		"non-numeric parallelism": "$argon2id$v=19$m=65536,t=3,p=zz$c2FsdA$aGFzaA",
		"bad salt base64":         "$argon2id$v=19$m=65536,t=3,p=4$!!!$aGFzaA",
		"bad hash base64":         "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$!!!",
	}
	for name, hash := range cases {
		ok, err := VerifyPassword("password", hash)
		wantFalse(t, ok, name+": should not verify")
		wantError(t, err, name+": should error")
	}
}

// TestErrorPaths_VerifyPassword_RoundTrip confirms a freshly hashed
// password verifies and a different one does not.
func TestErrorPaths_VerifyPassword_RoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse")
	wantNoError(t, err, "hash")
	ok, err := VerifyPassword("correct horse", hash)
	wantNoError(t, err, "verify match")
	wantTrue(t, ok, "matching password verifies")

	ok, err = VerifyPassword("battery staple", hash)
	wantNoError(t, err, "verify mismatch")
	wantFalse(t, ok, "non-matching password does not verify")
}

// --- legacy parseArgonParams trio --------------------------------------
//
// parseArgonParams / parsePrefixedInt / parsePrefixedUint32 are a second
// argon2 parameter parser that VerifyPassword does NOT call (it uses
// parseArgon2Params / parseArgon2Uint32 / parseArgon2Uint8). They are
// exercised here for coverage; see the surfacing note to Cladius about
// the duplicate dead surface.

// TestErrorPaths_ParseArgonParams covers the good path and each error
// branch of the legacy parser.
func TestErrorPaths_ParseArgonParams(t *testing.T) {
	m, tm, p, err := parseArgonParams("m=65536,t=3,p=4")
	wantNoError(t, err, "valid params parse")
	wantEqual(t, uint32(65536), m, "memory")
	wantEqual(t, uint32(3), tm, "time")
	wantEqual(t, uint8(4), p, "parallelism")

	_, _, _, err = parseArgonParams("m=1,t=2")
	wantError(t, err, "wrong field count errors")
	_, _, _, err = parseArgonParams("X=1,t=2,p=3")
	wantError(t, err, "missing memory prefix errors")
	_, _, _, err = parseArgonParams("m=1,X=2,p=3")
	wantError(t, err, "missing time prefix errors")
	_, _, _, err = parseArgonParams("m=1,t=2,X=3")
	wantError(t, err, "missing parallelism prefix errors")
	_, _, _, err = parseArgonParams("m=abc,t=2,p=3")
	wantError(t, err, "non-numeric memory errors")
}

// TestErrorPaths_ParsePrefixedInt covers good and error branches of the
// legacy int parser.
func TestErrorPaths_ParsePrefixedInt(t *testing.T) {
	v, err := parsePrefixedInt("n=42", "n=")
	wantNoError(t, err, "valid prefixed int parse")
	wantEqual(t, 42, v, "parsed value")

	_, err = parsePrefixedInt("42", "n=")
	wantError(t, err, "missing prefix errors")
	_, err = parsePrefixedInt("n=abc", "n=")
	wantError(t, err, "non-numeric value errors")
}

// TestErrorPaths_ParsePrefixedUint32 covers good and error branches.
func TestErrorPaths_ParsePrefixedUint32(t *testing.T) {
	v, err := parsePrefixedUint32("m=65536", "m=")
	wantNoError(t, err, "valid prefixed uint32 parse")
	wantEqual(t, uint32(65536), v, "parsed value")

	_, err = parsePrefixedUint32("65536", "m=")
	wantError(t, err, "missing prefix errors")
	_, err = parsePrefixedUint32("m=notnum", "m=")
	wantError(t, err, "non-numeric value errors")
}

// --- raw base64 padding -------------------------------------------------

// TestErrorPaths_PadRawBase64 covers every length-mod-4 branch including
// the default (invalid len%4==1) case.
func TestErrorPaths_PadRawBase64(t *testing.T) {
	wantEqual(t, "", padRawBase64(""))         // len%4 == 0
	wantEqual(t, "ab==", padRawBase64("ab"))   // len%4 == 2
	wantEqual(t, "abc=", padRawBase64("abc"))  // len%4 == 3
	wantEqual(t, "a", padRawBase64("a"))       // len%4 == 1 (default, returned as-is)
	wantEqual(t, "abcd", padRawBase64("abcd")) // len%4 == 0
}
