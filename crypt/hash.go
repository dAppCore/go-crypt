package crypt

import (
	// Note: intrinsic crypto primitive -- no core.* equivalent (go-crypt implements core crypto; cannot self-depend).
	"crypto/subtle"
	"strconv"

	core "dappco.re/go"
	"dappco.re/go/crypt/internal/corecompat"
	coreerr "dappco.re/go/log"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a password using Argon2id with default parameters.
// Returns a string in the format: $argon2id$v=19$m=65536,t=3,p=4$<base64salt>$<base64hash>
// Usage: call HashPassword(...) during the package's normal workflow.
func HashPassword(password string) (string, error) {
	salt, err := generateSalt(argon2SaltLen)
	if err != nil {
		return "", coreerr.E("crypt.HashPassword", "failed to generate salt", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Parallelism, argon2KeyLen)

	b64Salt := rawBase64Encode(salt)
	b64Hash := rawBase64Encode(hash)

	encoded := core.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Parallelism,
		b64Salt, b64Hash)

	return encoded, nil
}

// VerifyPassword verifies a password against an Argon2id hash string.
// The hash must be in the format produced by HashPassword.
// Usage: call VerifyPassword(...) during the package's normal workflow.
func VerifyPassword(password, hash string) (bool, error) {
	parts := core.Split(hash, "$")
	if len(parts) != 6 {
		return false, coreerr.E("crypt.VerifyPassword", "invalid hash format", nil)
	}

	version, err := parseArgon2Version(parts[2])
	if err != nil {
		return false, coreerr.E("crypt.VerifyPassword", "failed to parse version", err)
	}
	if version != argon2.Version {
		return false, coreerr.E("crypt.VerifyPassword", core.Sprintf("unsupported argon2 version %d", version), nil)
	}

	memory, time, parallelism, err := parseArgon2Params(parts[3])
	if err != nil {
		return false, coreerr.E("crypt.VerifyPassword", "failed to parse parameters", err)
	}

	salt, err := rawBase64Decode(parts[4])
	if err != nil {
		return false, coreerr.E("crypt.VerifyPassword", "failed to decode salt", err)
	}

	expectedHash, err := rawBase64Decode(parts[5])
	if err != nil {
		return false, coreerr.E("crypt.VerifyPassword", "failed to decode hash", err)
	}

	computedHash := argon2.IDKey([]byte(password), salt, time, memory, parallelism, uint32(len(expectedHash)))

	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1, nil
}

func parseArgonParams(input string) (uint32, uint32, uint8, error) {
	fields := core.Split(input, ",")
	if len(fields) != 3 {
		return 0, 0, 0, core.NewError("invalid argon2 parameters")
	}

	memory, err := parsePrefixedUint32(fields[0], "m=")
	if err != nil {
		return 0, 0, 0, err
	}
	time, err := parsePrefixedUint32(fields[1], "t=")
	if err != nil {
		return 0, 0, 0, err
	}
	parallelismValue, err := parsePrefixedUint32(fields[2], "p=")
	if err != nil {
		return 0, 0, 0, err
	}

	return memory, time, uint8(parallelismValue), nil
}

func parsePrefixedInt(input, prefix string) (int, error) {
	if !core.HasPrefix(input, prefix) {
		return 0, core.NewError(core.Sprintf("missing %q prefix", prefix))
	}

	value, err := strconv.Atoi(core.TrimPrefix(input, prefix))
	if err != nil {
		return 0, err
	}
	return value, nil
}

func parsePrefixedUint32(input, prefix string) (uint32, error) {
	if !core.HasPrefix(input, prefix) {
		return 0, core.NewError(core.Sprintf("missing %q prefix", prefix))
	}

	value, err := strconv.ParseUint(core.TrimPrefix(input, prefix), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(value), nil
}

// HashBcrypt hashes a password using bcrypt with the given cost.
// Cost must be between bcrypt.MinCost and bcrypt.MaxCost.
// Usage: call HashBcrypt(...) during the package's normal workflow.
func HashBcrypt(password string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", coreerr.E("crypt.HashBcrypt", "failed to hash password", err)
	}
	return string(hash), nil
}

// VerifyBcrypt verifies a password against a bcrypt hash.
// Usage: call VerifyBcrypt(...) during the package's normal workflow.
func VerifyBcrypt(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, coreerr.E("crypt.VerifyBcrypt", "failed to verify password", err)
	}
	return true, nil
}

func parseArgon2Version(s string) (int, error) {
	if !core.HasPrefix(s, "v=") {
		return 0, coreerr.E("crypt.parseArgon2Version", "missing version prefix", nil)
	}
	return strconv.Atoi(core.TrimPrefix(s, "v="))
}

func parseArgon2Params(s string) (uint32, uint32, uint8, error) {
	parts := core.Split(s, ",")
	if len(parts) != 3 {
		return 0, 0, 0, coreerr.E("crypt.parseArgon2Params", "invalid parameter count", nil)
	}

	memory, err := parseArgon2Uint32(parts[0], "m=")
	if err != nil {
		return 0, 0, 0, err
	}
	time, err := parseArgon2Uint32(parts[1], "t=")
	if err != nil {
		return 0, 0, 0, err
	}
	parallelism, err := parseArgon2Uint8(parts[2], "p=")
	if err != nil {
		return 0, 0, 0, err
	}
	return memory, time, parallelism, nil
}

func parseArgon2Uint32(s, prefix string) (uint32, error) {
	if !core.HasPrefix(s, prefix) {
		return 0, coreerr.E("crypt.parseArgon2Uint32", "missing parameter prefix", nil)
	}
	value, err := strconv.ParseUint(core.TrimPrefix(s, prefix), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(value), nil
}

func parseArgon2Uint8(s, prefix string) (uint8, error) {
	if !core.HasPrefix(s, prefix) {
		return 0, coreerr.E("crypt.parseArgon2Uint8", "missing parameter prefix", nil)
	}
	value, err := strconv.ParseUint(core.TrimPrefix(s, prefix), 10, 8)
	if err != nil {
		return 0, err
	}
	return uint8(value), nil
}

func rawBase64Encode(src []byte) string {
	return core.TrimSuffix(core.TrimSuffix(corecompat.Base64Encode(src), "="), "=")
}

func rawBase64Decode(s string) ([]byte, error) {
	return corecompat.Base64Decode(padRawBase64(s))
}

func padRawBase64(s string) string {
	switch len(s) % 4 {
	case 0:
		return s
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}
