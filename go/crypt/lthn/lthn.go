// Package lthn implements the LTHN quasi-salted hash algorithm (RFC-0004).
//
// LTHN produces deterministic, verifiable hashes without requiring separate salt
// storage. The salt is derived from the input itself through:
//  1. Reversing the input string
//  2. Applying "leet speak" style character substitutions
//
// The final hash is: SHA256(input || derived_salt)
//
// This is suitable for content identifiers, cache keys, and deduplication.
// NOT suitable for password hashing - use bcrypt, Argon2, or scrypt instead.
//
// Example:
//
//	hash := lthn.Hash("hello")
//	valid := lthn.Verify("hello", hash)  // true
package lthn

import (
	"crypto/subtle"

	enchantrixlthn "forge.lthn.ai/Snider/Enchantrix/pkg/crypt/std/lthn"
)

// SetKeyMap replaces the default character substitution map.
// Use this to customize the quasi-salt derivation for specific applications.
// Changes affect all subsequent Hash and Verify calls.
// Usage: call SetKeyMap(...) during the package's normal workflow.
func SetKeyMap(newKeyMap map[rune]rune) {
	enchantrixlthn.SetKeyMap(newKeyMap)
}

// GetKeyMap returns the current character substitution map.
// Usage: call GetKeyMap(...) during the package's normal workflow.
func GetKeyMap() map[rune]rune {
	return enchantrixlthn.GetKeyMap()
}

// Hash computes the LTHN hash of the input string.
//
// The algorithm:
//  1. Derive a quasi-salt by reversing the input and applying character substitutions
//  2. Concatenate: input + salt
//  3. Compute SHA-256 of the concatenated string
//  4. Return the hex-encoded digest (64 characters, lowercase)
//
// The same input always produces the same hash, enabling verification
// without storing a separate salt value.
// Usage: call Hash(...) when you need a deterministic content-style digest rather than a password hash.
func Hash(input string) string {
	return enchantrixlthn.Hash(input)
}

// Verify checks if an input string produces the given hash.
// Returns true if Hash(input) equals the provided hash value.
// Uses constant-time comparison to prevent timing attacks.
// Usage: call Verify(...) during the package's normal workflow.
func Verify(input string, hash string) bool {
	computed := Hash(input)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}
