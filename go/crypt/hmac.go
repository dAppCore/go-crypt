package crypt

import (
	// Note: intrinsic crypto primitive -- no core.* equivalent (go-crypt implements core crypto; cannot self-depend).
	"crypto/hmac"
	// Note: intrinsic crypto primitive -- no core.* equivalent (go-crypt implements core crypto; cannot self-depend).
	"crypto/sha256"
	// Note: intrinsic crypto primitive -- no core.* equivalent (go-crypt implements core crypto; cannot self-depend).
	"crypto/sha512"
	"hash"
)

// HMACSHA256 computes the HMAC-SHA256 of a message using the given key.
// Usage: call HMACSHA256(...) during the package's normal workflow.
func HMACSHA256(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// HMACSHA512 computes the HMAC-SHA512 of a message using the given key.
// Usage: call HMACSHA512(...) during the package's normal workflow.
func HMACSHA512(message, key []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// VerifyHMAC verifies an HMAC using constant-time comparison.
// hashFunc should be sha256.New, sha512.New, etc.
// Usage: call VerifyHMAC(...) during the package's normal workflow.
func VerifyHMAC(message, key, mac []byte, hashFunc func() hash.Hash) bool {
	expected := hmac.New(hashFunc, key)
	expected.Write(message)
	return hmac.Equal(mac, expected.Sum(nil))
}
