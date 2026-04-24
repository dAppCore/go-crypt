package crypt

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHMAC_HMACSHA256_Good(t *testing.T) {
	// RFC 4231 Test Case 2
	key := []byte("Jefe")
	message := []byte("what do ya want for nothing?")
	expected := "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

	mac := HMACSHA256(message, key)
	wantEqual(t, expected, hex.EncodeToString(mac))
}

func TestHMAC_VerifyHMAC_Good(t *testing.T) {
	key := []byte("secret-key")
	message := []byte("test message")

	mac := HMACSHA256(message, key)

	valid := VerifyHMAC(message, key, mac, sha256.New)
	wantTrue(t, valid)
}

func TestHMAC_VerifyHMAC_Bad(t *testing.T) {
	key := []byte("secret-key")
	message := []byte("test message")
	tampered := []byte("tampered message")

	mac := HMACSHA256(message, key)

	valid := VerifyHMAC(tampered, key, mac, sha256.New)
	wantFalse(t, valid)
}
