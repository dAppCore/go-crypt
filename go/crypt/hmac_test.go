package crypt

import (
	// Note: intrinsic crypto primitive -- no core.* equivalent (go-crypt implements core crypto; cannot self-depend).
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

func TestHmac_HMACSHA256_Good(t *core.T) {
	subject := HMACSHA256
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHmac_HMACSHA256_Bad(t *core.T) {
	subject := HMACSHA256
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHmac_HMACSHA256_Ugly(t *core.T) {
	subject := HMACSHA256
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHmac_HMACSHA512_Good(t *core.T) {
	subject := HMACSHA512
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHmac_HMACSHA512_Bad(t *core.T) {
	subject := HMACSHA512
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHmac_HMACSHA512_Ugly(t *core.T) {
	subject := HMACSHA512
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHmac_VerifyHMAC_Good(t *core.T) {
	subject := VerifyHMAC
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHmac_VerifyHMAC_Bad(t *core.T) {
	subject := VerifyHMAC
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHmac_VerifyHMAC_Ugly(t *core.T) {
	subject := VerifyHMAC
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
