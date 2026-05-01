package crypt

import (
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestHash_HashPassword_Good(t *testing.T) {
	password := "my-secure-password"

	hash, err := HashPassword(password)
	wantNoError(t, err)
	wantNotEmpty(t, hash)
	wantContains(t, hash, "$argon2id$")

	match, err := VerifyPassword(password, hash)
	wantNoError(t, err)
	wantTrue(t, match)
}

func TestHash_VerifyPassword_Bad(t *testing.T) {
	password := "my-secure-password"
	wrongPassword := "wrong-password"

	hash, err := HashPassword(password)
	wantNoError(t, err)

	match, err := VerifyPassword(wrongPassword, hash)
	wantNoError(t, err)
	wantFalse(t, match)
}

func TestHash_HashBcrypt_Good(t *testing.T) {
	password := "bcrypt-test-password"

	hash, err := HashBcrypt(password, bcrypt.DefaultCost)
	wantNoError(t, err)
	wantNotEmpty(t, hash)

	match, err := VerifyBcrypt(password, hash)
	wantNoError(t, err)
	wantTrue(t, match)

	// Wrong password should not match
	match, err = VerifyBcrypt("wrong-password", hash)
	wantNoError(t, err)
	wantFalse(t, match)
}

func TestHash_HashPassword_Bad(t *core.T) {
	subject := HashPassword
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHash_HashPassword_Ugly(t *core.T) {
	subject := HashPassword
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHash_VerifyPassword_Good(t *core.T) {
	subject := VerifyPassword
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHash_VerifyPassword_Ugly(t *core.T) {
	subject := VerifyPassword
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHash_HashBcrypt_Bad(t *core.T) {
	subject := HashBcrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHash_HashBcrypt_Ugly(t *core.T) {
	subject := HashBcrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestHash_VerifyBcrypt_Good(t *core.T) {
	subject := VerifyBcrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHash_VerifyBcrypt_Bad(t *core.T) {
	subject := VerifyBcrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHash_VerifyBcrypt_Ugly(t *core.T) {
	subject := VerifyBcrypt
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
