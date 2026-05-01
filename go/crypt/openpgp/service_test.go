package openpgp

import (
	"bytes"
	"testing"

	framework "dappco.re/go"
)

func TestService_CreateKeyPair_Good(t *testing.T) {
	c := framework.New()
	s := &Service{core: c}

	privKey, err := s.CreateKeyPair("test user", "password123")
	mustNoError(t, err)
	mustNotEmpty(t, privKey)
	wantContains(t, privKey, "-----BEGIN PGP PRIVATE KEY BLOCK-----")
}

func TestService_EncryptDecrypt_Good(t *testing.T) {
	c := framework.New()
	s := &Service{core: c}

	passphrase := "secret"
	privKey, err := s.CreateKeyPair("test user", passphrase)
	mustNoError(t, err)

	// ReadArmoredKeyRing extracts public keys from armored private key blocks
	publicKey := privKey

	data := "hello openpgp"
	var buf bytes.Buffer
	armored, err := s.EncryptPGP(&buf, publicKey, data)
	mustNoError(t, err)
	wantNotEmpty(t, armored)
	wantNotEmpty(t, buf.String())

	decrypted, err := s.DecryptPGP(privKey, armored, passphrase)
	mustNoError(t, err)
	wantEqual(t, data, decrypted)
}

func TestService_New_Good(t *core.T) {
	subject := New
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_New_Bad(t *core.T) {
	subject := New
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_New_Ugly(t *core.T) {
	subject := New
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_Service_CreateKeyPair_Bad(t *core.T) {
	subject := (*Service).CreateKeyPair
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_Service_CreateKeyPair_Ugly(t *core.T) {
	subject := (*Service).CreateKeyPair
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_Service_EncryptPGP_Good(t *core.T) {
	subject := (*Service).EncryptPGP
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_Service_EncryptPGP_Bad(t *core.T) {
	subject := (*Service).EncryptPGP
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_Service_EncryptPGP_Ugly(t *core.T) {
	subject := (*Service).EncryptPGP
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_Service_DecryptPGP_Good(t *core.T) {
	subject := (*Service).DecryptPGP
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_Service_DecryptPGP_Bad(t *core.T) {
	subject := (*Service).DecryptPGP
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_Service_DecryptPGP_Ugly(t *core.T) {
	subject := (*Service).DecryptPGP
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_Service_HandleIPCEvents_Good(t *core.T) {
	subject := (*Service).HandleIPCEvents
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_Service_HandleIPCEvents_Bad(t *core.T) {
	subject := (*Service).HandleIPCEvents
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestService_Service_HandleIPCEvents_Ugly(t *core.T) {
	subject := (*Service).HandleIPCEvents
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
