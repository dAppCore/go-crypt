package openpgp

import (
	"bytes"
	"testing"

	framework "dappco.re/go/core"
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
