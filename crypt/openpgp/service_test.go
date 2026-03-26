package openpgp

import (
	"bytes"
	"testing"

	framework "dappco.re/go/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_CreateKeyPair_Good(t *testing.T) {
	c := framework.New()
	s := &Service{core: c}

	privKey, err := s.CreateKeyPair("test user", "password123")
	require.NoError(t, err)
	require.NotEmpty(t, privKey)
	assert.Contains(t, privKey, "-----BEGIN PGP PRIVATE KEY BLOCK-----")
}

func TestService_EncryptDecrypt_Good(t *testing.T) {
	c := framework.New()
	s := &Service{core: c}

	passphrase := "secret"
	privKey, err := s.CreateKeyPair("test user", passphrase)
	require.NoError(t, err)

	// ReadArmoredKeyRing extracts public keys from armored private key blocks
	publicKey := privKey

	data := "hello openpgp"
	var buf bytes.Buffer
	armored, err := s.EncryptPGP(&buf, publicKey, data)
	require.NoError(t, err)
	assert.NotEmpty(t, armored)
	assert.NotEmpty(t, buf.String())

	decrypted, err := s.DecryptPGP(privKey, armored, passphrase)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted)
}
