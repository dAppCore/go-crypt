package openpgp

import (
	"bytes"
	"testing"

	framework "dappco.re/go"
)

const badKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nnonsense\n-----END PGP PRIVATE KEY BLOCK-----\n"

func newService(t testing.TB) *Service {
	t.Helper()
	v, err := New(framework.New())
	mustNoError(t, err, "construct service")
	s, ok := v.(*Service)
	mustTrue(t, ok, "service type")
	return s
}

// TestErrorPaths_EncryptPGP_BadRecipient rejects an unreadable recipient
// public key.
func TestErrorPaths_EncryptPGP_BadRecipient(t *testing.T) {
	s := newService(t)
	var buf bytes.Buffer
	_, err := s.EncryptPGP(&buf, badKey, "data")
	wantError(t, err, "EncryptPGP with an unreadable recipient key should error")
	_, err = s.EncryptPGP(&buf, "", "data")
	wantError(t, err, "EncryptPGP with an empty recipient key should error")
}

// TestErrorPaths_DecryptPGP_BadPrivateKey rejects an unreadable private
// key.
func TestErrorPaths_DecryptPGP_BadPrivateKey(t *testing.T) {
	s := newService(t)
	_, err := s.DecryptPGP(badKey, "message", "")
	wantError(t, err, "DecryptPGP with an unreadable private key should error")
}

// TestErrorPaths_DecryptPGP_WrongPassphrase rejects the wrong passphrase
// on a password-protected key.
func TestErrorPaths_DecryptPGP_WrongPassphrase(t *testing.T) {
	s := newService(t)
	priv, err := s.CreateKeyPair("Boxed", "key-pass")
	mustNoError(t, err, "create key pair")

	// The encrypted private key must be decrypted before the message can
	// be read; a wrong passphrase fails at that step.
	_, err = s.DecryptPGP(priv, "anything", "wrong-pass")
	wantError(t, err, "DecryptPGP with the wrong passphrase should error")
}

// TestErrorPaths_DecryptPGP_GarbageMessage rejects a non-armored message.
func TestErrorPaths_DecryptPGP_GarbageMessage(t *testing.T) {
	s := newService(t)
	priv, err := s.CreateKeyPair("Plain", "")
	mustNoError(t, err, "create key pair")
	_, err = s.DecryptPGP(priv, "not an armored message", "")
	wantError(t, err, "DecryptPGP of a non-armored message should error")
}

// TestErrorPaths_CreateKeyPair_PasswordProtected exercises the
// password-protected serializeEntity branch (encrypted private + subkey
// serialisation) and confirms a non-empty armored private key results.
func TestErrorPaths_CreateKeyPair_PasswordProtected(t *testing.T) {
	s := newService(t)
	priv, err := s.CreateKeyPair("Boxed User", "envelope-pass")
	mustNoError(t, err, "create password-protected key pair")
	mustNotEmpty(t, priv, "armored private key")
}

// TestErrorPaths_HandleIPCEvents drives the IPC dispatch surface: a valid
// create_key_pair action, an unknown action, and a non-map message.
func TestErrorPaths_HandleIPCEvents(t *testing.T) {
	s := newService(t)
	c := framework.New()

	err := s.HandleIPCEvents(c, map[string]any{
		"action": "openpgp.create_key_pair",
		"name":   "IPC User",
	})
	wantNoError(t, err, "valid create_key_pair IPC action should succeed")

	err = s.HandleIPCEvents(c, map[string]any{"action": "openpgp.unknown"})
	wantNoError(t, err, "unknown action is a no-op")

	err = s.HandleIPCEvents(c, "not a map")
	wantNoError(t, err, "non-map message is a no-op")
}
