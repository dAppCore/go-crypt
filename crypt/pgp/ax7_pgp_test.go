package pgp

import core "dappco.re/go"

func ax7KeyPair(t *core.T, password string) *KeyPair {
	t.Helper()
	kp, err := CreateKeyPair("AX7 User", "ax7@example.com", password)
	core.RequireNoError(t, err)
	core.RequireTrue(t, kp != nil)
	return kp
}

func TestAX7PGP_Decrypt_Good(t *core.T) {
	kp := ax7KeyPair(t, "")
	ciphertext, err := Encrypt([]byte("message"), kp.PublicKey)
	core.RequireNoError(t, err)
	plaintext, err := Decrypt(ciphertext, kp.PrivateKey, "")
	core.AssertNoError(t, err)
	core.AssertEqual(t, []byte("message"), plaintext)
}

func TestAX7PGP_Decrypt_Bad(t *core.T) {
	plaintext, err := Decrypt([]byte("not-a-message"), "not-a-key", "")
	core.AssertError(t, err)
	core.AssertNil(t, plaintext)
}

func TestAX7PGP_Decrypt_Ugly(t *core.T) {
	kp := ax7KeyPair(t, "secret")
	ciphertext, err := Encrypt([]byte("message"), kp.PublicKey)
	core.RequireNoError(t, err)
	plaintext, err := Decrypt(ciphertext, kp.PrivateKey, "wrong")
	core.AssertError(t, err)
	core.AssertNil(t, plaintext)
}

func TestAX7PGP_Verify_Good(t *core.T) {
	kp := ax7KeyPair(t, "")
	signature, err := Sign([]byte("message"), kp.PrivateKey, "")
	core.RequireNoError(t, err)
	err = Verify([]byte("message"), signature, kp.PublicKey)
	core.AssertNoError(t, err)
}

func TestAX7PGP_Verify_Bad(t *core.T) {
	kp := ax7KeyPair(t, "")
	signature, err := Sign([]byte("message"), kp.PrivateKey, "")
	core.RequireNoError(t, err)
	err = Verify([]byte("tampered"), signature, kp.PublicKey)
	core.AssertError(t, err)
}

func TestAX7PGP_Verify_Ugly(t *core.T) {
	kp := ax7KeyPair(t, "")
	signature, err := Sign([]byte("message"), kp.PrivateKey, "")
	core.RequireNoError(t, err)
	err = Verify([]byte("message"), signature, "not-a-key")
	core.AssertError(t, err)
}
