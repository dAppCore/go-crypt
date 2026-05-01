package chachapoly

import core "dappco.re/go"

func ax7Key() []byte {
	key := make([]byte, 32)
	key[0] = 1
	return key
}

func TestAX7Chachapoly_Encrypt_Good(t *core.T) {
	key := ax7Key()
	ciphertext, err := Encrypt([]byte("plain"), key)
	core.AssertNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > len("plain"))
}

func TestAX7Chachapoly_Encrypt_Bad(t *core.T) {
	key := []byte("short")
	ciphertext, err := Encrypt([]byte("plain"), key)
	core.AssertError(t, err)
	core.AssertNil(t, ciphertext)
}

func TestAX7Chachapoly_Encrypt_Ugly(t *core.T) {
	key := ax7Key()
	ciphertext, err := Encrypt(nil, key)
	core.AssertNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > 0)
}

func TestAX7Chachapoly_Decrypt_Good(t *core.T) {
	key := ax7Key()
	ciphertext, err := Encrypt([]byte("plain"), key)
	core.RequireNoError(t, err)
	plaintext, err := Decrypt(ciphertext, key)
	core.AssertNoError(t, err)
	core.AssertEqual(t, []byte("plain"), plaintext)
}

func TestAX7Chachapoly_Decrypt_Bad(t *core.T) {
	key := ax7Key()
	plaintext, err := Decrypt([]byte("short"), key)
	core.AssertError(t, err)
	core.AssertNil(t, plaintext)
}

func TestAX7Chachapoly_Decrypt_Ugly(t *core.T) {
	key := ax7Key()
	ciphertext, err := Encrypt([]byte("plain"), key)
	core.RequireNoError(t, err)
	wrongKey := ax7Key()
	wrongKey[1] = 2
	plaintext, err := Decrypt(ciphertext, wrongKey)
	core.AssertError(t, err)
	core.AssertNil(t, plaintext)
}
