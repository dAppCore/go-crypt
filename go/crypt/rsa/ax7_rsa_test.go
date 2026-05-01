package rsa

import core "dappco.re/go"

func ax7KeyPair(t *core.T) ([]byte, []byte) {
	t.Helper()
	svc := NewService()
	publicKey, privateKey, err := svc.GenerateKeyPair(2048)
	core.RequireNoError(t, err)
	return publicKey, privateKey
}

func TestAX7RSA_NewService_Good(t *core.T) {
	svc := NewService()
	core.AssertNotNil(t, svc)
	core.AssertNotNil(t, NewService())
}

func TestAX7RSA_NewService_Bad(t *core.T) {
	svc := NewService()
	ciphertext, err := svc.Encrypt([]byte("not-a-key"), []byte("data"), nil)
	core.AssertError(t, err)
	core.AssertNil(t, ciphertext)
}

func TestAX7RSA_NewService_Ugly(t *core.T) {
	first := NewService()
	second := NewService()
	core.AssertNotNil(t, first)
	core.AssertTrue(t, first != second)
}

func TestAX7RSA_Service_Encrypt_Good(t *core.T) {
	publicKey, _ := ax7KeyPair(t)
	svc := NewService()
	ciphertext, err := svc.Encrypt(publicKey, []byte("message"), []byte("label"))
	core.AssertNoError(t, err)
	core.AssertNotEmpty(t, ciphertext)
}

func TestAX7RSA_Service_Encrypt_Bad(t *core.T) {
	svc := NewService()
	ciphertext, err := svc.Encrypt([]byte("not-a-key"), []byte("message"), nil)
	core.AssertError(t, err)
	core.AssertNil(t, ciphertext)
}

func TestAX7RSA_Service_Encrypt_Ugly(t *core.T) {
	publicKey, _ := ax7KeyPair(t)
	svc := NewService()
	oversized := make([]byte, 2048)
	ciphertext, err := svc.Encrypt(publicKey, oversized, nil)
	core.AssertError(t, err)
	core.AssertNil(t, ciphertext)
}

func TestAX7RSA_Service_Decrypt_Good(t *core.T) {
	publicKey, privateKey := ax7KeyPair(t)
	svc := NewService()
	ciphertext, err := svc.Encrypt(publicKey, []byte("message"), []byte("label"))
	core.RequireNoError(t, err)
	plaintext, err := svc.Decrypt(privateKey, ciphertext, []byte("label"))
	core.AssertNoError(t, err)
	core.AssertEqual(t, []byte("message"), plaintext)
}

func TestAX7RSA_Service_Decrypt_Bad(t *core.T) {
	svc := NewService()
	plaintext, err := svc.Decrypt([]byte("not-a-key"), []byte("ciphertext"), nil)
	core.AssertError(t, err)
	core.AssertNil(t, plaintext)
}

func TestAX7RSA_Service_Decrypt_Ugly(t *core.T) {
	publicKey, privateKey := ax7KeyPair(t)
	svc := NewService()
	ciphertext, err := svc.Encrypt(publicKey, []byte("message"), []byte("label"))
	core.RequireNoError(t, err)
	plaintext, err := svc.Decrypt(privateKey, ciphertext, []byte("wrong-label"))
	core.AssertError(t, err)
	core.AssertNil(t, plaintext)
}
