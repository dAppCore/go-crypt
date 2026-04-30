package crypt

import (
	"crypto/sha256"

	core "dappco.re/go"
)

func ax7Key() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func ax7Salt() []byte {
	return []byte("1234567890abcdef")
}

func TestAX7Crypt_HMACSHA256_Good(t *core.T) {
	mac := HMACSHA256([]byte("message"), []byte("key"))
	core.AssertEqual(t, 32, len(mac))
	core.AssertTrue(t, VerifyHMAC([]byte("message"), []byte("key"), mac, sha256.New))
}

func TestAX7Crypt_HMACSHA256_Bad(t *core.T) {
	mac := HMACSHA256([]byte("message"), []byte("key"))
	core.AssertEqual(t, 32, len(mac))
	core.AssertFalse(t, VerifyHMAC([]byte("message!"), []byte("key"), mac, sha256.New))
}

func TestAX7Crypt_HMACSHA256_Ugly(t *core.T) {
	mac := HMACSHA256(nil, nil)
	core.AssertEqual(t, 32, len(mac))
	core.AssertTrue(t, VerifyHMAC(nil, nil, mac, sha256.New))
}

func TestAX7Crypt_HMACSHA512_Good(t *core.T) {
	mac := HMACSHA512([]byte("message"), []byte("key"))
	core.AssertEqual(t, 64, len(mac))
	core.AssertNotEqual(t, HMACSHA512([]byte("message"), []byte("other")), mac)
}

func TestAX7Crypt_HMACSHA512_Bad(t *core.T) {
	left := HMACSHA512([]byte("message"), []byte("key"))
	right := HMACSHA512([]byte("tampered"), []byte("key"))
	core.AssertNotEqual(t, left, right)
}

func TestAX7Crypt_HMACSHA512_Ugly(t *core.T) {
	mac := HMACSHA512(nil, nil)
	core.AssertEqual(t, 64, len(mac))
	core.AssertEqual(t, mac, HMACSHA512(nil, nil))
}

func TestAX7Crypt_VerifyHMAC_Good(t *core.T) {
	mac := HMACSHA256([]byte("payload"), []byte("secret"))
	ok := VerifyHMAC([]byte("payload"), []byte("secret"), mac, sha256.New)
	core.AssertTrue(t, ok)
}

func TestAX7Crypt_VerifyHMAC_Bad(t *core.T) {
	mac := HMACSHA256([]byte("payload"), []byte("secret"))
	ok := VerifyHMAC([]byte("payload"), []byte("wrong"), mac, sha256.New)
	core.AssertFalse(t, ok)
}

func TestAX7Crypt_VerifyHMAC_Ugly(t *core.T) {
	ok := VerifyHMAC(nil, nil, HMACSHA256(nil, nil), sha256.New)
	core.AssertTrue(t, ok)
	core.AssertFalse(t, VerifyHMAC(nil, nil, []byte("short"), sha256.New))
}

func TestAX7Crypt_HashPassword_Good(t *core.T) {
	hash, err := HashPassword("secret")
	core.RequireNoError(t, err)
	core.AssertTrue(t, core.Contains(hash, "$argon2id$"))
}

func TestAX7Crypt_HashPassword_Bad(t *core.T) {
	hash, err := HashPassword("")
	core.RequireNoError(t, err)
	core.AssertTrue(t, core.Contains(hash, "$argon2id$"))
}

func TestAX7Crypt_HashPassword_Ugly(t *core.T) {
	hash, err := HashPassword("pässwörd")
	core.RequireNoError(t, err)
	core.AssertTrue(t, core.Contains(hash, "$argon2id$"))
}

func TestAX7Crypt_VerifyPassword_Good(t *core.T) {
	hash, err := HashPassword("secret")
	core.RequireNoError(t, err)
	ok, err := VerifyPassword("secret", hash)
	core.AssertNoError(t, err)
	core.AssertTrue(t, ok)
}

func TestAX7Crypt_VerifyPassword_Bad(t *core.T) {
	ok, err := VerifyPassword("secret", "not-an-argon-hash")
	core.AssertError(t, err)
	core.AssertFalse(t, ok)
}

func TestAX7Crypt_VerifyPassword_Ugly(t *core.T) {
	hash, err := HashPassword("secret")
	core.RequireNoError(t, err)
	ok, err := VerifyPassword("wrong", hash)
	core.AssertNoError(t, err)
	core.AssertFalse(t, ok)
}

func TestAX7Crypt_HashBcrypt_Good(t *core.T) {
	hash, err := HashBcrypt("secret", 4)
	core.RequireNoError(t, err)
	core.AssertTrue(t, core.HasPrefix(hash, "$2"))
}

func TestAX7Crypt_HashBcrypt_Bad(t *core.T) {
	hash, err := HashBcrypt("secret", 100)
	core.AssertError(t, err)
	core.AssertEqual(t, "", hash)
}

func TestAX7Crypt_HashBcrypt_Ugly(t *core.T) {
	hash, err := HashBcrypt("", 4)
	core.RequireNoError(t, err)
	core.AssertTrue(t, core.HasPrefix(hash, "$2"))
}

func TestAX7Crypt_VerifyBcrypt_Good(t *core.T) {
	hash, err := HashBcrypt("secret", 4)
	core.RequireNoError(t, err)
	ok, err := VerifyBcrypt("secret", hash)
	core.AssertNoError(t, err)
	core.AssertTrue(t, ok)
}

func TestAX7Crypt_VerifyBcrypt_Bad(t *core.T) {
	hash, err := HashBcrypt("secret", 4)
	core.RequireNoError(t, err)
	ok, err := VerifyBcrypt("wrong", hash)
	core.AssertNoError(t, err)
	core.AssertFalse(t, ok)
}

func TestAX7Crypt_VerifyBcrypt_Ugly(t *core.T) {
	ok, err := VerifyBcrypt("secret", "not-a-bcrypt-hash")
	core.AssertError(t, err)
	core.AssertFalse(t, ok)
}

func TestAX7Crypt_DeriveKey_Good(t *core.T) {
	key := DeriveKey([]byte("pass"), ax7Salt(), 32)
	core.AssertEqual(t, 32, len(key))
	core.AssertEqual(t, key, DeriveKey([]byte("pass"), ax7Salt(), 32))
}

func TestAX7Crypt_DeriveKey_Bad(t *core.T) {
	salt := ax7Salt()
	core.AssertEqual(t, 16, len(salt))
	core.AssertPanics(t, func() {
		_ = DeriveKey([]byte("pass"), salt, 0)
	})
}

func TestAX7Crypt_DeriveKey_Ugly(t *core.T) {
	key := DeriveKey(nil, nil, 16)
	core.AssertEqual(t, 16, len(key))
	core.AssertEqual(t, key, DeriveKey(nil, nil, 16))
}

func TestAX7Crypt_DeriveKeyScrypt_Good(t *core.T) {
	key, err := DeriveKeyScrypt([]byte("pass"), ax7Salt(), 32)
	core.AssertNoError(t, err)
	core.AssertEqual(t, 32, len(key))
}

func TestAX7Crypt_DeriveKeyScrypt_Bad(t *core.T) {
	salt := ax7Salt()
	core.AssertEqual(t, 16, len(salt))
	core.AssertPanics(t, func() {
		_, _ = DeriveKeyScrypt([]byte("pass"), salt, -1)
	})
}

func TestAX7Crypt_DeriveKeyScrypt_Ugly(t *core.T) {
	key, err := DeriveKeyScrypt(nil, nil, 16)
	core.AssertNoError(t, err)
	core.AssertEqual(t, 16, len(key))
}

func TestAX7Crypt_HKDF_Good(t *core.T) {
	key, err := HKDF([]byte("secret"), []byte("salt"), []byte("info"), 32)
	core.AssertNoError(t, err)
	core.AssertEqual(t, 32, len(key))
}

func TestAX7Crypt_HKDF_Bad(t *core.T) {
	key, err := HKDF([]byte("secret"), []byte("salt"), []byte("info"), 0)
	core.AssertNoError(t, err)
	core.AssertEqual(t, 0, len(key))
}

func TestAX7Crypt_HKDF_Ugly(t *core.T) {
	key, err := HKDF(nil, nil, nil, 16)
	core.AssertNoError(t, err)
	core.AssertEqual(t, 16, len(key))
}

func TestAX7Crypt_ChaCha20Encrypt_Good(t *core.T) {
	ciphertext, err := ChaCha20Encrypt([]byte("plain"), ax7Key())
	core.AssertNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > len("plain"))
}

func TestAX7Crypt_ChaCha20Encrypt_Bad(t *core.T) {
	ciphertext, err := ChaCha20Encrypt([]byte("plain"), []byte("short"))
	core.AssertError(t, err)
	core.AssertNil(t, ciphertext)
}

func TestAX7Crypt_ChaCha20Encrypt_Ugly(t *core.T) {
	ciphertext, err := ChaCha20Encrypt(nil, ax7Key())
	core.AssertNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > 0)
}

func TestAX7Crypt_ChaCha20Decrypt_Good(t *core.T) {
	ciphertext, err := ChaCha20Encrypt([]byte("plain"), ax7Key())
	core.RequireNoError(t, err)
	plain, err := ChaCha20Decrypt(ciphertext, ax7Key())
	core.AssertNoError(t, err)
	core.AssertEqual(t, []byte("plain"), plain)
}

func TestAX7Crypt_ChaCha20Decrypt_Bad(t *core.T) {
	plain, err := ChaCha20Decrypt([]byte("short"), ax7Key())
	core.AssertError(t, err)
	core.AssertNil(t, plain)
}

func TestAX7Crypt_ChaCha20Decrypt_Ugly(t *core.T) {
	plain, err := ChaCha20Decrypt(nil, []byte("short"))
	core.AssertError(t, err)
	core.AssertNil(t, plain)
}

func TestAX7Crypt_AESGCMEncrypt_Good(t *core.T) {
	ciphertext, err := AESGCMEncrypt([]byte("plain"), ax7Key())
	core.AssertNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > len("plain"))
}

func TestAX7Crypt_AESGCMEncrypt_Bad(t *core.T) {
	ciphertext, err := AESGCMEncrypt([]byte("plain"), []byte("short"))
	core.AssertError(t, err)
	core.AssertNil(t, ciphertext)
}

func TestAX7Crypt_AESGCMEncrypt_Ugly(t *core.T) {
	ciphertext, err := AESGCMEncrypt(nil, ax7Key())
	core.AssertNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > 0)
}

func TestAX7Crypt_AESGCMDecrypt_Good(t *core.T) {
	ciphertext, err := AESGCMEncrypt([]byte("plain"), ax7Key())
	core.RequireNoError(t, err)
	plain, err := AESGCMDecrypt(ciphertext, ax7Key())
	core.AssertNoError(t, err)
	core.AssertEqual(t, []byte("plain"), plain)
}

func TestAX7Crypt_AESGCMDecrypt_Bad(t *core.T) {
	plain, err := AESGCMDecrypt([]byte("short"), ax7Key())
	core.AssertError(t, err)
	core.AssertNil(t, plain)
}

func TestAX7Crypt_AESGCMDecrypt_Ugly(t *core.T) {
	plain, err := AESGCMDecrypt(nil, []byte("short"))
	core.AssertError(t, err)
	core.AssertNil(t, plain)
}

func TestAX7Crypt_Encrypt_Good(t *core.T) {
	ciphertext, err := Encrypt([]byte("plain"), []byte("pass"))
	core.RequireNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > len("plain"))
}

func TestAX7Crypt_Encrypt_Bad(t *core.T) {
	ciphertext, err := Encrypt(nil, []byte("pass"))
	core.AssertNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > 0)
}

func TestAX7Crypt_Encrypt_Ugly(t *core.T) {
	ciphertext, err := Encrypt([]byte("plain"), nil)
	core.AssertNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > 0)
}

func TestAX7Crypt_Decrypt_Good(t *core.T) {
	ciphertext, err := Encrypt([]byte("plain"), []byte("pass"))
	core.RequireNoError(t, err)
	plain, err := Decrypt(ciphertext, []byte("pass"))
	core.AssertNoError(t, err)
	core.AssertEqual(t, []byte("plain"), plain)
}

func TestAX7Crypt_Decrypt_Bad(t *core.T) {
	plain, err := Decrypt([]byte("short"), []byte("pass"))
	core.AssertError(t, err)
	core.AssertNil(t, plain)
}

func TestAX7Crypt_Decrypt_Ugly(t *core.T) {
	ciphertext, err := Encrypt([]byte("plain"), nil)
	core.RequireNoError(t, err)
	plain, err := Decrypt(ciphertext, nil)
	core.AssertNoError(t, err)
	core.AssertEqual(t, []byte("plain"), plain)
}

func TestAX7Crypt_EncryptAES_Good(t *core.T) {
	ciphertext, err := EncryptAES([]byte("plain"), []byte("pass"))
	core.RequireNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > len("plain"))
}

func TestAX7Crypt_EncryptAES_Bad(t *core.T) {
	ciphertext, err := EncryptAES(nil, []byte("pass"))
	core.AssertNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > 0)
}

func TestAX7Crypt_EncryptAES_Ugly(t *core.T) {
	ciphertext, err := EncryptAES([]byte("plain"), nil)
	core.AssertNoError(t, err)
	core.AssertTrue(t, len(ciphertext) > 0)
}

func TestAX7Crypt_DecryptAES_Good(t *core.T) {
	ciphertext, err := EncryptAES([]byte("plain"), []byte("pass"))
	core.RequireNoError(t, err)
	plain, err := DecryptAES(ciphertext, []byte("pass"))
	core.AssertNoError(t, err)
	core.AssertEqual(t, []byte("plain"), plain)
}

func TestAX7Crypt_DecryptAES_Bad(t *core.T) {
	plain, err := DecryptAES([]byte("short"), []byte("pass"))
	core.AssertError(t, err)
	core.AssertNil(t, plain)
}

func TestAX7Crypt_DecryptAES_Ugly(t *core.T) {
	ciphertext, err := EncryptAES([]byte("plain"), nil)
	core.RequireNoError(t, err)
	plain, err := DecryptAES(ciphertext, nil)
	core.AssertNoError(t, err)
	core.AssertEqual(t, []byte("plain"), plain)
}

func TestAX7Crypt_SHA256File_Good(t *core.T) {
	path := core.Path(t.TempDir(), "data.txt")
	core.RequireTrue(t, (&core.Fs{}).New("/").WriteMode(path, "hello", 0o644).OK)
	got, err := SHA256File(path)
	core.AssertNoError(t, err)
	core.AssertEqual(t, 64, len(got))
}

func TestAX7Crypt_SHA256File_Bad(t *core.T) {
	got, err := SHA256File(core.Path(t.TempDir(), "missing.txt"))
	core.AssertError(t, err)
	core.AssertEqual(t, "", got)
}

func TestAX7Crypt_SHA256File_Ugly(t *core.T) {
	path := core.Path(t.TempDir(), "empty.txt")
	core.RequireTrue(t, (&core.Fs{}).New("/").WriteMode(path, "", 0o644).OK)
	got, err := SHA256File(path)
	core.AssertNoError(t, err)
	core.AssertEqual(t, SHA256Sum(nil), got)
}

func TestAX7Crypt_SHA512File_Good(t *core.T) {
	path := core.Path(t.TempDir(), "data.txt")
	core.RequireTrue(t, (&core.Fs{}).New("/").WriteMode(path, "hello", 0o644).OK)
	got, err := SHA512File(path)
	core.AssertNoError(t, err)
	core.AssertEqual(t, 128, len(got))
}

func TestAX7Crypt_SHA512File_Bad(t *core.T) {
	got, err := SHA512File(core.Path(t.TempDir(), "missing.txt"))
	core.AssertError(t, err)
	core.AssertEqual(t, "", got)
}

func TestAX7Crypt_SHA512File_Ugly(t *core.T) {
	path := core.Path(t.TempDir(), "empty.txt")
	core.RequireTrue(t, (&core.Fs{}).New("/").WriteMode(path, "", 0o644).OK)
	got, err := SHA512File(path)
	core.AssertNoError(t, err)
	core.AssertEqual(t, SHA512Sum(nil), got)
}

func TestAX7Crypt_SHA256Sum_Good(t *core.T) {
	got := SHA256Sum([]byte("hello"))
	core.AssertEqual(t, 64, len(got))
	core.AssertNotEqual(t, SHA256Sum([]byte("world")), got)
}

func TestAX7Crypt_SHA256Sum_Bad(t *core.T) {
	got := SHA256Sum(nil)
	core.AssertEqual(t, 64, len(got))
	core.AssertEqual(t, got, SHA256Sum([]byte{}))
}

func TestAX7Crypt_SHA256Sum_Ugly(t *core.T) {
	got := SHA256Sum([]byte{0xff, 0x00})
	core.AssertEqual(t, 64, len(got))
	core.AssertFalse(t, core.Contains(got, " "))
}

func TestAX7Crypt_SHA512Sum_Good(t *core.T) {
	got := SHA512Sum([]byte("hello"))
	core.AssertEqual(t, 128, len(got))
	core.AssertNotEqual(t, SHA512Sum([]byte("world")), got)
}

func TestAX7Crypt_SHA512Sum_Bad(t *core.T) {
	got := SHA512Sum(nil)
	core.AssertEqual(t, 128, len(got))
	core.AssertEqual(t, got, SHA512Sum([]byte{}))
}

func TestAX7Crypt_SHA512Sum_Ugly(t *core.T) {
	got := SHA512Sum([]byte{0xff, 0x00})
	core.AssertEqual(t, 128, len(got))
	core.AssertFalse(t, core.Contains(got, " "))
}
