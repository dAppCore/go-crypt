package crypt

import . "dappco.re/go"

func TestAX7CryptCmd_AddCryptCommands_Good(t *T) {
	c := New()
	AddCryptCommands(c)
	AssertTrue(t, c.Command("crypt/hash").OK)
	AssertTrue(t, c.Command("crypt/checksum").OK)
}

func TestAX7CryptCmd_AddCryptCommands_Bad(t *T) {
	c := New()
	AddCryptCommands(c)
	result := c.Command("crypt/missing")
	AssertFalse(t, result.OK)
}

func TestAX7CryptCmd_AddCryptCommands_Ugly(t *T) {
	c := New()
	AddCryptCommands(c)
	AddCryptCommands(c)
	AssertTrue(t, c.Command("crypt/keygen").OK)
}
