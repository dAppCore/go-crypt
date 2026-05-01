package openpgp

import (
	"bytes"

	framework "dappco.re/go"
)

func ax7Service(t *framework.T) *Service {
	t.Helper()
	c := framework.New()
	v, err := New(c)
	framework.RequireNoError(t, err)
	svc, ok := v.(*Service)
	framework.RequireTrue(t, ok)
	return svc
}

func TestAX7OpenPGP_New_Good(t *framework.T) {
	c := framework.New()
	v, err := New(c)
	framework.AssertNoError(t, err)
	framework.AssertNotNil(t, v)
}

func TestAX7OpenPGP_New_Bad(t *framework.T) {
	v, err := New(nil)
	framework.AssertNoError(t, err)
	framework.AssertNotNil(t, v)
}

func TestAX7OpenPGP_New_Ugly(t *framework.T) {
	v, err := New(framework.New())
	framework.RequireNoError(t, err)
	_, ok := v.(*Service)
	framework.AssertTrue(t, ok)
}

func TestAX7OpenPGP_Service_CreateKeyPair_Good(t *framework.T) {
	svc := ax7Service(t)
	key, err := svc.CreateKeyPair("AX7 User", "secret")
	framework.AssertNoError(t, err)
	framework.AssertContains(t, key, "-----BEGIN PGP PRIVATE KEY BLOCK-----")
}

func TestAX7OpenPGP_Service_CreateKeyPair_Bad(t *framework.T) {
	svc := ax7Service(t)
	key, err := svc.CreateKeyPair("", "")
	framework.AssertNoError(t, err)
	framework.AssertContains(t, key, "-----BEGIN PGP PRIVATE KEY BLOCK-----")
}

func TestAX7OpenPGP_Service_CreateKeyPair_Ugly(t *framework.T) {
	svc := ax7Service(t)
	key, err := svc.CreateKeyPair("AX7 User", "")
	framework.AssertNoError(t, err)
	framework.AssertContains(t, key, "-----BEGIN PGP PRIVATE KEY BLOCK-----")
}

func TestAX7OpenPGP_Service_EncryptPGP_Good(t *framework.T) {
	svc := ax7Service(t)
	key, err := svc.CreateKeyPair("AX7 User", "")
	framework.RequireNoError(t, err)
	var out bytes.Buffer
	armored, err := svc.EncryptPGP(&out, key, "message")
	framework.AssertNoError(t, err)
	framework.AssertContains(t, armored, "-----BEGIN PGP MESSAGE-----")
}

func TestAX7OpenPGP_Service_EncryptPGP_Bad(t *framework.T) {
	svc := ax7Service(t)
	var out bytes.Buffer
	armored, err := svc.EncryptPGP(&out, "not-a-key", "message")
	framework.AssertError(t, err)
	framework.AssertEqual(t, "", armored)
}

func TestAX7OpenPGP_Service_EncryptPGP_Ugly(t *framework.T) {
	svc := ax7Service(t)
	key, err := svc.CreateKeyPair("AX7 User", "")
	framework.RequireNoError(t, err)
	var out bytes.Buffer
	armored, err := svc.EncryptPGP(&out, key, "")
	framework.AssertNoError(t, err)
	framework.AssertContains(t, armored, "-----BEGIN PGP MESSAGE-----")
}

func TestAX7OpenPGP_Service_DecryptPGP_Good(t *framework.T) {
	svc := ax7Service(t)
	key, err := svc.CreateKeyPair("AX7 User", "secret")
	framework.RequireNoError(t, err)
	var out bytes.Buffer
	armored, err := svc.EncryptPGP(&out, key, "message")
	framework.RequireNoError(t, err)
	plaintext, err := svc.DecryptPGP(key, armored, "secret")
	framework.AssertNoError(t, err)
	framework.AssertEqual(t, "message", plaintext)
}

func TestAX7OpenPGP_Service_DecryptPGP_Bad(t *framework.T) {
	svc := ax7Service(t)
	plaintext, err := svc.DecryptPGP("not-a-key", "not-a-message", "")
	framework.AssertError(t, err)
	framework.AssertEqual(t, "", plaintext)
}

func TestAX7OpenPGP_Service_DecryptPGP_Ugly(t *framework.T) {
	svc := ax7Service(t)
	key, err := svc.CreateKeyPair("AX7 User", "secret")
	framework.RequireNoError(t, err)
	var out bytes.Buffer
	armored, err := svc.EncryptPGP(&out, key, "message")
	framework.RequireNoError(t, err)
	plaintext, err := svc.DecryptPGP(key, armored, "wrong")
	framework.AssertError(t, err)
	framework.AssertEqual(t, "", plaintext)
}

func TestAX7OpenPGP_Service_HandleIPCEvents_Good(t *framework.T) {
	c := framework.New()
	svc := ax7Service(t)
	err := svc.HandleIPCEvents(c, map[string]any{"action": "openpgp.create_key_pair", "name": "AX7"})
	framework.AssertNoError(t, err)
	framework.AssertNotNil(t, svc)
}

func TestAX7OpenPGP_Service_HandleIPCEvents_Bad(t *framework.T) {
	c := framework.New()
	svc := ax7Service(t)
	err := svc.HandleIPCEvents(c, map[string]any{"action": "unknown"})
	framework.AssertNoError(t, err)
	framework.AssertNotNil(t, svc)
}

func TestAX7OpenPGP_Service_HandleIPCEvents_Ugly(t *framework.T) {
	c := framework.New()
	svc := ax7Service(t)
	err := svc.HandleIPCEvents(c, "not-a-map")
	framework.AssertNoError(t, err)
	framework.AssertNotNil(t, svc)
}
