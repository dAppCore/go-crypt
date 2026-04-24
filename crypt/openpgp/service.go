package openpgp

import (
	"bytes"
	"crypto"
	goio "io"

	framework "dappco.re/go/core"
	coreerr "dappco.re/go/log"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Service provides OpenPGP cryptographic operations.
// Usage: use Service with the other exported helpers in this package.
type Service struct {
	core *framework.Core
}

// New creates a new OpenPGP service instance.
// Usage: call New(...) to create a ready-to-use value.
func New(c *framework.Core) (any, error) {
	return &Service{core: c}, nil
}

// CreateKeyPair generates a new RSA-4096 PGP keypair.
// Returns the armored private key string.
// Usage: call CreateKeyPair(...) during the package's normal workflow.
func (s *Service) CreateKeyPair(name, passphrase string) (string, error) {
	config := &packet.Config{
		Algorithm:     packet.PubKeyAlgoRSA,
		RSABits:       4096,
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}

	entity, err := openpgp.NewEntity(name, "Workspace Key", "", config)
	if err != nil {
		return "", coreerr.E("openpgp.CreateKeyPair", "failed to create entity", err)
	}

	// Encrypt private key if passphrase is provided
	if passphrase != "" {
		err = entity.PrivateKey.Encrypt([]byte(passphrase))
		if err != nil {
			return "", coreerr.E("openpgp.CreateKeyPair", "failed to encrypt private key", err)
		}
		for _, subkey := range entity.Subkeys {
			err = subkey.PrivateKey.Encrypt([]byte(passphrase))
			if err != nil {
				return "", coreerr.E("openpgp.CreateKeyPair", "failed to encrypt subkey", err)
			}
		}
	}

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", coreerr.E("openpgp.CreateKeyPair", "failed to create armor encoder", err)
	}

	// Manual serialisation to avoid panic from re-signing encrypted keys
	err = serializeEntity(w, entity)
	if err != nil {
		w.Close()
		return "", coreerr.E("openpgp.CreateKeyPair", "failed to serialise private key", err)
	}
	w.Close()

	return buf.String(), nil
}

// serializeEntity manually serialises an OpenPGP entity to avoid re-signing.
func serializeEntity(w goio.Writer, e *openpgp.Entity) error {
	err := e.PrivateKey.Serialize(w)
	if err != nil {
		return err
	}
	for _, ident := range e.Identities {
		err = ident.UserId.Serialize(w)
		if err != nil {
			return err
		}
		err = ident.SelfSignature.Serialize(w)
		if err != nil {
			return err
		}
	}
	for _, subkey := range e.Subkeys {
		err = subkey.PrivateKey.Serialize(w)
		if err != nil {
			return err
		}
		err = subkey.Sig.Serialize(w)
		if err != nil {
			return err
		}
	}
	return nil
}

// EncryptPGP encrypts data for a recipient identified by their public key (armored string in recipientPath).
// The encrypted data is written to the provided writer and also returned as an armored string.
// Usage: call EncryptPGP(...) during the package's normal workflow.
func (s *Service) EncryptPGP(writer goio.Writer, recipientPath, data string, opts ...any) (string, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(framework.NewReader(recipientPath))
	if err != nil {
		return "", coreerr.E("openpgp.EncryptPGP", "failed to read recipient key", err)
	}

	var armoredBuf bytes.Buffer
	armoredWriter, err := armor.Encode(&armoredBuf, "PGP MESSAGE", nil)
	if err != nil {
		return "", coreerr.E("openpgp.EncryptPGP", "failed to create armor encoder", err)
	}

	// MultiWriter to write to both the provided writer and our armored buffer
	mw := goio.MultiWriter(writer, armoredWriter)

	w, err := openpgp.Encrypt(mw, entityList, nil, nil, nil)
	if err != nil {
		armoredWriter.Close()
		return "", coreerr.E("openpgp.EncryptPGP", "failed to start encryption", err)
	}

	_, err = goio.WriteString(w, data)
	if err != nil {
		w.Close()
		armoredWriter.Close()
		return "", coreerr.E("openpgp.EncryptPGP", "failed to write data", err)
	}

	w.Close()
	armoredWriter.Close()

	return armoredBuf.String(), nil
}

// DecryptPGP decrypts a PGP message using the provided armored private key and passphrase.
// Usage: call DecryptPGP(...) during the package's normal workflow.
func (s *Service) DecryptPGP(privateKey, message, passphrase string, opts ...any) (string, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(framework.NewReader(privateKey))
	if err != nil {
		return "", coreerr.E("openpgp.DecryptPGP", "failed to read private key", err)
	}

	entity := entityList[0]
	if entity.PrivateKey.Encrypted {
		err = entity.PrivateKey.Decrypt([]byte(passphrase))
		if err != nil {
			return "", coreerr.E("openpgp.DecryptPGP", "failed to decrypt private key", err)
		}
		for _, subkey := range entity.Subkeys {
			_ = subkey.PrivateKey.Decrypt([]byte(passphrase))
		}
	}

	// Decrypt armored message
	block, err := armor.Decode(framework.NewReader(message))
	if err != nil {
		return "", coreerr.E("openpgp.DecryptPGP", "failed to decode armored message", err)
	}

	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return "", coreerr.E("openpgp.DecryptPGP", "failed to read message", err)
	}

	var buf bytes.Buffer
	_, err = goio.Copy(&buf, md.UnverifiedBody)
	if err != nil {
		return "", coreerr.E("openpgp.DecryptPGP", "failed to read decrypted body", err)
	}

	return buf.String(), nil
}

// HandleIPCEvents handles PGP-related IPC messages.
// Usage: call HandleIPCEvents(...) during the package's normal workflow.
func (s *Service) HandleIPCEvents(c *framework.Core, msg framework.Message) error {
	switch m := msg.(type) {
	case map[string]any:
		action, _ := m["action"].(string)
		switch action {
		case "openpgp.create_key_pair":
			name, _ := m["name"].(string)
			passphrase, _ := m["passphrase"].(string)
			_, err := s.CreateKeyPair(name, passphrase)
			return err
		}
	}
	return nil
}
