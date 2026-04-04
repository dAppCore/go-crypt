package crypt

import (
	core "dappco.re/go/core"
	"dappco.re/go/core/crypt/crypt"
	coreio "dappco.re/go/core/io"
	"forge.lthn.ai/core/cli/pkg/cli"
)

// Encrypt command flags
var (
	encryptPassphrase string
	encryptAES        bool
)

func addEncryptCommand(parent *cli.Command) {
	encryptCmd := cli.NewCommand("encrypt", "Encrypt a file", "", func(cmd *cli.Command, args []string) error {
		return runEncrypt(args[0])
	})
	encryptCmd.Args = cli.ExactArgs(1)

	cli.StringFlag(encryptCmd, &encryptPassphrase, "passphrase", "p", "", "Passphrase (prompted if not given)")
	cli.BoolFlag(encryptCmd, &encryptAES, "aes", "", false, "Use AES-256-GCM instead of ChaCha20-Poly1305")

	parent.AddCommand(encryptCmd)

	decryptCmd := cli.NewCommand("decrypt", "Decrypt an encrypted file", "", func(cmd *cli.Command, args []string) error {
		return runDecrypt(args[0])
	})
	decryptCmd.Args = cli.ExactArgs(1)

	cli.StringFlag(decryptCmd, &encryptPassphrase, "passphrase", "p", "", "Passphrase (prompted if not given)")
	cli.BoolFlag(decryptCmd, &encryptAES, "aes", "", false, "Use AES-256-GCM instead of ChaCha20-Poly1305")

	parent.AddCommand(decryptCmd)
}

func getPassphrase() (string, error) {
	if encryptPassphrase != "" {
		return encryptPassphrase, nil
	}
	return cli.Prompt("Passphrase", "")
}

func runEncrypt(path string) error {
	passphrase, err := getPassphrase()
	if err != nil {
		return cli.Wrap(err, "failed to read passphrase")
	}
	if passphrase == "" {
		return cli.Err("passphrase cannot be empty")
	}

	raw, err := coreio.Local.Read(path)
	if err != nil {
		return cli.Wrap(err, "failed to read file")
	}
	data := []byte(raw)

	var encrypted []byte
	if encryptAES {
		encrypted, err = crypt.EncryptAES(data, []byte(passphrase))
	} else {
		encrypted, err = crypt.Encrypt(data, []byte(passphrase))
	}
	if err != nil {
		return cli.Wrap(err, "failed to encrypt")
	}

	outPath := path + ".enc"
	if err := coreio.Local.Write(outPath, string(encrypted)); err != nil {
		return cli.Wrap(err, "failed to write encrypted file")
	}

	cli.Success(core.Sprintf("Encrypted %s -> %s", path, outPath))
	return nil
}

func runDecrypt(path string) error {
	passphrase, err := getPassphrase()
	if err != nil {
		return cli.Wrap(err, "failed to read passphrase")
	}
	if passphrase == "" {
		return cli.Err("passphrase cannot be empty")
	}

	raw, err := coreio.Local.Read(path)
	if err != nil {
		return cli.Wrap(err, "failed to read file")
	}
	data := []byte(raw)

	var decrypted []byte
	if encryptAES {
		decrypted, err = crypt.DecryptAES(data, []byte(passphrase))
	} else {
		decrypted, err = crypt.Decrypt(data, []byte(passphrase))
	}
	if err != nil {
		return cli.Wrap(err, "failed to decrypt")
	}

	outPath := core.TrimSuffix(path, ".enc")
	if outPath == path {
		outPath = path + ".dec"
	}

	if err := coreio.Local.Write(outPath, string(decrypted)); err != nil {
		return cli.Wrap(err, "failed to write decrypted file")
	}

	cli.Success(core.Sprintf("Decrypted %s -> %s", path, outPath))
	return nil
}
