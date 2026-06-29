package crypt

import (
	core "dappco.re/go"
	"dappco.re/go/cli/pkg/cli"
	"dappco.re/go/crypt/crypt"
	coreio "dappco.re/go/io"
)

// Encrypt command flags
var (
	encryptPassphrase string
	encryptAES        bool
)

func addEncryptCommand(c *core.Core) {
	c.Command("crypt/encrypt", core.Command{
		Description: "Encrypt a file",
		Action: func(opts core.Options) core.Result {
			path := opts.String("_arg")
			if path == "" {
				return cli.Err("encrypt requires a path")
			}
			encryptPassphrase = opts.String("passphrase")
			encryptAES = opts.Bool("aes")
			return runEncrypt(path)
		},
	})
	c.Command("crypt/decrypt", core.Command{
		Description: "Decrypt an encrypted file",
		Action: func(opts core.Options) core.Result {
			path := opts.String("_arg")
			if path == "" {
				return cli.Err("decrypt requires a path")
			}
			encryptPassphrase = opts.String("passphrase")
			encryptAES = opts.Bool("aes")
			return runDecrypt(path)
		},
	})
}

func getPassphrase() core.Result {
	if encryptPassphrase != "" {
		return core.Ok(encryptPassphrase)
	}
	return cli.Prompt("Passphrase", "")
}

func runEncrypt(path string) core.Result {
	pr := getPassphrase()
	if !pr.OK {
		return pr
	}
	passphrase, _ := pr.Value.(string)
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
	return core.Ok(nil)
}

func runDecrypt(path string) core.Result {
	pr := getPassphrase()
	if !pr.OK {
		return pr
	}
	passphrase, _ := pr.Value.(string)
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
	return core.Ok(nil)
}
