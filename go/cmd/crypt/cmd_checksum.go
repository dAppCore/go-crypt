package crypt

import (
	core "dappco.re/go"
	"dappco.re/go/cli/pkg/cli"
	"dappco.re/go/crypt/crypt"
)

// Checksum command flags
var (
	checksumSHA512 bool
	checksumVerify string
)

func addChecksumCommand(c *core.Core) {
	c.Command("crypt/checksum", core.Command{
		Description: "Compute file checksum",
		Action: func(opts core.Options) core.Result {
			path := opts.String("_arg")
			if path == "" {
				return core.Fail(cli.Err("checksum requires a path"))
			}
			checksumSHA512 = opts.Bool("sha512")
			checksumVerify = opts.String("verify")
			return core.ResultOf(nil, runChecksum(path))
		},
	})
}

func runChecksum(path string) error {
	var hash string
	var err error

	if checksumSHA512 {
		hash, err = crypt.SHA512File(path)
	} else {
		hash, err = crypt.SHA256File(path)
	}

	if err != nil {
		return cli.Wrap(err, "failed to compute checksum")
	}

	if checksumVerify != "" {
		if hash == checksumVerify {
			cli.Success(core.Sprintf("Checksum matches: %s", core.PathBase(path)))
			return nil
		}
		cli.Error(core.Sprintf("Checksum mismatch: %s", core.PathBase(path)))
		cli.Dim(core.Sprintf("  expected: %s", checksumVerify))
		cli.Dim(core.Sprintf("  got:      %s", hash))
		return cli.Err("checksum verification failed")
	}

	algo := "SHA-256"
	if checksumSHA512 {
		algo = "SHA-512"
	}

	core.Print(nil, "%s  %s  (%s)", hash, path, algo)
	return nil
}
