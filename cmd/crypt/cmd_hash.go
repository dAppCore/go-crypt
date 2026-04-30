package crypt

import (
	core "dappco.re/go"
	"dappco.re/go/cli/pkg/cli"
	"dappco.re/go/crypt/crypt"

	"golang.org/x/crypto/bcrypt"
)

// Hash command flags
var (
	hashBcrypt bool
	hashVerify string
)

func addHashCommand(c *core.Core) {
	c.Command("crypt/hash", core.Command{
		Description: "Hash a password with Argon2id or bcrypt",
		Action: func(opts core.Options) core.Result {
			input := opts.String("_arg")
			if input == "" {
				return core.Fail(cli.Err("hash requires input"))
			}
			hashBcrypt = opts.Bool("bcrypt")
			hashVerify = opts.String("verify")
			return core.ResultOf(nil, runHash(input))
		},
	})
}

func runHash(input string) error {
	// Verify mode
	if hashVerify != "" {
		return runHashVerify(input, hashVerify)
	}

	// Hash mode
	if hashBcrypt {
		hash, err := crypt.HashBcrypt(input, bcrypt.DefaultCost)
		if err != nil {
			return cli.Wrap(err, "failed to hash password")
		}
		core.Println(hash)
		return nil
	}

	hash, err := crypt.HashPassword(input)
	if err != nil {
		return cli.Wrap(err, "failed to hash password")
	}
	core.Println(hash)
	return nil
}

func runHashVerify(input, hash string) error {
	var match bool
	var err error

	if hashBcrypt {
		match, err = crypt.VerifyBcrypt(input, hash)
	} else {
		match, err = crypt.VerifyPassword(input, hash)
	}

	if err != nil {
		return cli.Wrap(err, "failed to verify hash")
	}

	if match {
		cli.Success("Password matches hash")
		return nil
	}

	cli.Error("Password does not match hash")
	return cli.Err("hash verification failed")
}
