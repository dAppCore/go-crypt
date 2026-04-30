package crypt

import (
	core "dappco.re/go"
	"dappco.re/go/cli/pkg/cli"
)

func init() {
	cli.RegisterCommands(AddCryptCommands)
}

// AddCryptCommands registers the 'crypt' command group and all subcommands.
// Usage: call AddCryptCommands(...) during the package's normal workflow.
func AddCryptCommands(c *core.Core) {
	c.Command("crypt", core.Command{
		Description: "Cryptographic utilities",
	})

	addHashCommand(c)
	addEncryptCommand(c)
	addKeygenCommand(c)
	addChecksumCommand(c)
}
