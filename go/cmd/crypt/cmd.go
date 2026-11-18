package crypt

import (
	core "github.com/dappcore/go"
	"github.com/dappcore/cli/go/pkg/cli"
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
