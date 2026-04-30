package crypt

import (
	"crypto/rand"

	core "dappco.re/go"
	"dappco.re/go/cli/pkg/cli"
	"dappco.re/go/crypt/internal/corecompat"
)

// Keygen command flags
var (
	keygenLength int
	keygenHex    bool
	keygenBase64 bool
)

func addKeygenCommand(c *core.Core) {
	c.Command("crypt/keygen", core.Command{
		Description: "Generate a random cryptographic key",
		Action: func(opts core.Options) core.Result {
			keygenLength = opts.Int("length")
			if keygenLength == 0 {
				keygenLength = 32
			}
			keygenHex = opts.Bool("hex")
			keygenBase64 = opts.Bool("base64")
			return core.ResultOf(nil, runKeygen())
		},
	})
}

func runKeygen() error {
	if keygenHex && keygenBase64 {
		return cli.Err("--hex and --base64 are mutually exclusive")
	}
	if keygenLength <= 0 || keygenLength > 1024 {
		return cli.Err("key length must be between 1 and 1024 bytes")
	}

	key := make([]byte, keygenLength)
	if _, err := rand.Read(key); err != nil {
		return cli.Wrap(err, "failed to generate random key")
	}

	switch {
	case keygenHex:
		core.Print(nil, "%s", corecompat.HexEncode(key))
	case keygenBase64:
		core.Print(nil, "%s", corecompat.Base64Encode(key))
	default:
		// Default to hex output
		core.Print(nil, "%s", corecompat.HexEncode(key))
	}

	return nil
}
