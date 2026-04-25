package crypt

import (
	"crypto/rand"
<<<<<<< HEAD
	"encoding/base64"
	"encoding/hex"

	core "dappco.re/go/core"
	"dappco.re/go/cli/pkg/cli"
=======

	"dappco.re/go/core"
	"dappco.re/go/crypt/internal/corecompat"
	"forge.lthn.ai/core/cli/pkg/cli"
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
)

// Keygen command flags
var (
	keygenLength int
	keygenHex    bool
	keygenBase64 bool
)

func addKeygenCommand(parent *cli.Command) {
	keygenCmd := cli.NewCommand("keygen", "Generate a random cryptographic key", "", func(cmd *cli.Command, args []string) error {
		return runKeygen()
	})

	cli.IntFlag(keygenCmd, &keygenLength, "length", "l", 32, "Key length in bytes")
	cli.BoolFlag(keygenCmd, &keygenHex, "hex", "", false, "Output as hex string")
	cli.BoolFlag(keygenCmd, &keygenBase64, "base64", "", false, "Output as base64 string")

	parent.AddCommand(keygenCmd)
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
<<<<<<< HEAD
		core.Println(hex.EncodeToString(key))
	case keygenBase64:
		core.Println(base64.StdEncoding.EncodeToString(key))
	default:
		// Default to hex output
		core.Println(hex.EncodeToString(key))
=======
		core.Print(nil, "%s", corecompat.HexEncode(key))
	case keygenBase64:
		core.Print(nil, "%s", corecompat.Base64Encode(key))
	default:
		// Default to hex output
		core.Print(nil, "%s", corecompat.HexEncode(key))
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
	}

	return nil
}
