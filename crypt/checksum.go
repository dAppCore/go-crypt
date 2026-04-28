package crypt

import (
	stdcrypto "crypto"
	"io"

	core "dappco.re/go"
	"dappco.re/go/crypt/internal/corecompat"
	coreerr "dappco.re/go/log"

	"forge.lthn.ai/Snider/Enchantrix/pkg/enchantrix"
)

// SHA256File computes the SHA-256 checksum of a file and returns it as a hex string.
// Usage: call SHA256File(...) during the package's normal workflow.
func SHA256File(path string) (string, error) {
	openResult := (&core.Fs{}).New("/").Open(path)
	if !openResult.OK {
		err, _ := openResult.Value.(error)
		return "", coreerr.E("crypt.SHA256File", "failed to open file", err)
	}
	f := openResult.Value.(io.ReadCloser)
	defer func() {
		if err := f.Close(); err != nil {
			core.Print(nil, "crypt.SHA256File: close failed: %v", err)
		}
	}()

	data, err := io.ReadAll(f)
	if err != nil {
		return "", coreerr.E("crypt.SHA256File", "failed to read file", err)
	}

	return enchantrixHexHash(stdcrypto.SHA256, data)
}

// SHA512File computes the SHA-512 checksum of a file and returns it as a hex string.
// Usage: call SHA512File(...) during the package's normal workflow.
func SHA512File(path string) (string, error) {
	openResult := (&core.Fs{}).New("/").Open(path)
	if !openResult.OK {
		err, _ := openResult.Value.(error)
		return "", coreerr.E("crypt.SHA512File", "failed to open file", err)
	}
	f := openResult.Value.(io.ReadCloser)
	defer func() {
		if err := f.Close(); err != nil {
			core.Print(nil, "crypt.SHA512File: close failed: %v", err)
		}
	}()

	data, err := io.ReadAll(f)
	if err != nil {
		return "", coreerr.E("crypt.SHA512File", "failed to read file", err)
	}

	return enchantrixHexHash(stdcrypto.SHA512, data)
}

// SHA256Sum computes the SHA-256 checksum of data and returns it as a hex string.
// Usage: call SHA256Sum(...) during the package's normal workflow.
func SHA256Sum(data []byte) string {
	return mustEnchantrixHexHash(stdcrypto.SHA256, data)
}

// SHA512Sum computes the SHA-512 checksum of data and returns it as a hex string.
// Usage: call SHA512Sum(...) during the package's normal workflow.
func SHA512Sum(data []byte) string {
	return mustEnchantrixHexHash(stdcrypto.SHA512, data)
}

func enchantrixHexHash(hash stdcrypto.Hash, data []byte) (string, error) {
	sum, err := enchantrix.NewHashSigil(hash).In(data)
	if err != nil {
		return "", err
	}
	return corecompat.HexEncode(sum), nil
}

func mustEnchantrixHexHash(hash stdcrypto.Hash, data []byte) string {
	sum, err := enchantrixHexHash(hash, data)
	if err != nil {
		return ""
	}
	return sum
}
