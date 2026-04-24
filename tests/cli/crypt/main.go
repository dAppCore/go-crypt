package main

import (
	"bytes"
	"fmt"
	"os"

	"dappco.re/go/core/crypt/crypt"
)

func main() {
	plaintext := []byte("hello world")
	passphrase := []byte("ax-10-cli-artifact-validation")

	ciphertext, err := crypt.Encrypt(plaintext, passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	decrypted, err := crypt.Decrypt(ciphertext, passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if !bytes.Equal(decrypted, plaintext) {
		fmt.Fprintln(os.Stderr, "decrypted plaintext does not match original plaintext")
		os.Exit(1)
	}
}
