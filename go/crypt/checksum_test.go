package crypt

import (
	"testing"

	core "dappco.re/go"
)

func TestChecksum_SHA256Sum_Good(t *testing.T) {
	data := []byte("hello")
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

	result := SHA256Sum(data)
	wantEqual(t, expected, result)
}

func TestChecksum_SHA512Sum_Good(t *testing.T) {
	data := []byte("hello")
	expected := "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"

	result := SHA512Sum(data)
	wantEqual(t, expected, result)
}

// --- Phase 0 Additions ---

// TestChecksum_SHA256File_Good verifies checksum of an empty file.
func TestChecksum_SHA256File_Good(t *testing.T) {
	tmpDir := t.TempDir()
	emptyFile := core.Path(tmpDir, "empty.bin")
	writeResult := (&core.Fs{}).New("/").WriteMode(emptyFile, "", 0o644)
	mustTrue(t, writeResult.OK, testMessagef("failed to write empty test file: %v", writeResult.Value))

	hash, err := SHA256File(emptyFile)
	mustNoError(t, err)
	// SHA-256 of empty input is the well-known constant
	wantEqual(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash)
}

// TestChecksum_SHA512File_Good verifies SHA-512 checksum of an empty file.
func TestChecksum_SHA512File_Good(t *testing.T) {
	tmpDir := t.TempDir()
	emptyFile := core.Path(tmpDir, "empty.bin")
	writeResult := (&core.Fs{}).New("/").WriteMode(emptyFile, "", 0o644)
	mustTrue(t, writeResult.OK, testMessagef("failed to write empty test file: %v", writeResult.Value))

	hash, err := SHA512File(emptyFile)
	mustNoError(t, err)
	wantEqual(t, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", hash)
}

// TestChecksum_SHA256FileNonExistent_Bad verifies error on non-existent file.
func TestChecksum_SHA256FileNonExistent_Bad(t *testing.T) {
	_, err := SHA256File("/nonexistent/path/to/file.bin")
	wantError(t, err)
	wantContains(t, err.Error(), "failed to open file")
}

// TestChecksum_SHA512FileNonExistent_Bad verifies error on non-existent file.
func TestChecksum_SHA512FileNonExistent_Bad(t *testing.T) {
	_, err := SHA512File("/nonexistent/path/to/file.bin")
	wantError(t, err)
	wantContains(t, err.Error(), "failed to open file")
}

// TestChecksum_SHA256FileWithContent_Good verifies checksum of a file with known content.
func TestChecksum_SHA256FileWithContent_Good(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := core.Path(tmpDir, "test.txt")
	writeResult := (&core.Fs{}).New("/").WriteMode(testFile, "hello", 0o644)
	mustTrue(t, writeResult.OK, testMessagef("failed to write checksum fixture: %v", writeResult.Value))

	hash, err := SHA256File(testFile)
	mustNoError(t, err)
	// Must match SHA256Sum("hello")
	wantEqual(t, SHA256Sum([]byte("hello")), hash)
}
