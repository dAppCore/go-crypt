package crypt

import (
	"testing"

	core "dappco.re/go/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSHA256Sum_Good(t *testing.T) {
	data := []byte("hello")
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

	result := SHA256Sum(data)
	assert.Equal(t, expected, result)
}

func TestSHA512Sum_Good(t *testing.T) {
	data := []byte("hello")
	expected := "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"

	result := SHA512Sum(data)
	assert.Equal(t, expected, result)
}

// --- Phase 0 Additions ---

// TestSHA256FileEmpty_Good verifies checksum of an empty file.
func TestSHA256FileEmpty_Good(t *testing.T) {
	tmpDir := t.TempDir()
	emptyFile := core.Path(tmpDir, "empty.bin")
	writeResult := (&core.Fs{}).New("/").WriteMode(emptyFile, "", 0o644)
	require.Truef(t, writeResult.OK, "failed to write empty test file: %v", writeResult.Value)

	hash, err := SHA256File(emptyFile)
	require.NoError(t, err)
	// SHA-256 of empty input is the well-known constant
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash)
}

// TestSHA512FileEmpty_Good verifies SHA-512 checksum of an empty file.
func TestSHA512FileEmpty_Good(t *testing.T) {
	tmpDir := t.TempDir()
	emptyFile := core.Path(tmpDir, "empty.bin")
	writeResult := (&core.Fs{}).New("/").WriteMode(emptyFile, "", 0o644)
	require.Truef(t, writeResult.OK, "failed to write empty test file: %v", writeResult.Value)

	hash, err := SHA512File(emptyFile)
	require.NoError(t, err)
	assert.Equal(t, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", hash)
}

// TestSHA256FileNonExistent_Bad verifies error on non-existent file.
func TestSHA256FileNonExistent_Bad(t *testing.T) {
	_, err := SHA256File("/nonexistent/path/to/file.bin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

// TestSHA512FileNonExistent_Bad verifies error on non-existent file.
func TestSHA512FileNonExistent_Bad(t *testing.T) {
	_, err := SHA512File("/nonexistent/path/to/file.bin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

// TestSHA256FileWithContent_Good verifies checksum of a file with known content.
func TestSHA256FileWithContent_Good(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := core.Path(tmpDir, "test.txt")
	writeResult := (&core.Fs{}).New("/").WriteMode(testFile, "hello", 0o644)
	require.Truef(t, writeResult.OK, "failed to write checksum fixture: %v", writeResult.Value)

	hash, err := SHA256File(testFile)
	require.NoError(t, err)
	// Must match SHA256Sum("hello")
	assert.Equal(t, SHA256Sum([]byte("hello")), hash)
}
