package corecompat

import (
	"bytes"
	"testing"
)

// TestRoundtrip_HexEncode covers the empty, single-byte, and multi-byte
// cases of HexEncode.
func TestRoundtrip_HexEncode(t *testing.T) {
	if got := HexEncode(nil); got != "" {
		t.Fatalf("HexEncode(nil) = %q, want empty", got)
	}
	if got := HexEncode([]byte{0x00}); got != "00" {
		t.Fatalf("HexEncode(0x00) = %q, want 00", got)
	}
	if got := HexEncode([]byte{0xde, 0xad, 0xbe, 0xef}); got != "deadbeef" {
		t.Fatalf("HexEncode(deadbeef) = %q", got)
	}
}

// TestRoundtrip_Base64 covers every padding length (0/1/2 trailing bytes)
// and confirms encode/decode is lossless across the alphabet.
func TestRoundtrip_Base64(t *testing.T) {
	cases := [][]byte{
		{},
		{0x66},                               // len%3 == 1 -> "==" padding
		{0x66, 0x6f},                         // len%3 == 2 -> "=" padding
		{0x66, 0x6f, 0x6f},                   // len%3 == 0 -> no padding
		{0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72}, // multi-group
		{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9}, // high bytes exercise +// alphabet
		[]byte("the quick brown fox jumps over the lazy dog"),
	}
	for _, in := range cases {
		enc := Base64Encode(in)
		dec, err := Base64Decode(enc)
		if err != nil {
			t.Fatalf("Base64Decode(%q): %v", enc, err)
		}
		if !bytes.Equal(in, dec) {
			t.Fatalf("round-trip mismatch: in=%x dec=%x", in, dec)
		}
	}
}

// TestRoundtrip_Base64Decode_Malformed drives each Base64Decode error
// branch.
func TestRoundtrip_Base64Decode_Malformed(t *testing.T) {
	cases := map[string]string{
		"length not multiple of 4": "abc",
		"invalid first char":       "!bcd",
		"invalid second char":      "a!cd",
		"invalid third char":       "ab!d",
		"invalid fourth char":      "abc!",
		"misplaced pad in third":   "ab=d",     // '=' at idx 2 but idx 3 not '='
		"premature double pad":     "ab==cdef", // pad group not at the end
		"premature single pad":     "abc=defg", // single pad not at the end
	}
	for name, in := range cases {
		if _, err := Base64Decode(in); err == nil {
			t.Fatalf("%s: Base64Decode(%q) should error", name, in)
		}
	}
}

// TestRoundtrip_Base64Value covers every accept branch plus the reject
// default of the alphabet lookup, through Base64Decode of single groups.
func TestRoundtrip_Base64Value(t *testing.T) {
	// Each input is a valid 4-char group whose first two chars sweep the
	// alphabet classes: upper, lower, digit, '+', '/'.
	valid := []string{
		"AAAA", // 'A' upper
		"aaaa", // 'a' lower
		"0000", // '0' digit
		"++++", // '+'
		"////", // '/'
	}
	for _, g := range valid {
		if _, err := Base64Decode(g); err != nil {
			t.Fatalf("Base64Decode(%q) should succeed: %v", g, err)
		}
	}
	// A character outside the alphabet (space) hits the default reject.
	if _, err := Base64Decode("AA A"); err == nil {
		t.Fatal("Base64Decode with an out-of-alphabet char should error")
	}
}
