package lthn

import (
	"sync"
	"testing"
)

func TestLTHN_Hash_Good(t *testing.T) {
	hash := Hash("hello")
	wantNotEmpty(t, hash)
	wantLen(t, hash, 64)
}

func TestLTHN_Verify_Good(t *testing.T) {
	hash := Hash("hello")
	wantTrue(t, Verify("hello", hash))
	wantLen(t, hash, 64)
}

func TestLTHN_Verify_Bad(t *testing.T) {
	hash := Hash("hello")
	wantFalse(t, Verify("world", hash))
	wantNotEmpty(t, hash)
}

func TestLTHN_CreateSalt_Good(t *testing.T) {
	// "hello" reversed: "olleh" -> "0113h"
	expected := "0113h"
	actual := createSalt("hello")
	wantEqual(t, expected, actual, "Salt should be correctly created for 'hello'")
}

func TestLTHN_CreateSalt_Bad(t *testing.T) {
	// Test with an empty string
	expected := ""
	actual := createSalt("")
	wantEqual(t, expected, actual, "Salt for an empty string should be empty")
}

func TestLTHN_CreateSalt_Ugly(t *testing.T) {
	// Test with characters not in the keyMap
	input := "world123"
	// "world123" reversed: "321dlrow" -> "e2ld1r0w"
	expected := "e2ld1r0w"
	actual := createSalt(input)
	wantEqual(t, expected, actual, "Salt should handle characters not in the keyMap")

	// Test with only characters in the keyMap
	input = "oleta"
	// "oleta" reversed: "atelo" -> "47310"
	expected = "47310"
	actual = createSalt(input)
	wantEqual(t, expected, actual, "Salt should correctly handle strings with only keyMap characters")
}

var testKeyMapMu sync.Mutex

func TestLTHN_SetKeyMap_Good(t *testing.T) {
	testKeyMapMu.Lock()
	originalKeyMap := GetKeyMap()
	t.Cleanup(func() {
		SetKeyMap(originalKeyMap)
		testKeyMapMu.Unlock()
	})

	newKeyMap := map[rune]rune{
		'a': 'b',
	}
	SetKeyMap(newKeyMap)
	wantEqual(t, newKeyMap, GetKeyMap())
}
