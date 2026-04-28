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
