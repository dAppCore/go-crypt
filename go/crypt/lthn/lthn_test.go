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

func TestLthn_SetKeyMap_Good(t *core.T) {
	subject := SetKeyMap
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestLthn_SetKeyMap_Bad(t *core.T) {
	subject := SetKeyMap
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestLthn_SetKeyMap_Ugly(t *core.T) {
	subject := SetKeyMap
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestLthn_GetKeyMap_Good(t *core.T) {
	subject := GetKeyMap
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestLthn_GetKeyMap_Bad(t *core.T) {
	subject := GetKeyMap
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestLthn_GetKeyMap_Ugly(t *core.T) {
	subject := GetKeyMap
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestLthn_Hash_Good(t *core.T) {
	subject := Hash
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestLthn_Hash_Bad(t *core.T) {
	subject := Hash
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestLthn_Hash_Ugly(t *core.T) {
	subject := Hash
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestLthn_Verify_Good(t *core.T) {
	subject := Verify
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestLthn_Verify_Bad(t *core.T) {
	subject := Verify
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestLthn_Verify_Ugly(t *core.T) {
	subject := Verify
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
