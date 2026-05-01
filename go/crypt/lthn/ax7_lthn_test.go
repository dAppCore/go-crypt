package lthn

import . "dappco.re/go"

func preserveKeyMap(t *T) {
	t.Helper()
	original := GetKeyMap()
	clone := make(map[rune]rune, len(original))
	for k, v := range original {
		clone[k] = v
	}
	t.Cleanup(func() { SetKeyMap(clone) })
}

func TestAX7LTHN_SetKeyMap_Good(t *T) {
	preserveKeyMap(t)
	SetKeyMap(map[rune]rune{'x': 'y'})
	AssertEqual(t, map[rune]rune{'x': 'y'}, GetKeyMap())
}

func TestAX7LTHN_SetKeyMap_Bad(t *T) {
	preserveKeyMap(t)
	SetKeyMap(nil)
	AssertNil(t, GetKeyMap())
}

func TestAX7LTHN_SetKeyMap_Ugly(t *T) {
	preserveKeyMap(t)
	custom := map[rune]rune{'a': 'z'}
	SetKeyMap(custom)
	custom['b'] = 'y'
	AssertEqual(t, 'y', GetKeyMap()['b'])
}

func TestAX7LTHN_GetKeyMap_Good(t *T) {
	preserveKeyMap(t)
	SetKeyMap(map[rune]rune{'o': '0'})
	AssertEqual(t, '0', GetKeyMap()['o'])
}

func TestAX7LTHN_GetKeyMap_Bad(t *T) {
	preserveKeyMap(t)
	SetKeyMap(nil)
	AssertNil(t, GetKeyMap())
}

func TestAX7LTHN_GetKeyMap_Ugly(t *T) {
	preserveKeyMap(t)
	SetKeyMap(map[rune]rune{})
	AssertEqual(t, 0, len(GetKeyMap()))
}

func TestAX7LTHN_Hash_Good(t *T) {
	got := Hash("agent")
	AssertEqual(t, 64, len(got))
	AssertTrue(t, Verify("agent", got))
}

func TestAX7LTHN_Hash_Bad(t *T) {
	left := Hash("agent")
	right := Hash("other")
	AssertNotEqual(t, left, right)
}

func TestAX7LTHN_Hash_Ugly(t *T) {
	got := Hash("")
	AssertEqual(t, 64, len(got))
	AssertTrue(t, Verify("", got))
}

func TestAX7LTHN_Verify_Good(t *T) {
	hash := Hash("agent")
	AssertTrue(t, Verify("agent", hash))
	AssertEqual(t, 64, len(hash))
}

func TestAX7LTHN_Verify_Bad(t *T) {
	hash := Hash("agent")
	AssertFalse(t, Verify("wrong", hash))
	AssertEqual(t, 64, len(hash))
}

func TestAX7LTHN_Verify_Ugly(t *T) {
	hash := Hash("")
	AssertFalse(t, Verify("agent", hash))
	AssertFalse(t, Verify("agent", ""))
	AssertFalse(t, Verify("", "not-a-sha256"))
}
