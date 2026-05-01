package corecompat

import core "dappco.re/go"

func TestAX7Corecompat_HexEncode_Good(t *core.T) {
	got := HexEncode([]byte{0x0f, 0xa0})
	core.AssertEqual(t, "0fa0", got)
	core.AssertEqual(t, 4, len(got))
}

func TestAX7Corecompat_HexEncode_Bad(t *core.T) {
	got := HexEncode(nil)
	core.AssertEqual(t, "", got)
	core.AssertEqual(t, 0, len(got))
}

func TestAX7Corecompat_HexEncode_Ugly(t *core.T) {
	got := HexEncode([]byte{0x00, 0xff})
	core.AssertEqual(t, "00ff", got)
	core.AssertFalse(t, core.Contains(got, " "))
}

func TestAX7Corecompat_Base64Encode_Good(t *core.T) {
	got := Base64Encode([]byte("agent"))
	core.AssertEqual(t, "YWdlbnQ=", got)
	core.AssertTrue(t, core.HasSuffix(got, "="))
}

func TestAX7Corecompat_Base64Encode_Bad(t *core.T) {
	got := Base64Encode(nil)
	core.AssertEqual(t, "", got)
	core.AssertEqual(t, 0, len(got))
}

func TestAX7Corecompat_Base64Encode_Ugly(t *core.T) {
	got := Base64Encode([]byte{0xff})
	core.AssertEqual(t, "/w==", got)
	core.AssertTrue(t, core.HasSuffix(got, "=="))
}

func TestAX7Corecompat_Base64Decode_Good(t *core.T) {
	got, err := Base64Decode("YWdlbnQ=")
	core.AssertNoError(t, err)
	core.AssertEqual(t, []byte("agent"), got)
}

func TestAX7Corecompat_Base64Decode_Bad(t *core.T) {
	got, err := Base64Decode("not padded")
	core.AssertError(t, err)
	core.AssertNil(t, got)
}

func TestAX7Corecompat_Base64Decode_Ugly(t *core.T) {
	got, err := Base64Decode("")
	core.AssertNoError(t, err)
	core.AssertEqual(t, []byte{}, got)
}
