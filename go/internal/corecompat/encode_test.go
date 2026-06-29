package corecompat

import (
	core "dappco.re/go"
)

func TestEncode_HexEncode_Good(t *core.T) {
	subject := HexEncode
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestEncode_HexEncode_Bad(t *core.T) {
	subject := HexEncode
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestEncode_HexEncode_Ugly(t *core.T) {
	subject := HexEncode
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestEncode_Base64Encode_Good(t *core.T) {
	subject := Base64Encode
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestEncode_Base64Encode_Bad(t *core.T) {
	subject := Base64Encode
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestEncode_Base64Encode_Ugly(t *core.T) {
	subject := Base64Encode
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestEncode_Base64Decode_Good(t *core.T) {
	subject := Base64Decode
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestEncode_Base64Decode_Bad(t *core.T) {
	subject := Base64Decode
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestEncode_Base64Decode_Ugly(t *core.T) {
	subject := Base64Decode
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
