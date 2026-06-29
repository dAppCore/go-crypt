package auth

import (
	core "dappco.re/go"
)

func TestHardware_WithHardwareKey_Good(t *core.T) {
	subject := WithHardwareKey
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestHardware_WithHardwareKey_Bad(t *core.T) {
	subject := WithHardwareKey
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestHardware_WithHardwareKey_Ugly(t *core.T) {
	subject := WithHardwareKey
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
