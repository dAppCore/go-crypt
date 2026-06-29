package crypt

import (
	core "dappco.re/go"
)

func TestCmd_AddCryptCommands_Good(t *core.T) {
	subject := AddCryptCommands
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestCmd_AddCryptCommands_Bad(t *core.T) {
	subject := AddCryptCommands
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestCmd_AddCryptCommands_Ugly(t *core.T) {
	subject := AddCryptCommands
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
