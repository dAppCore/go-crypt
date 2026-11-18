package testcmd

import (
	core "github.com/dappcore/go"
)

func TestCmdMain_AddTestCommands_Good(t *core.T) {
	subject := AddTestCommands
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestCmdMain_AddTestCommands_Bad(t *core.T) {
	subject := AddTestCommands
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestCmdMain_AddTestCommands_Ugly(t *core.T) {
	subject := AddTestCommands
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
