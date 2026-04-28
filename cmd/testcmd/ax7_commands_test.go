package testcmd

import . "dappco.re/go"

func TestAX7TestCmd_AddTestCommands_Good(t *T) {
	c := New()
	AddTestCommands(c)
	AssertTrue(t, c.Command("test").OK)
}

func TestAX7TestCmd_AddTestCommands_Bad(t *T) {
	c := New()
	result := c.Command("test")
	AssertFalse(t, result.OK)
}

func TestAX7TestCmd_AddTestCommands_Ugly(t *T) {
	c := New()
	AddTestCommands(c)
	AddTestCommands(c)
	AssertTrue(t, c.Command("test").OK)
}
