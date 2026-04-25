package testcmd

import (
	"os"

	"dappco.re/go/core"
)

func testPrintf(format string, args ...any) {
	_, _ = os.Stdout.WriteString(core.Sprintf(format, args...))
}

func testPrintln() {
	_, _ = os.Stdout.WriteString("\n")
}

func repeatSpaces(n int) string {
	if n <= 0 {
		return ""
	}
	b := core.NewBuilder()
	for range n {
		b.WriteString(" ")
	}
	return b.String()
}
