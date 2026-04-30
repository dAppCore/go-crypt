// Package testcmd provides test running commands.
//
// Note: Package named testcmd to avoid conflict with Go's test package.
package testcmd

import (
	core "dappco.re/go"
	"dappco.re/go/cli/pkg/cli"
	"dappco.re/go/i18n"
)

// Style aliases from shared
var (
	testHeaderStyle  = cli.RepoStyle
	testPassStyle    = cli.SuccessStyle
	testFailStyle    = cli.ErrorStyle
	testSkipStyle    = cli.WarningStyle
	testDimStyle     = cli.DimStyle
	testCovHighStyle = cli.NewStyle().Foreground(cli.ColourGreen500)
	testCovMedStyle  = cli.NewStyle().Foreground(cli.ColourAmber500)
	testCovLowStyle  = cli.NewStyle().Foreground(cli.ColourRed500)
)

// Flag variables for test command.
var (
	testVerbose  bool
	testCoverage bool
	testShort    bool
	testPkg      string
	testRun      string
	testRace     bool
	testJSON     bool
)

// AddTestCommands registers the 'test' command and all subcommands.
// Usage: call AddTestCommands(...) during the package's normal workflow.
func AddTestCommands(c *core.Core) {
	c.Command("test", core.Command{
		Description: i18n.T("cmd.test.short"),
		Action: func(opts core.Options) core.Result {
			testVerbose = opts.Bool("verbose")
			testCoverage = opts.Bool("coverage")
			testShort = opts.Bool("short")
			testPkg = opts.String("pkg")
			testRun = opts.String("run")
			testRace = opts.Bool("race")
			testJSON = opts.Bool("json")
			return core.ResultOf(nil, runTest(testVerbose, testCoverage, testShort, testPkg, testRun, testRace, testJSON))
		},
	})
}
