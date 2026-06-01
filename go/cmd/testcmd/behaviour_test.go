package testcmd

import (
	"testing"

	core "dappco.re/go"
)

// TestBehaviour_ParseTestOutput_Cached parses both cached and timed ok
// lines plus a trailing standalone coverage line that back-fills the
// most recent package without coverage.
func TestBehaviour_ParseTestOutput_Cached(t *testing.T) {
	output := `ok  	dappco.re/go/pkg/timed	0.250s	coverage: 73.8% of statements
ok  	dappco.re/go/pkg/cached	(cached)	coverage: 91.2% of statements
ok  	dappco.re/go/pkg/nocov	0.010s
coverage: 42.0% of statements
`
	results := parseTestOutput(output)
	wantEqual(t, 3, results.passed)
	wantEqual(t, 0, results.failed)
	// nocov package back-filled by the trailing coverage line.
	wantEqual(t, 3, results.covCount)
}

// TestBehaviour_ParseTestOutput_Empty handles empty input gracefully.
func TestBehaviour_ParseTestOutput_Empty(t *testing.T) {
	results := parseTestOutput("")
	wantEqual(t, 0, results.passed)
	wantEqual(t, 0, results.failed)
	wantEqual(t, 0, results.skipped)
}

// TestBehaviour_PrintTestSummary_Good renders a summary with passes,
// failures, skips, failed-package listing, and a coverage footer.
func TestBehaviour_PrintTestSummary_Good(t *testing.T) {
	results := testResults{
		packages:   []packageCoverage{{name: "dappco.re/go/pkg/foo", coverage: 90, hasCov: true}},
		passed:     5,
		failed:     2,
		skipped:    1,
		totalCov:   90,
		covCount:   1,
		failedPkgs: []string{"dappco.re/go/pkg/bar"},
	}
	wantNotPanic(t, func() { printTestSummary(results, true) })
	wantNotPanic(t, func() { printTestSummary(results, false) })
}

// TestBehaviour_PrintTestSummary_Empty is a no-op when there is nothing
// to report.
func TestBehaviour_PrintTestSummary_Empty(t *testing.T) {
	wantNotPanic(t, func() { printTestSummary(testResults{}, true) })
	wantNotPanic(t, func() { printTestSummary(testResults{}, false) })
}

// TestBehaviour_PrintCoverageSummary_NoPackages returns early when there
// are no packages.
func TestBehaviour_PrintCoverageSummary_NoPackages(t *testing.T) {
	wantNotPanic(t, func() { printCoverageSummary(testResults{}) })
}

// TestBehaviour_PrintJSONResults_Good emits JSON for both the
// with-coverage and zero-coverage cases.
func TestBehaviour_PrintJSONResults_Good(t *testing.T) {
	withCov := testResults{passed: 3, failed: 1, skipped: 0, totalCov: 80, covCount: 1, failedPkgs: []string{"x"}}
	wantNotPanic(t, func() { printJSONResults(withCov, 1) })

	noCov := testResults{passed: 1}
	wantNotPanic(t, func() { printJSONResults(noCov, 0) })
}

// TestBehaviour_RepeatString covers positive, zero, and negative counts.
func TestBehaviour_RepeatString(t *testing.T) {
	wantEqual(t, "***", repeatString("*", 3))
	wantEqual(t, "", repeatString("*", 0))
	wantEqual(t, "", repeatString("*", -2))
}

// TestBehaviour_RepeatSpaces covers positive, zero, and negative counts.
func TestBehaviour_RepeatSpaces(t *testing.T) {
	wantEqual(t, "   ", repeatSpaces(3))
	wantEqual(t, "", repeatSpaces(0))
	wantEqual(t, "", repeatSpaces(-1))
}

// TestBehaviour_TestPrintHelpers exercise the stdout print helpers.
func TestBehaviour_TestPrintHelpers(t *testing.T) {
	wantNotPanic(t, func() {
		testPrintf("value=%d\n", 7)
		testPrintln()
	})
}

// TestBehaviour_FilterLinkerWarnings strips ld: warning lines and test
// binary build comments while preserving real output.
func TestBehaviour_FilterLinkerWarnings(t *testing.T) {
	input := "ld: warning: ignoring duplicate libraries\n" +
		"# dappco.re/go/pkg/foo.test\n" +
		"ok  \tdappco.re/go/pkg/foo\t0.1s\n"
	got := filterLinkerWarnings(input)
	wantFalse(t, core.Contains(got, "ld: warning:"), "linker warning stripped")
	wantFalse(t, core.Contains(got, ".test"), "test build comment stripped")
	wantTrue(t, core.Contains(got, "ok  "), "real output preserved")
}

// TestBehaviour_FilterLinkerWarnings_Empty returns empty for empty input.
func TestBehaviour_FilterLinkerWarnings_Empty(t *testing.T) {
	wantEqual(t, "", filterLinkerWarnings(""))
}

// TestBehaviour_GetMacOSDeploymentTarget returns a MACOSX target on
// darwin and an empty string elsewhere — assert it never panics and the
// value is well-formed for the current platform.
func TestBehaviour_GetMacOSDeploymentTarget(t *testing.T) {
	target := getMacOSDeploymentTarget()
	if target != "" {
		wantTrue(t, core.HasPrefix(target, "MACOSX_DEPLOYMENT_TARGET="), "darwin target shape")
	}
}

// TestBehaviour_AddTestCommands_Good registers the 'test' command and
// drives its Action down the no-go-mod early-return error path by
// pointing DIR_CWD at a directory with no go.mod.
func TestBehaviour_AddTestCommands_Good(t *testing.T) {
	c := core.New()
	AddTestCommands(c)

	got := c.Command("test")
	mustTrue(t, got.OK, "test command should be registered")
	cmd, ok := got.Value.(*core.Command)
	mustTrue(t, ok, "registered value should be *core.Command")

	// Point the runner at an empty temp dir so the no-go-mod guard fires
	// instead of recursively shelling out to `go test ./...`.
	t.Setenv("DIR_CWD", t.TempDir())
	r := cmd.Run(core.NewOptions(
		core.Option{Key: "json", Value: true},
		core.Option{Key: "pkg", Value: "./does-not-exist"},
	))
	wantFalse(t, r.OK, "test action should fail when no go.mod is present")
}
