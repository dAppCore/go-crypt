package testcmd

import (
	"testing"
)

func TestOutput_ShortenPackageName_Good(t *testing.T) {
	wantEqual(t, "pkg/foo", shortenPackageName("dappco.re/go/pkg/foo"))
	wantEqual(t, "cli-php", shortenPackageName("example.com/org/cli-php"))
	wantEqual(t, "bar", shortenPackageName("github.com/other/bar"))
}

func TestOutput_FormatCoverage_Good(t *testing.T) {
	wantContains(t, formatCoverage(85.0), "85.0%")
	wantContains(t, formatCoverage(65.0), "65.0%")
	wantContains(t, formatCoverage(25.0), "25.0%")
}

func TestOutput_ParseTestOutput_Good(t *testing.T) {
	output := `ok  	dappco.re/go/core/pkg/foo	0.100s	coverage: 50.0% of statements
FAIL	dappco.re/go/core/pkg/bar
?   	dappco.re/go/core/pkg/baz	[no test files]
`
	results := parseTestOutput(output)
	wantEqual(t, 1, results.passed)
	wantEqual(t, 1, results.failed)
	wantEqual(t, 1, results.skipped)
	wantEqual(t, 1, len(results.failedPkgs))
	wantEqual(t, "dappco.re/go/pkg/bar", results.failedPkgs[0])
	wantEqual(t, 1, len(results.packages))
	wantEqual(t, 50.0, results.packages[0].coverage)
}

func TestOutput_PrintCoverageSummary_Good_LongPackageNames(t *testing.T) {
	// This tests the bug fix for long package names causing negative Repeat count
	results := testResults{
		packages: []packageCoverage{
			{name: "dappco.re/go/pkg/short", coverage: 100, hasCov: true},
			{name: "dappco.re/go/pkg/a-very-very-very-very-very-long-package-name-that-might-cause-issues", coverage: 80, hasCov: true},
		},
		passed:   2,
		totalCov: 180,
		covCount: 2,
	}

	// Should not panic
	wantNotPanic(t, func() {
		printCoverageSummary(results)
	})
}
