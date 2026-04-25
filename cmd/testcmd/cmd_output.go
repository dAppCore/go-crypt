package testcmd

import (
	"bufio"
	"cmp"
<<<<<<< HEAD
=======
	"path/filepath"
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
	"regexp"
	"slices"
	"strconv"

<<<<<<< HEAD
	core "dappco.re/go/core"
	"dappco.re/go/i18n"
=======
	"dappco.re/go/core"
	"dappco.re/go/core/i18n"
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
)

type packageCoverage struct {
	name     string
	coverage float64
	hasCov   bool
}

type testResults struct {
	packages   []packageCoverage
	passed     int
	failed     int
	skipped    int
	totalCov   float64
	covCount   int
	failedPkgs []string
}

func parseTestOutput(output string) testResults {
	results := testResults{}

	// Regex patterns - handle both timed and cached test results
	// Example: ok  	dappco.re/go/crypt/crypt	0.015s	coverage: 91.2% of statements
	// Example: ok  	dappco.re/go/crypt/crypt	(cached)	coverage: 91.2% of statements
	okPattern := regexp.MustCompile(`^ok\s+(\S+)\s+(?:[\d.]+s|\(cached\))(?:\s+coverage:\s+([\d.]+)%)?`)
	failPattern := regexp.MustCompile(`^FAIL\s+(\S+)`)
	skipPattern := regexp.MustCompile(`^\?\s+(\S+)\s+\[no test files\]`)
	coverPattern := regexp.MustCompile(`coverage:\s+([\d.]+)%`)

	scanner := bufio.NewScanner(core.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if matches := okPattern.FindStringSubmatch(line); matches != nil {
			pkg := packageCoverage{name: matches[1]}
			if len(matches) > 2 && matches[2] != "" {
				cov, _ := strconv.ParseFloat(matches[2], 64)
				pkg.coverage = cov
				pkg.hasCov = true
				results.totalCov += cov
				results.covCount++
			}
			results.packages = append(results.packages, pkg)
			results.passed++
		} else if matches := failPattern.FindStringSubmatch(line); matches != nil {
			results.failed++
			results.failedPkgs = append(results.failedPkgs, matches[1])
		} else if matches := skipPattern.FindStringSubmatch(line); matches != nil {
			results.skipped++
		} else if matches := coverPattern.FindStringSubmatch(line); matches != nil {
			// Catch any additional coverage lines
			cov, _ := strconv.ParseFloat(matches[1], 64)
			if cov > 0 {
				// Find the last package without coverage and update it
				for i := len(results.packages) - 1; i >= 0; i-- {
					if !results.packages[i].hasCov {
						results.packages[i].coverage = cov
						results.packages[i].hasCov = true
						results.totalCov += cov
						results.covCount++
						break
					}
				}
			}
		}
	}

	return results
}

func printTestSummary(results testResults, showCoverage bool) {
	// Print pass/fail summary
	total := results.passed + results.failed
	if total > 0 {
<<<<<<< HEAD
		line := core.NewBuilder()
		line.WriteString("  ")
		line.WriteString(testPassStyle.Render("✓"))
		line.WriteString(" ")
		line.WriteString(i18n.T("i18n.count.passed", results.passed))
		if results.failed > 0 {
			line.WriteString("  ")
			line.WriteString(testFailStyle.Render("✗"))
			line.WriteString(" ")
			line.WriteString(i18n.T("i18n.count.failed", results.failed))
		}
		if results.skipped > 0 {
			line.WriteString("  ")
			line.WriteString(testSkipStyle.Render("○"))
			line.WriteString(" ")
			line.WriteString(i18n.T("i18n.count.skipped", results.skipped))
		}
		core.Println(line.String())
=======
		testPrintf("  %s %s", testPassStyle.Render("✓"), i18n.T("i18n.count.passed", results.passed))
		if results.failed > 0 {
			testPrintf("  %s %s", testFailStyle.Render("✗"), i18n.T("i18n.count.failed", results.failed))
		}
		if results.skipped > 0 {
			testPrintf("  %s %s", testSkipStyle.Render("○"), i18n.T("i18n.count.skipped", results.skipped))
		}
		testPrintln()
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
	}

	// Print failed packages
	if len(results.failedPkgs) > 0 {
<<<<<<< HEAD
		core.Println()
		core.Println("  " + i18n.T("cmd.test.failed_packages"))
		for _, pkg := range results.failedPkgs {
			core.Println(core.Sprintf("    %s %s", testFailStyle.Render("✗"), pkg))
=======
		testPrintf("\n  %s\n", i18n.T("cmd.test.failed_packages"))
		for _, pkg := range results.failedPkgs {
			testPrintf("    %s %s\n", testFailStyle.Render("✗"), pkg)
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
		}
	}

	// Print coverage
	if showCoverage {
		printCoverageSummary(results)
	} else if results.covCount > 0 {
		avgCov := results.totalCov / float64(results.covCount)
<<<<<<< HEAD
		core.Println()
		core.Println(core.Sprintf("  %s %s", i18n.Label("coverage"), formatCoverage(avgCov)))
=======
		testPrintf("\n  %s %s\n", i18n.Label("coverage"), formatCoverage(avgCov))
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
	}
}

func printCoverageSummary(results testResults) {
	if len(results.packages) == 0 {
		return
	}

<<<<<<< HEAD
	core.Println()
	core.Println("  " + testHeaderStyle.Render(i18n.T("cmd.test.coverage_by_package")))
=======
	testPrintf("\n  %s\n", testHeaderStyle.Render(i18n.T("cmd.test.coverage_by_package")))
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))

	// Sort packages by name
	slices.SortFunc(results.packages, func(a, b packageCoverage) int {
		return cmp.Compare(a.name, b.name)
	})

	// Find max package name length for alignment
	maxLen := 0
	for _, pkg := range results.packages {
		name := shortenPackageName(pkg.name)
		if len(name) > maxLen {
			maxLen = len(name)
		}
	}

	// Print each package
	for _, pkg := range results.packages {
		if !pkg.hasCov {
			continue
		}
		name := shortenPackageName(pkg.name)
		padLen := maxLen - len(name) + 2
		if padLen < 0 {
			padLen = 2
		}
<<<<<<< HEAD
		padding := repeatString(" ", padLen)
		core.Println(core.Sprintf("    %s%s%s", name, padding, formatCoverage(pkg.coverage)))
=======
		padding := repeatSpaces(padLen)
		testPrintf("    %s%s%s\n", name, padding, formatCoverage(pkg.coverage))
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
	}

	// Print average
	if results.covCount > 0 {
		avgCov := results.totalCov / float64(results.covCount)
		avgLabel := i18n.T("cmd.test.label.average")
		padLen := maxLen - len(avgLabel) + 2
		if padLen < 0 {
			padLen = 2
		}
<<<<<<< HEAD
		padding := repeatString(" ", padLen)
		core.Println()
		core.Println(core.Sprintf("    %s%s%s", testHeaderStyle.Render(avgLabel), padding, formatCoverage(avgCov)))
=======
		padding := repeatSpaces(padLen)
		testPrintf("\n    %s%s%s\n", testHeaderStyle.Render(avgLabel), padding, formatCoverage(avgCov))
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
	}
}

func formatCoverage(cov float64) string {
	s := core.Sprintf("%.1f%%", cov)
	if cov >= 80 {
		return testCovHighStyle.Render(s)
	} else if cov >= 50 {
		return testCovMedStyle.Render(s)
	}
	return testCovLowStyle.Render(s)
}

func shortenPackageName(name string) string {
	const modulePrefix = "dappco.re/go/"
	if core.HasPrefix(name, modulePrefix) {
		remainder := core.TrimPrefix(name, modulePrefix)
<<<<<<< HEAD
=======
		// If there's a sub-path (e.g. "go/pkg/foo"), strip the module name
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
		parts := core.SplitN(remainder, "/", 2)
		if len(parts) == 2 {
			return parts[1]
		}
		// Module root (e.g. "cli-php") — return as-is
		return remainder
	}
	return core.PathBase(name)
}

func printJSONResults(results testResults, exitCode int) {
<<<<<<< HEAD
	payload := struct {
		Passed         int      `json:"passed"`
		Failed         int      `json:"failed"`
		Skipped        int      `json:"skipped"`
		Coverage       float64  `json:"coverage,omitempty"`
		ExitCode       int      `json:"exit_code"`
		FailedPackages []string `json:"failed_packages"`
	}{
		Passed:         results.passed,
		Failed:         results.failed,
		Skipped:        results.skipped,
		ExitCode:       exitCode,
		FailedPackages: results.failedPkgs,
	}
	if results.covCount > 0 {
		payload.Coverage = results.totalCov / float64(results.covCount)
	}
	core.Println(core.JSONMarshalString(payload))
}

func repeatString(part string, count int) string {
	if count <= 0 {
		return ""
	}

	builder := core.NewBuilder()
	for range count {
		builder.WriteString(part)
	}
	return builder.String()
=======
	// Simple JSON output for agents
	testPrintf("{\n")
	testPrintf("  \"passed\": %d,\n", results.passed)
	testPrintf("  \"failed\": %d,\n", results.failed)
	testPrintf("  \"skipped\": %d,\n", results.skipped)
	if results.covCount > 0 {
		avgCov := results.totalCov / float64(results.covCount)
		testPrintf("  \"coverage\": %.1f,\n", avgCov)
	}
	testPrintf("  \"exit_code\": %d,\n", exitCode)
	if len(results.failedPkgs) > 0 {
		testPrintf("  \"failed_packages\": [\n")
		for i, pkg := range results.failedPkgs {
			comma := ","
			if i == len(results.failedPkgs)-1 {
				comma = ""
			}
			testPrintf("    %q%s\n", pkg, comma)
		}
		testPrintf("  ]\n")
	} else {
		testPrintf("  \"failed_packages\": []\n")
	}
	testPrintf("}\n")
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
}
