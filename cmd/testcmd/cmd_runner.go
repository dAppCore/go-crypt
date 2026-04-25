package testcmd

import (
	"bufio"
<<<<<<< HEAD
	"context"
	"runtime"
	"sync"

	core "dappco.re/go/core"
	"dappco.re/go/i18n"
	coreerr "dappco.re/go/log"
	"dappco.re/go/process"
)

var (
	processInitOnce sync.Once
	processInitErr  error
=======
	"io"
	"os"
	"os/exec"
	"runtime"

	"dappco.re/go/core"
	"dappco.re/go/core/i18n"
	coreerr "dappco.re/go/log"
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
)

func runTest(verbose, coverage, short bool, pkg, run string, race, jsonOutput bool) error {
	processInitOnce.Do(func() {
		processInitErr = process.Init(core.New())
	})
	if processInitErr != nil {
		return coreerr.E("cmd.test", i18n.T("i18n.fail.run", "tests"), processInitErr)
	}

	// Detect if we're in a Go project
	if !(&core.Fs{}).New("/").Exists("go.mod") {
		return coreerr.E("cmd.test", i18n.T("cmd.test.error.no_go_mod"), nil)
	}

	// Build command arguments
	args := []string{"test"}

	// Default to ./... if no package specified
	if pkg == "" {
		pkg = "./..."
	}

	// Add flags
	if verbose {
		args = append(args, "-v")
	}
	if short {
		args = append(args, "-short")
	}
	if run != "" {
		args = append(args, "-run", run)
	}
	if race {
		args = append(args, "-race")
	}

	// Always add coverage
	args = append(args, "-cover")

	// Add package pattern
	args = append(args, pkg)

	if !jsonOutput {
<<<<<<< HEAD
		core.Println(core.Sprintf("%s %s", testHeaderStyle.Render(i18n.Label("test")), i18n.ProgressSubject("run", "tests")))
		core.Println(core.Sprintf("  %s %s", i18n.Label("package"), testDimStyle.Render(pkg)))
		if run != "" {
			core.Println(core.Sprintf("  %s  %s", i18n.Label("filter"), testDimStyle.Render(run)))
		}
		core.Println()
	}

	options := process.RunOptions{
		Command: "go",
		Args:    args,
		Dir:     core.Env("DIR_CWD"),
	}
	if target := getMacOSDeploymentTarget(); target != "" {
		options.Env = []string{target}
=======
		testPrintf("%s %s\n", testHeaderStyle.Render(i18n.Label("test")), i18n.ProgressSubject("run", "tests"))
		testPrintf("  %s %s\n", i18n.Label("package"), testDimStyle.Render(pkg))
		if run != "" {
			testPrintf("  %s  %s\n", i18n.Label("filter"), testDimStyle.Render(run))
		}
		testPrintln()
	}

	// Capture output for parsing
	stdout, stderr := core.NewBuilder(), core.NewBuilder()

	if verbose && !jsonOutput {
		// Stream output in verbose mode, but also capture for parsing
		cmd.Stdout = io.MultiWriter(os.Stdout, stdout)
		cmd.Stderr = io.MultiWriter(os.Stderr, stderr)
	} else {
		// Capture output for parsing
		cmd.Stdout = stdout
		cmd.Stderr = stderr
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
	}

	proc, err := process.StartWithOptions(context.Background(), options)
	if err != nil {
		return coreerr.E("cmd.test", i18n.T("i18n.fail.run", "tests"), err)
	}

	waitErr := proc.Wait()
	exitCode := proc.ExitCode
	combined := filterLinkerWarnings(proc.Output())

	// Parse results
	results := parseTestOutput(combined)

	if jsonOutput {
		// JSON output for CI/agents
		printJSONResults(results, exitCode)
		if exitCode != 0 {
			return coreerr.E("cmd.test", i18n.T("i18n.fail.run", "tests"), nil)
		}
		return nil
	}

	// Print summary
	if !verbose {
		printTestSummary(results, coverage)
	} else if coverage {
		// In verbose mode, still show coverage summary at end
<<<<<<< HEAD
		if combined != "" {
			core.Println(combined)
		}
		core.Println()
=======
		testPrintln()
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
		printCoverageSummary(results)
	} else if combined != "" {
		core.Println(combined)
	}

	if exitCode != 0 {
<<<<<<< HEAD
		core.Println()
		core.Println(core.Sprintf("%s %s", testFailStyle.Render(i18n.T("cli.fail")), i18n.T("cmd.test.tests_failed")))
		return coreerr.E("cmd.test", i18n.T("i18n.fail.run", "tests"), waitErr)
	}

	core.Println()
	core.Println(core.Sprintf("%s %s", testPassStyle.Render(i18n.T("cli.pass")), i18n.T("common.result.all_passed")))
=======
		testPrintf("\n%s %s\n", testFailStyle.Render(i18n.T("cli.fail")), i18n.T("cmd.test.tests_failed"))
		return coreerr.E("cmd.test", i18n.T("i18n.fail.run", "tests"), nil)
	}

	testPrintf("\n%s %s\n", testPassStyle.Render(i18n.T("cli.pass")), i18n.T("common.result.all_passed"))
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
	return nil
}

func getMacOSDeploymentTarget() string {
	if runtime.GOOS == "darwin" {
		// Use deployment target matching current macOS to suppress linker warnings
		return "MACOSX_DEPLOYMENT_TARGET=26.0"
	}
	return ""
}

func filterLinkerWarnings(output string) string {
	// Filter out ld: warning lines that pollute the output
	var filtered []string
	scanner := bufio.NewScanner(core.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip linker warnings
		if core.HasPrefix(line, "ld: warning:") {
			continue
		}
		// Skip test binary build comments
		if core.HasPrefix(line, "# ") && core.HasSuffix(line, ".test") {
			continue
		}
		filtered = append(filtered, line)
	}
	return core.Join("\n", filtered...)
}
