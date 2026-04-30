package testcmd

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"runtime"

	core "dappco.re/go"
	"dappco.re/go/i18n"
	coreerr "dappco.re/go/log"
)

func runTest(verbose, coverage, short bool, pkg, run string, race, jsonOutput bool) error {
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
		core.Println(core.Sprintf("%s %s", testHeaderStyle.Render(i18n.Label("test")), i18n.ProgressSubject("run", "tests")))
		core.Println(core.Sprintf("  %s %s", i18n.Label("package"), testDimStyle.Render(pkg)))
		if run != "" {
			core.Println(core.Sprintf("  %s  %s", i18n.Label("filter"), testDimStyle.Render(run)))
		}
		core.Println()
	}

	cmd := exec.Command("go", args...)
	if dir := core.Env("DIR_CWD"); dir != "" {
		cmd.Dir = dir
	}
	if target := getMacOSDeploymentTarget(); target != "" {
		cmd.Env = append(os.Environ(), target)
	}

	stdout, stderr := core.NewBuilder(), core.NewBuilder()
	if verbose && !jsonOutput {
		cmd.Stdout = io.MultiWriter(os.Stdout, stdout)
		cmd.Stderr = io.MultiWriter(os.Stderr, stderr)
	} else {
		cmd.Stdout = stdout
		cmd.Stderr = stderr
	}

	waitErr := cmd.Run()
	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return coreerr.E("cmd.test", i18n.T("i18n.fail.run", "tests"), waitErr)
		}
	}
	if exitCode < 0 {
		exitCode = 1
	}

	combined := filterLinkerWarnings(core.Concat(stdout.String(), stderr.String()))
	if waitErr != nil && combined == "" {
		return coreerr.E("cmd.test", i18n.T("i18n.fail.run", "tests"), waitErr)
	}

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
		if combined != "" {
			core.Println(combined)
		}
		core.Println()
		printCoverageSummary(results)
	} else if combined != "" {
		core.Println(combined)
	}

	if exitCode != 0 {
		core.Println()
		core.Println(core.Sprintf("%s %s", testFailStyle.Render(i18n.T("cli.fail")), i18n.T("cmd.test.tests_failed")))
		return coreerr.E("cmd.test", i18n.T("i18n.fail.run", "tests"), waitErr)
	}

	core.Println()
	core.Println(core.Sprintf("%s %s", testPassStyle.Render(i18n.T("cli.pass")), i18n.T("common.result.all_passed")))
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
