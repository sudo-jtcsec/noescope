package portabletests

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
)

func RunCLI(ctx context.Context, bundleRoot string, args []string, stdout, stderr io.Writer, factory BrowserFactory) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: runner <list|show|test|serve>")
		return 2
	}
	bundle, err := Load(bundleRoot)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	switch args[0] {
	case "list":
		return listCommand(bundle, stdout)
	case "show":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: runner show <test-id>")
			return 2
		}
		return showCommand(bundle, args[1], stdout, stderr)
	case "test":
		flags := flag.NewFlagSet("test", flag.ContinueOnError)
		flags.SetOutput(stderr)
		testID := flags.String("test", "", "run one test ID")
		baseURL := flags.String("base-url", "", "override the bundle target")
		headless := flags.Bool("headless", true, "run Chromium headlessly")
		output := flags.String("output", "", "execution history directory")
		mutations := flags.Bool("mutations", false, "explicitly allow mutating tests")
		executable := flags.String("browser-executable", "", "Chromium executable path")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		runner := Runner{Bundle: bundle, Options: RunOptions{BaseURL: *baseURL, Headless: *headless,
			OutputRoot: *output, Mutations: *mutations, SelectedTestID: *testID,
			ExecutablePath: *executable, BrowserFactory: factory}}
		execution, root, err := runner.Run(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		for _, result := range execution.Results {
			fmt.Fprintf(stdout, "%-15s %s", statusLabel(result.Status), result.TestID)
			if result.Reason != "" {
				fmt.Fprintf(stdout, ": %s", result.Reason)
			}
			fmt.Fprintln(stdout)
		}
		fmt.Fprintf(stdout, "Execution: %s\n", root)
		return ExecutionExitCode(execution, *testID != "")
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		flags.SetOutput(stderr)
		addr := flags.String("addr", "127.0.0.1:8765", "localhost listen address")
		baseURL := flags.String("base-url", "", "override the bundle target")
		headless := flags.Bool("headless", true, "run Chromium headlessly")
		mutations := flags.Bool("mutations", false, "permit explicitly confirmed mutating UI runs")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		server := NewServer(bundle, RunOptions{BaseURL: *baseURL, Headless: *headless, Mutations: *mutations, BrowserFactory: factory})
		fmt.Fprintf(stdout, "Portable Core Test UI: http://%s\n", *addr)
		if err := server.Serve(ctx, *addr); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}

func listCommand(bundle *Bundle, out io.Writer) int {
	latest := LatestResults(bundle)
	tests := sortedTests(bundle.Tests)
	fmt.Fprintf(out, "%-16s %-44s %s\n", "STATUS", "ID", "NAME")
	for _, test := range tests {
		status := StatusNotRun
		if result, ok := latest[test.ID]; ok {
			status = result.Status
		}
		fmt.Fprintf(out, "%-16s %-44s %s\n", statusLabel(status), test.ID, test.Name)
	}
	return 0
}

func showCommand(bundle *Bundle, id string, out, errOut io.Writer) int {
	test, ok := findTest(bundle.Tests, id)
	if !ok {
		fmt.Fprintf(errOut, "test %q was not found\n", id)
		return 2
	}
	latest := LatestResults(bundle)[id]
	fmt.Fprintf(out, "%s\nID: %s\nStatus: %s\nSafety: %s\nPurpose: %s\n",
		test.Name, test.ID, statusLabel(latest.Status), safetyLabel(test.Safety), test.Description)
	fmt.Fprintf(out, "Features: %s\nInterfaces: %s\nEntities: %s\nIdentity: %s\n",
		strings.Join(test.FeatureIDs, ", "), strings.Join(test.InterfaceIDs, ", "), strings.Join(test.EntityIDs, ", "), test.Identity)
	fmt.Fprintln(out, "Steps:")
	for index, step := range test.Steps {
		fmt.Fprintf(out, "  %d. %s\n", index+1, stepDescription(step))
	}
	fmt.Fprintln(out, "Assertions:")
	for _, assertion := range test.Assertions {
		fmt.Fprintf(out, "  - %s\n", assertionDescription(assertion))
	}
	if len(test.Cleanup) > 0 {
		fmt.Fprintln(out, "Cleanup:")
		for _, cleanup := range test.Cleanup {
			fmt.Fprintf(out, "  - %s\n", cleanupDescription(cleanup))
		}
	}
	if latest.Reason != "" {
		fmt.Fprintf(out, "Latest failure: %s\n", latest.Reason)
	}
	if latest.WorkflowFailure != "" {
		fmt.Fprintf(out, "Workflow failure: %s\n", latest.WorkflowFailure)
	}
	if latest.CleanupFailure != "" {
		fmt.Fprintf(out, "Cleanup failure: %s\nManual cleanup may be required.\n", latest.CleanupFailure)
	}
	if len(latest.EvidenceIDs) > 0 {
		fmt.Fprintf(out, "Evidence: %s\n", strings.Join(latest.EvidenceIDs, ", "))
	}
	fmt.Fprintln(out, "History:")
	for _, execution := range bundle.History {
		for _, result := range execution.Results {
			if result.TestID == id {
				fmt.Fprintf(out, "  - %s: %s (%d ms)\n", execution.ExecutionID, statusLabel(result.Status), result.DurationMS)
			}
		}
	}
	return 0
}

func ExecutionExitCode(execution *Execution, explicitlySelected bool) int {
	for _, result := range execution.Results {
		if result.Status == StatusFailed || result.Status == StatusCleanupFailed || result.Status == StatusUnresolved {
			return 1
		}
		if result.Status == StatusBlocked && (explicitlySelected || !result.Mutating) {
			return 1
		}
	}
	return 0
}

func ProductionBrowserFactory(ctx context.Context, options browser.Options) (browser.Engine, error) {
	return browser.NewChrome(ctx, options)
}

func testIDs(tests []Test) []string {
	ids := make([]string, 0, len(tests))
	for _, test := range tests {
		ids = append(ids, test.ID)
	}
	sort.Strings(ids)
	return ids
}
