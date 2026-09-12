package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sudo-jtcsec/noescope/internal/authn"
	"github.com/sudo-jtcsec/noescope/internal/config"
	"github.com/sudo-jtcsec/noescope/internal/coretests"
	"github.com/sudo-jtcsec/noescope/internal/repository"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

func testCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "test",
		Short: "Generate and execute application test packs",
	}
	command.AddCommand(coreTestCommand())
	command.AddCommand(exportTestCommand())
	return command
}

func coreTestCommand() *cobra.Command {
	var sourceRunID string
	var runtimeRunID string
	var testID string
	command := &cobra.Command{
		Use:   "core",
		Short: "Generate, execute, and baseline a Core Test Pack",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCoreTests(cmd.Context(), sourceRunID, runtimeRunID, testID)
		},
	}
	command.Flags().StringVar(&sourceRunID, "run", "", "source discovery run ID (defaults to latest compatible complete run)")
	command.Flags().StringVar(&runtimeRunID, "runtime", "", "runtime verification run ID (defaults to latest compatible completed run)")
	command.Flags().StringVar(&testID, "test", "", "execute only the selected canonical Core Test candidate")
	return command
}

func runCoreTests(ctx context.Context, sourceRunID, runtimeRunID, testID string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	configPath, err := config.Find(cwd)
	if err != nil {
		return err
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if !cfg.Testing.Enabled {
		return fmt.Errorf("testing.enabled must be true in noescope.yml")
	}
	if cfg.Testing.MaxCoreTests <= 0 {
		return fmt.Errorf("testing.max_core_tests must be greater than zero")
	}
	if cfg.Runtime.BaseURL == "" {
		return fmt.Errorf("runtime.base_url or application.url must be configured in noescope.yml")
	}

	projectRoot := filepath.Dir(configPath)
	repo, err := repository.Open(filepath.Join(projectRoot, cfg.Source.Path))
	if err != nil {
		return err
	}
	repoInfo, err := repo.Info()
	if err != nil {
		return err
	}
	source, err := runtimeverify.LoadSourceModel(
		projectRoot, sourceRunID, repoInfo.Root, repoInfo.Commit,
	)
	if err != nil {
		return err
	}
	loadedRuntime, err := coretests.LoadCompletedRuntime(source.Run.Root, runtimeRunID, source.Application)
	if err != nil {
		return err
	}
	if loadedRuntime.Runtime.BaseURL != cfg.Runtime.BaseURL {
		return fmt.Errorf(
			"runtime target %q does not match configured runtime.base_url %q",
			loadedRuntime.Runtime.BaseURL, cfg.Runtime.BaseURL,
		)
	}
	var credentials *browser.Credentials
	var totpReference *authn.TOTPReference
	var authenticationUnavailableReason string
	redactor := runtimeverify.NewRedactor()
	if cfg.Testing.Identity == "" {
		authenticationUnavailableReason = "testing.identity is not configured"
	} else {
		identity, identityErr := cfg.Identity(cfg.Testing.Identity)
		if identityErr != nil {
			return identityErr
		}
		resolved, credentialsErr := identity.ResolveCredentials(os.LookupEnv)
		if credentialsErr != nil {
			authenticationUnavailableReason = credentialsErr.Error()
		} else {
			credentials = &browser.Credentials{Username: resolved.Username, Password: resolved.Password}
			redactor = runtimeverify.NewRedactor(resolved.Username, resolved.Password)
			if identity.TOTP != nil {
				totpReference = &authn.TOTPReference{SecretEnv: identity.TOTP.SecretEnv,
					Period: identity.TOTP.Period, Digits: identity.TOTP.Digits, Algorithm: identity.TOTP.Algorithm}
			}
		}
	}

	candidates, err := coretests.SelectCandidates(
		source.Application, loadedRuntime.Runtime,
		coretests.SelectionOptions{MaxCandidates: cfg.Testing.MaxCoreTests},
	)
	if err != nil {
		return fmt.Errorf("select Core Test candidates: %w", err)
	}
	var workflowPlan *coretests.OwnedLifecyclePlan
	if testID != "" {
		workflowPlan, _ = coretests.PlanOwnedLifecycle(source.Application)
		candidates, err = coretests.FilterTestCandidates(candidates, workflowPlan, testID)
		if err != nil {
			return err
		}
	}
	if len(candidates) == 0 {
		return fmt.Errorf("no grounded Core Test candidates were selected")
	}
	session, err := coretests.NewSession(
		source.Run.Root, cfg.Testing.Identity, source.Application, loadedRuntime.Runtime, redactor,
	)
	if err != nil {
		return err
	}
	previousPack, err := coretests.LoadBestVerifiedPack(
		source.Run.Root, source.Application, loadedRuntime.Runtime.RuntimeID,
	)
	if err != nil {
		return err
	}
	session.SeedVerifiedTests(previousPack)
	evidenceStore := coretests.NewEvidenceStore(session.Root, redactor)

	fmt.Printf("Source run:  %s\n", source.Run.ID)
	fmt.Printf("Runtime run: %s\n", loadedRuntime.Runtime.RuntimeID)
	fmt.Printf("Test pack:   %s\n\n", session.Pack.TestPackID)
	if authenticationUnavailableReason != "" {
		fmt.Printf("Authentication candidates will be blocked: %s\n\n", authenticationUnavailableReason)
	}
	fmt.Printf("Core Test candidates (%d, deterministic priority order):\n", len(candidates))
	for index, candidate := range candidates {
		classification := "read-only"
		if candidate.Safety.Mutating {
			classification = "mutating"
		}
		fmt.Printf("%2d. score=%d [%s] %s (%s)\n", index+1,
			candidate.Safety.SelectionScore, classification, candidate.Name, candidate.ID)
	}
	if workflowPlan != nil && len(candidates) == 1 && candidates[0].ID == workflowPlan.Test.ID {
		fmt.Printf("\nOwned lifecycle plan:\n")
		fmt.Printf("  parent: %s (%s)\n", workflowPlan.ParentEntity.Name, workflowPlan.ParentEntity.ID)
		fmt.Printf("  child: %s (%s)\n", workflowPlan.ChildEntity.Name, workflowPlan.ChildEntity.ID)
		fmt.Printf("  interfaces: %s\n", strings.Join(workflowPlan.Test.InterfaceIDs, ", "))
		fmt.Printf("  features: %s\n", strings.Join(workflowPlan.Test.FeatureIDs, ", "))
	}
	fmt.Println()

	executorOptions := coretests.ExecutorOptions{
		Application: source.Application, Runtime: loadedRuntime.Runtime,
		Credentials: credentials, MutationsEnabled: cfg.Testing.Mutations.Enabled,
		TOTP: totpReference, LookupEnv: os.LookupEnv, RegisterSecrets: redactor.AddSecrets,
		AuthenticationUnavailableReason: authenticationUnavailableReason,
		Cleanup:                         cfg.Testing.Cleanup, Evidence: evidenceStore,
		BrowserFactory: func(ctx context.Context) (browser.Engine, error) {
			return browser.NewChrome(ctx, browser.Options{
				Headless: cfg.Runtime.Browser.Headless, IgnoreTLSErrors: cfg.Runtime.Browser.IgnoreTLSErrors,
				ExecutablePath: cfg.Runtime.Browser.Executable,
			})
		},
	}
	var results []testsmodel.CandidateResult
	if workflowPlan != nil && len(candidates) == 1 && candidates[0].ID == workflowPlan.Test.ID {
		results = []testsmodel.CandidateResult{coretests.ExecuteOwnedLifecycle(
			ctx, workflowPlan, coretests.WorkflowExecutorOptions{
				ExecutorOptions: executorOptions, ExecutionID: session.Pack.TestPackID,
			},
		)}
	} else {
		results = coretests.ExecuteCandidates(ctx, candidates, executorOptions)
	}
	session.Complete(results)
	paths, err := session.Write(source.Application)
	if err != nil {
		return err
	}

	for _, result := range session.Execution.Results {
		fmt.Printf("[%s] %s", result.Status, result.Candidate.ID)
		if result.Reason != "" {
			fmt.Printf(": %s", redactor.String(result.Reason))
		}
		fmt.Println()
	}
	printCoreSummary(session.Execution.Summary)
	fmt.Printf("\nVerified Core Test Pack:\n%s\n", paths.Pack)
	fmt.Printf("Core Test report:\n%s\n", paths.Markdown)
	fmt.Printf("Candidate execution:\n%s\n", paths.Execution)
	fmt.Printf("Test evidence:\n%s\n", paths.Evidence)
	if paths.Baseline != "" {
		fmt.Printf("Baseline:\n%s\n", paths.Baseline)
	} else {
		fmt.Println("Baseline: not created because no Core Test candidate passed")
	}
	return nil
}

func printCoreSummary(summary testsmodel.ExecutionSummary) {
	fmt.Printf("\nCore Test candidate summary:\n")
	fmt.Printf("  candidates: %d\n", summary.Candidates)
	fmt.Printf("  passed: %d\n", summary.Passed)
	fmt.Printf("  blocked: %d\n", summary.Blocked)
	fmt.Printf("  failed: %d\n", summary.Failed)
	fmt.Printf("  cleanup_failed: %d\n", summary.CleanupFailed)
	fmt.Printf("  unresolved: %d\n", summary.Unresolved)
}
