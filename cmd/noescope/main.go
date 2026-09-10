package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sudo-jtcsec/noescope/internal/config"
	"github.com/sudo-jtcsec/noescope/internal/evidence"
	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/llm"
	"github.com/sudo-jtcsec/noescope/internal/repository"
	runpkg "github.com/sudo-jtcsec/noescope/internal/run"
	"github.com/sudo-jtcsec/noescope/internal/tools"
	repositorytools "github.com/sudo-jtcsec/noescope/internal/tools/repository"
)

var version = "0.0.1-dev"

func main() {
	rootCmd := &cobra.Command{
		Use:   "noescope",
		Short: "AI-powered application discovery and understanding",
		Long: `Noescope analyzes application source code and runtime behavior
to build an evidence-backed model of application functionality.`,
	}

	rootCmd.AddCommand(versionCommand())
	rootCmd.AddCommand(initCommand())
	rootCmd.AddCommand(discoverCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Noescope version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	}
}

func initCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize Noescope in the current project",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := config.Initialize(
				config.ConfigFilename,
			); err != nil {
				return err
			}

			fmt.Printf(
				"Created %s\n",
				config.ConfigFilename,
			)

			return nil
		},
	}
}

func discoverCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "discover",
		Short: "Discover and document application functionality",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

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

			if cfg.AI.Model == "" {
				return fmt.Errorf(
					"ai.model must be configured in noescope.yml",
				)
			}

			projectRoot := filepath.Dir(configPath)
			sourcePath := filepath.Join(
				projectRoot,
				cfg.Source.Path,
			)

			repo, err := repository.Open(sourcePath)
			if err != nil {
				return err
			}

			repoInfo, err := repo.Info()
			if err != nil {
				return err
			}

			currentRun, err := runpkg.Start(
				projectRoot,
				"discover",
			)
			if err != nil {
				return err
			}

			registry := tools.NewRegistry()

			if err := repositorytools.RegisterAll(
				registry,
				repo,
			); err != nil {
				return err
			}

			evidenceStore := evidence.NewStore(
				currentRun.Root,
			)

			client := llm.NewClient(
				cfg.AI.BaseURL,
				cfg.AI.APIKey,
				cfg.AI.Model,
			)

			runner := investigation.NewRunner(
				client,
				registry,
				evidenceStore,
			)

			runner.Logf = func(
				format string,
				args ...any,
			) {
				fmt.Printf(format+"\n", args...)
			}

			fmt.Printf(
				"Noescope project: %s\n",
				cfg.Project.Name,
			)
			fmt.Printf(
				"Git commit:       %s\n",
				repoInfo.Commit,
			)
			fmt.Printf(
				"Run:              %s\n\n",
				currentRun.ID,
			)

			fmt.Println(
				"[1/3] Architecture Discovery",
			)

			architectureFindings, architectureResult, err := architecture.Run(
				ctx,
				runner,
			)
			if err != nil {
				return err
			}

			output := struct {
				Status   string                 `json:"status"`
				Summary  string                 `json:"summary"`
				Findings *architecture.Findings `json:"findings"`
			}{
				Status:   architectureResult.Status,
				Summary:  architectureResult.Summary,
				Findings: architectureFindings,
			}

			outputPath := filepath.Join(
				currentRun.Root,
				"output",
				"architecture.json",
			)

			if err := writeJSON(
				outputPath,
				output,
			); err != nil {
				return err
			}

			fmt.Printf(
				"\nArchitecture discovery complete.\n%s\n",
				architectureResult.Summary,
			)

			fmt.Printf(
				"\nWritten to:\n%s\n",
				outputPath,
			)

			architectureContext, err := marshalAuthenticationContext(
				architectureFindings,
			)
			if err != nil {
				return fmt.Errorf(
					"marshal architecture context: %w",
					err,
				)
			}

			fmt.Println(
				"\n[2/3] Authentication Discovery",
			)

			authenticationFindings, authenticationResult, err := authentication.Run(
				ctx,
				runner,
				architectureContext,
			)
			if err != nil {
				return err
			}

			authenticationOutput := struct {
				Status     string                             `json:"status"`
				Summary    string                             `json:"summary"`
				Findings   *authentication.Findings           `json:"findings"`
				Claims     []investigation.Claim              `json:"claims,omitempty"`
				Unresolved []investigation.UnresolvedQuestion `json:"unresolved,omitempty"`
			}{
				Status:     authenticationResult.Status,
				Summary:    authenticationResult.Summary,
				Findings:   authenticationFindings,
				Claims:     authenticationResult.Claims,
				Unresolved: authenticationResult.Unresolved,
			}

			authenticationOutputPath := filepath.Join(
				currentRun.Root,
				"output",
				"authentication.json",
			)

			if err := writeJSON(
				authenticationOutputPath,
				authenticationOutput,
			); err != nil {
				return err
			}

			fmt.Printf(
				"\nAuthentication discovery complete.\n%s\n",
				authenticationResult.Summary,
			)

			fmt.Printf(
				"\nWritten to:\n%s\n",
				authenticationOutputPath,
			)

			authorizationContext, err := marshalAuthorizationContext(
				architectureFindings,
				authenticationFindings,
			)
			if err != nil {
				return fmt.Errorf(
					"marshal authorization context: %w",
					err,
				)
			}

			fmt.Println(
				"\n[3/3] Authorization Discovery",
			)

			authorizationFindings, authorizationResult, err := authorization.Run(
				ctx,
				runner,
				authorizationContext,
			)
			if err != nil {
				return err
			}

			authorizationOutput := struct {
				Status     string                             `json:"status"`
				Summary    string                             `json:"summary"`
				Findings   *authorization.Findings            `json:"findings"`
				Claims     []investigation.Claim              `json:"claims,omitempty"`
				Unresolved []investigation.UnresolvedQuestion `json:"unresolved,omitempty"`
			}{
				Status:     authorizationResult.Status,
				Summary:    authorizationResult.Summary,
				Findings:   authorizationFindings,
				Claims:     authorizationResult.Claims,
				Unresolved: authorizationResult.Unresolved,
			}

			authorizationOutputPath := filepath.Join(
				currentRun.Root,
				"output",
				"authorization.json",
			)

			if err := writeJSON(
				authorizationOutputPath,
				authorizationOutput,
			); err != nil {
				return err
			}

			fmt.Printf(
				"\nAuthorization discovery complete.\n%s\n",
				authorizationResult.Summary,
			)

			fmt.Printf(
				"\nWritten to:\n%s\n",
				authorizationOutputPath,
			)

			return nil
		},
	}
}

// Context builders intentionally accept only validated structured findings.
// Investigation summaries are narrative-only and must not become downstream
// canonical context.
func marshalAuthenticationContext(
	findings *architecture.Findings,
) (json.RawMessage, error) {
	return json.Marshal(findings)
}

func marshalAuthorizationContext(
	architectureFindings *architecture.Findings,
	authenticationFindings *authentication.Findings,
) (json.RawMessage, error) {
	return json.Marshal(struct {
		Architecture   *architecture.Findings   `json:"architecture"`
		Authentication *authentication.Findings `json:"authentication"`
	}{
		Architecture:   architectureFindings,
		Authentication: authenticationFindings,
	})
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
