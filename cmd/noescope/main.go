package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sudo-jtcsec/noescope/internal/config"
	"github.com/sudo-jtcsec/noescope/internal/discovery"
	"github.com/sudo-jtcsec/noescope/internal/evidence"
	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/llm"
	"github.com/sudo-jtcsec/noescope/internal/model"
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
	rootCmd.AddCommand(verifyCommand())

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
	var throughName string
	var resumeID string
	var rerunStage string
	command := &cobra.Command{
		Use:   "discover",
		Short: "Discover and document application functionality",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			through, err := discovery.ParseThrough(throughName)
			if err != nil {
				return err
			}

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

			var currentRun *runpkg.Run
			resume := resumeID != ""
			if resume {
				currentRun, err = runpkg.Open(projectRoot, resumeID)
				if err != nil {
					return err
				}
				if err := currentRun.ValidateRepository(repoInfo.Root, repoInfo.Commit); err != nil {
					return err
				}
				recordedThrough, err := discovery.ParseThrough(currentRun.Through)
				if err != nil {
					return fmt.Errorf("run %q has invalid through stage: %w", resumeID, err)
				}
				if throughName == "" {
					through = recordedThrough
				} else {
					if err := discovery.ValidateResumeTarget(recordedThrough, through); err != nil {
						return fmt.Errorf("run %q: %w", resumeID, err)
					}
					if through != recordedThrough {
						if err := currentRun.SetThrough(string(through)); err != nil {
							return err
						}
					}
				}
				if rerunStage != "" {
					if rerunStage != string(discovery.StageFeatures) {
						return fmt.Errorf("--rerun currently supports only features")
					}
					if recordedThrough != discovery.StageFeatures {
						return fmt.Errorf("--rerun features requires a run targeted through features")
					}
					through = discovery.StageFeatures
				}
			} else {
				if rerunStage != "" {
					return fmt.Errorf("--rerun requires --resume")
				}
				currentRun, err = runpkg.StartWithOptions(
					projectRoot,
					"discover",
					runpkg.StartOptions{
						RepositoryRoot: repoInfo.Root, RepositoryCommit: repoInfo.Commit,
						Through: string(through),
					},
				)
				if err != nil {
					return err
				}
			}

			registry := tools.NewRegistry()

			if err := repositorytools.RegisterAll(
				registry,
				repo,
			); err != nil {
				return err
			}

			var evidenceStore *evidence.Store
			if resume {
				evidenceStore, err = evidence.OpenStore(currentRun.Root)
				if err != nil {
					return err
				}
			} else {
				evidenceStore = evidence.NewStore(currentRun.Root)
			}

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

			return discovery.RunThrough(
				ctx,
				runner,
				currentRun.Root,
				os.Stdout,
				through,
				model.Metadata{
					ProjectName: cfg.Project.Name,
					RunID:       currentRun.ID,
					Source: model.SourceMetadata{
						Root:      repoInfo.Root,
						GitBranch: repoInfo.Branch,
						GitCommit: repoInfo.Commit,
						GitDirty:  repoInfo.Dirty,
					},
					ApplicationURL: cfg.Application.URL,
				},
				discovery.Options{
					Resume: resume, RerunFeatures: rerunStage == string(discovery.StageFeatures),
					Manifest: currentRun,
				},
			)
		},
	}
	command.Flags().StringVar(
		&throughName,
		"through",
		"",
		"run discovery through a stage (architecture, authentication, authorization, entities, surface, features)",
	)
	command.Flags().StringVar(
		&rerunStage,
		"rerun",
		"",
		"rerun a completed terminal stage (currently features)",
	)
	command.Flags().StringVar(
		&resumeID,
		"resume",
		"",
		"resume a compatible failed discovery run",
	)

	return command
}
