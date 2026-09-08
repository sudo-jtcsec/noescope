package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/sudo-jtcsec/noescope/internal/config"
	"github.com/sudo-jtcsec/noescope/internal/repository"
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
			path := config.ConfigFilename

			if err := config.Initialize(path); err != nil {
				return err
			}

			fmt.Printf("Created %s\n", path)
			return nil
		},
	}
}

func discoverCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "discover",
		Short: "Discover and document application functionality",
		RunE: func(cmd *cobra.Command, args []string) error {
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

			projectRoot := filepath.Dir(configPath)
			sourcePath := filepath.Join(projectRoot, cfg.Source.Path)

			repo, err := repository.Open(sourcePath)
			if err != nil {
				return err
			}

			repoInfo, err := repo.Info()
			if err != nil {
				return err
			}

			fmt.Printf("Noescope project: %s\n", cfg.Project.Name)
			fmt.Printf("Project root:     %s\n", projectRoot)
			fmt.Printf("Source root:      %s\n", repoInfo.Root)
			fmt.Printf("Git branch:       %s\n", repoInfo.Branch)
			fmt.Printf("Git commit:       %s\n", repoInfo.Commit)
			fmt.Printf("Git dirty:        %t\n", repoInfo.Dirty)
			fmt.Printf("Files:            %d\n", repoInfo.FileCount)
			fmt.Printf("Languages:        %v\n", repoInfo.Languages)
			fmt.Printf("LLM endpoint:     %s\n", cfg.AI.BaseURL)
			fmt.Printf("LLM model:        %s\n", cfg.AI.Model)

			return nil
		},
	}
}
