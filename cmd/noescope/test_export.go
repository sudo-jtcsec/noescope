package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sudo-jtcsec/noescope/internal/config"
	"github.com/sudo-jtcsec/noescope/internal/testbundle"
)

func exportTestCommand() *cobra.Command {
	var packID, output, runnerPath string
	command := &cobra.Command{
		Use:   "export",
		Short: "Export a portable standalone Core Test bundle",
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
			if runnerPath == "" {
				executable, err := os.Executable()
				if err != nil {
					return err
				}
				runnerPath = filepath.Join(filepath.Dir(executable), "noescope-test-runner")
			}
			result, err := testbundle.Export(testbundle.ExportOptions{ProjectRoot: filepath.Dir(configPath),
				PackID: packID, Output: output, RunnerPath: runnerPath, Config: cfg})
			if err != nil {
				return err
			}
			fmt.Printf("Portable Core Test bundle: %s\n", result.Root)
			fmt.Printf("Tests: %d\nRunner: %s\nHTML report: %s\nMarkdown report: %s\n",
				result.Tests, result.RunnerPath, result.HTMLPath, result.Markdown)
			return nil
		},
	}
	command.Flags().StringVar(&packID, "pack", "", "Core Test Pack ID to export")
	command.Flags().StringVar(&output, "output", "", "portable bundle output directory")
	command.Flags().StringVar(&runnerPath, "runner", "", "prebuilt standalone runner binary")
	_ = command.MarkFlagRequired("pack")
	_ = command.MarkFlagRequired("output")
	return command
}
