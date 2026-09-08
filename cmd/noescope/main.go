package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "0.0.1-dev"

func main() {
	rootCmd := &cobra.Command{
		Use:   "noescope",
		Short: "AI-powered application discovery and understanding",
		Long: `Noescope analyzes application source code and runtime behavior
to build an evidence-backed model of application functionality.`,
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print Noescope version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Initialize Noescope in the current project",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("noescope init: not implemented yet")
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "discover",
		Short: "Discover and document application functionality",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("noescope discover: not implemented yet")
			return nil
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
