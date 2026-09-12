package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/sudo-jtcsec/noescope/internal/portabletests"
)

func main() {
	executable, err := os.Executable()
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(2)
	}
	root := filepath.Dir(executable)
	os.Exit(portabletests.RunCLI(context.Background(), root, os.Args[1:], os.Stdout, os.Stderr, portabletests.ProductionBrowserFactory))
}
