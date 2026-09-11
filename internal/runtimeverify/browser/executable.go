package browser

import (
	"fmt"
	"os/exec"
	"strings"
)

var defaultExecutableNames = []string{
	"google-chrome",
	"google-chrome-stable",
	"chromium",
	"chromium-browser",
}

func ResolveExecutable(configured string) (string, error) {
	return resolveExecutable(configured, exec.LookPath)
}

func resolveExecutable(
	configured string,
	lookPath func(string) (string, error),
) (string, error) {
	candidates := make([]string, 0, len(defaultExecutableNames)+1)
	if configured != "" {
		candidates = append(candidates, configured)
	}
	for _, name := range defaultExecutableNames {
		duplicate := false
		for _, candidate := range candidates {
			if candidate == name {
				duplicate = true
				break
			}
		}
		if !duplicate {
			candidates = append(candidates, name)
		}
	}
	for _, candidate := range candidates {
		path, err := lookPath(candidate)
		if err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("Chromium executable not found; tried: %s", strings.Join(candidates, ", "))
}
