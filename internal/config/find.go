package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const ConfigFilename = "noescope.yml"

func Find(start string) (string, error) {
	current, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}

	for {
		candidate := filepath.Join(current, ConfigFilename)

		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}

		current = parent
	}

	return "", fmt.Errorf("%s not found", ConfigFilename)
}
