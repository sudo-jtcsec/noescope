package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Resolve ${ENV_VAR} references in memory only.
	data = []byte(os.ExpandEnv(string(data)))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Source.Path == "" {
		cfg.Source.Path = "."
	}

	if cfg.Discovery.MaxPages == 0 {
		cfg.Discovery.MaxPages = 500
	}

	return &cfg, nil
}
