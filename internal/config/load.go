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

	// Default before unmarshalling so an explicit headless: false is preserved.
	cfg := Config{Runtime: RuntimeConfig{Browser: RuntimeBrowserConfig{Headless: true}}}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// Preserve the existing in-memory environment expansion for ordinary
	// configuration while intentionally retaining identity credential fields as
	// environment variable names.
	expandConfigEnvironment(&cfg)

	if cfg.Source.Path == "" {
		cfg.Source.Path = "."
	}

	if cfg.Discovery.MaxPages == 0 {
		cfg.Discovery.MaxPages = 500
	}
	if cfg.Runtime.BaseURL == "" {
		cfg.Runtime.BaseURL = cfg.Application.URL
	}
	if cfg.Testing.Cleanup == "" {
		cfg.Testing.Cleanup = "always"
	}
	if cfg.Testing.MaxCoreTests == 0 {
		cfg.Testing.MaxCoreTests = 20
	}

	return &cfg, nil
}

func expandConfigEnvironment(cfg *Config) {
	cfg.Project.Name = os.ExpandEnv(cfg.Project.Name)
	cfg.Source.Path = os.ExpandEnv(cfg.Source.Path)
	for index := range cfg.Source.Ignore {
		cfg.Source.Ignore[index] = os.ExpandEnv(cfg.Source.Ignore[index])
	}
	for index := range cfg.Source.Deny {
		cfg.Source.Deny[index] = os.ExpandEnv(cfg.Source.Deny[index])
	}
	cfg.Application.URL = os.ExpandEnv(cfg.Application.URL)
	cfg.Runtime.BaseURL = os.ExpandEnv(cfg.Runtime.BaseURL)
	cfg.Runtime.Identity = os.ExpandEnv(cfg.Runtime.Identity)
	cfg.Testing.Identity = os.ExpandEnv(cfg.Testing.Identity)
	cfg.Testing.Cleanup = os.ExpandEnv(cfg.Testing.Cleanup)
	for index := range cfg.Identities {
		cfg.Identities[index].ID = os.ExpandEnv(cfg.Identities[index].ID)
		cfg.Identities[index].ExpectedRole = os.ExpandEnv(cfg.Identities[index].ExpectedRole)
	}
	cfg.AI.BaseURL = os.ExpandEnv(cfg.AI.BaseURL)
	cfg.AI.Model = os.ExpandEnv(cfg.AI.Model)
	cfg.AI.APIKey = os.ExpandEnv(cfg.AI.APIKey)
	for index := range cfg.Discovery.AllowedHosts {
		cfg.Discovery.AllowedHosts[index] = os.ExpandEnv(cfg.Discovery.AllowedHosts[index])
	}
}
