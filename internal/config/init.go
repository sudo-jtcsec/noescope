package config

import (
	"fmt"
	"os"
)

const DefaultConfig = `project:
  name: my-app

source:
  path: .
  ignore:
    - .git/**
    - vendor/**
    - node_modules/**
    - dist/**
  deny: []

application:
  url: ""

identities: []

runtime:
  base_url: ""
  browser:
    headless: true
    ignore_tls_errors: false
    executable: ""
  identity: ""

ai:
  base_url: http://localhost:8000/v1
  model: ""
  api_key: ${NOESCOPE_LLM_KEY}

discovery:
  allowed_hosts: []
  external_navigation: false
  destructive_actions: false
  max_pages: 500
`

func Initialize(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}

	if err := os.WriteFile(path, []byte(DefaultConfig), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}
