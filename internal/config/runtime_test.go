package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeConfigPreservesCredentialEnvironmentReferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noescope.yml")
	data := `project:
  name: fixture
source:
  path: .
application:
  url: https://fallback.example
runtime:
  base_url: https://runtime.example
  browser:
    headless: false
    ignore_tls_errors: true
    executable: /opt/chromium
  identity: admin
identities:
  - id: admin
    username_env: NOESCOPE_USERNAME
    password_env: NOESCOPE_PASSWORD
ai:
  api_key: ${NOESCOPE_TEST_LLM_KEY}
`
	t.Setenv("NOESCOPE_USERNAME", "expanded-user")
	t.Setenv("NOESCOPE_PASSWORD", "expanded-secret")
	t.Setenv("NOESCOPE_TEST_LLM_KEY", "llm-key")
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Runtime.BaseURL != "https://runtime.example" || cfg.Runtime.Browser.Headless ||
		!cfg.Runtime.Browser.IgnoreTLSErrors || cfg.Runtime.Browser.Executable != "/opt/chromium" ||
		cfg.Runtime.Identity != "admin" {
		t.Fatalf("unexpected runtime config: %#v", cfg.Runtime)
	}
	identity, err := cfg.Identity("admin")
	if err != nil {
		t.Fatal(err)
	}
	if identity.UsernameEnv != "NOESCOPE_USERNAME" ||
		identity.PasswordEnv != "NOESCOPE_PASSWORD" {
		t.Fatalf("credential references expanded or changed: %#v", identity)
	}
	if cfg.AI.APIKey != "llm-key" {
		t.Fatalf("AI key expansion changed: %q", cfg.AI.APIKey)
	}
	credentials, err := identity.ResolveCredentials(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Username != "expanded-user" || credentials.Password != "expanded-secret" {
		t.Fatal("runtime credentials were not resolved in memory")
	}
	serialized, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), "expanded-user") || strings.Contains(string(serialized), "expanded-secret") {
		t.Fatalf("runtime credentials are serializable: %s", serialized)
	}
}

func TestRuntimeCredentialsRequireEnvironmentReferences(t *testing.T) {
	identity := IdentityConfig{ID: "admin", UsernameEnv: "literal@example.com", PasswordEnv: "secret"}
	_, err := identity.ResolveCredentials(func(string) (string, bool) { return "value", true })
	if err == nil || !strings.Contains(err.Error(), "environment variable names") {
		t.Fatalf("expected environment reference error, got %v", err)
	}
}

func TestRuntimeConfigRejectsLiteralIdentityCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noescope.yml")
	if err := os.WriteFile(path, []byte(`identities:
  - id: admin
    username: literal-user
    password: literal-secret
`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "must use username_env") {
		t.Fatalf("literal credentials were not rejected: %v", err)
	}
}

func TestRuntimeDefaultsToApplicationURLAndHeadless(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noescope.yml")
	if err := os.WriteFile(path, []byte("application:\n  url: https://app.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Runtime.BaseURL != "https://app.example" || !cfg.Runtime.Browser.Headless {
		t.Fatalf("unexpected runtime defaults: %#v", cfg.Runtime)
	}
}
