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
    totp:
      secret_env: NOESCOPE_TOTP_SECRET
      period: 30
      digits: 6
      algorithm: sha1
ai:
  api_key: ${NOESCOPE_TEST_LLM_KEY}
`
	t.Setenv("NOESCOPE_USERNAME", "expanded-user")
	t.Setenv("NOESCOPE_PASSWORD", "expanded-secret")
	t.Setenv("NOESCOPE_TOTP_SECRET", "expanded-totp-seed")
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
		identity.PasswordEnv != "NOESCOPE_PASSWORD" || identity.TOTP == nil ||
		identity.TOTP.SecretEnv != "NOESCOPE_TOTP_SECRET" || identity.TOTP.Algorithm != "SHA1" {
		t.Fatalf("credential references expanded or changed: %#v", identity)
	}
	identityJSON, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(identityJSON), "expanded-totp-seed") {
		t.Fatalf("identity serialization expanded the TOTP seed: %s", identityJSON)
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

func TestIdentityWithoutTOTPRemainsOptional(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noescope.yml")
	if err := os.WriteFile(path, []byte(`identities:
  - id: admin
    username_env: USER_ENV
    password_env: PASSWORD_ENV
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil || cfg.Identities[0].TOTP != nil {
		t.Fatalf("non-TOTP identity changed: %#v %v", cfg, err)
	}
}

func TestTOTPConfigRejectsLiteralSeedAndInvalidParameters(t *testing.T) {
	values := []string{
		"totp:\n      secret: literal-seed",
		"totp:\n      secret_env: invalid-name!",
		"totp:\n      secret_env: TOTP_SEED\n      period: 1",
		"totp:\n      secret_env: TOTP_SEED\n      digits: 7",
		"totp:\n      secret_env: TOTP_SEED\n      algorithm: MD5",
	}
	for _, value := range values {
		path := filepath.Join(t.TempDir(), "noescope.yml")
		data := "identities:\n  - id: admin\n    username_env: USER_ENV\n    password_env: PASSWORD_ENV\n    " + value + "\n"
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("invalid TOTP configuration was accepted:\n%s", data)
		}
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

func TestTestingConfigParsingAndSafeMutationDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noescope.yml")
	if err := os.WriteFile(path, []byte(`testing:
  enabled: true
  identity: admin
  cleanup: always
  max_core_tests: 12
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Testing.Enabled || cfg.Testing.Identity != "admin" || cfg.Testing.Cleanup != "always" ||
		cfg.Testing.MaxCoreTests != 12 || cfg.Testing.Mutations.Enabled {
		t.Fatalf("unexpected testing config: %#v", cfg.Testing)
	}
}

func TestTestingDefaultsAreNonMutatingAndBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noescope.yml")
	if err := os.WriteFile(path, []byte("project:\n  name: fixture\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Testing.Enabled || cfg.Testing.Mutations.Enabled || cfg.Testing.Cleanup != "always" || cfg.Testing.MaxCoreTests != 20 {
		t.Fatalf("unsafe testing defaults: %#v", cfg.Testing)
	}
}
