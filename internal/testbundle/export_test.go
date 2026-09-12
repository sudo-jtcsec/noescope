package testbundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/config"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/portabletests"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

func TestExportCreatesStandaloneRelocatableBundle(t *testing.T) {
	projectRoot := t.TempDir()
	runRoot := filepath.Join(projectRoot, ".noescope", "runs", "run-1")
	packRoot := filepath.Join(runRoot, "tests", "pack-1")
	application := &model.Application{SchemaVersion: model.SchemaVersion,
		Metadata: model.Metadata{ProjectName: "Fixture", RunID: "run-1", Source: model.SourceMetadata{GitCommit: "commit-1"}},
		Surface: surface.Findings{Interfaces: []surface.Interface{{ID: "auth.login", Type: "web_page", Name: "Login",
			Description: "Login", Locator: surface.InterfaceLocator{Path: "/login", Method: "GET"}}}}}
	test := testsmodel.TestCase{ID: "auth.login.public", Name: "Public Login", Kind: testsmodel.KindCore,
		Description: "Verify login.", InterfaceIDs: []string{"auth.login"}, EntityIDs: []string{}, FeatureIDs: []string{},
		Preconditions: testsmodel.Preconditions{Authentication: "unauthenticated"},
		Steps:         []testsmodel.Step{{Type: "navigate", InterfaceID: "auth.login"}, {Type: "observe"}},
		Assertions:    []testsmodel.Assertion{{Type: "http_status", HTTPStatus: 200}}, Cleanup: []testsmodel.CleanupStep{},
		Safety: testsmodel.SafetyMetadata{Classification: "safe"}, EvidenceIDs: []string{}, GeneratedValues: []testsmodel.ValueReference{}}
	pack := testsmodel.TestPack{SchemaVersion: testsmodel.SchemaVersion, TestPackID: "pack-1", SourceRunID: "run-1",
		RuntimeRunID: "runtime-1", GitCommit: "commit-1", Identity: "admin", GeneratedAt: time.Unix(1, 0).UTC(), Tests: []testsmodel.TestCase{test}}
	execution := testsmodel.Execution{SchemaVersion: testsmodel.SchemaVersion, TestPackID: "pack-1", SourceRunID: "run-1",
		RuntimeRunID: "runtime-1", GitCommit: "commit-1", StartedAt: time.Unix(2, 0).UTC(), CompletedAt: time.Unix(3, 0).UTC(),
		Results: []testsmodel.CandidateResult{{Candidate: test, Status: testsmodel.StatusPassed}}}
	runtime := runtimeverify.Runtime{SchemaVersion: runtimeverify.SchemaVersion, RuntimeID: "runtime-1", SourceRunID: "run-1",
		SourceGitCommit: "commit-1", Status: runtimeverify.RunStatusCompleted, BaseURL: "https://example.test",
		Authentication: runtimeverify.AuthenticationObservation{LoginURL: "https://example.test/login"}}
	writeFixtureJSON(t, filepath.Join(runRoot, "output", "application.json"), application)
	writeFixtureJSON(t, filepath.Join(packRoot, "core-tests.json"), pack)
	writeFixtureJSON(t, filepath.Join(packRoot, "execution.json"), execution)
	if err := os.MkdirAll(packRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packRoot, "evidence.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	writeFixtureJSON(t, filepath.Join(runRoot, "runtime", "runtime-1", "runtime.json"), runtime)
	runner := filepath.Join(t.TempDir(), "runner")
	if err := os.WriteFile(runner, []byte("standalone"), 0755); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle")
	cfg := &config.Config{Project: config.ProjectConfig{Name: "Fixture"}, Testing: config.TestingConfig{Identity: "admin"},
		Identities: []config.IdentityConfig{{ID: "admin", UsernameEnv: "PORTABLE_USER", PasswordEnv: "PORTABLE_PASSWORD",
			TOTP: &config.TOTPConfig{SecretEnv: "PORTABLE_TOTP", Period: 30, Digits: 6, Algorithm: "SHA1"}}}}
	result, err := Export(ExportOptions{ProjectRoot: projectRoot, PackID: "pack-1", Output: output, RunnerPath: runner, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if result.Tests != 1 {
		t.Fatalf("unexpected test count: %d", result.Tests)
	}
	for _, path := range []string{"testpack.json", "testpack.lock.json", "tests/auth.login.public.json", "report.html", "report.md", "runner", "README.md", "runs/onboarding/execution.json"} {
		if _, err := os.Stat(filepath.Join(output, filepath.FromSlash(path))); err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
	}
	if err := os.RemoveAll(runRoot); err != nil {
		t.Fatal(err)
	}
	loaded, err := portabletests.Load(output)
	if err != nil || len(loaded.Tests) != 1 {
		t.Fatalf("bundle depended on removed source application: %#v %v", loaded, err)
	}
	if loaded.Manifest.Identities[0].UsernameEnv != "PORTABLE_USER" || loaded.Manifest.Identities[0].PasswordEnv != "PORTABLE_PASSWORD" {
		t.Fatal("identity references missing")
	}
	if loaded.Manifest.Identities[0].TOTP == nil || loaded.Manifest.Identities[0].TOTP.SecretEnv != "PORTABLE_TOTP" {
		t.Fatal("TOTP environment reference missing from portable bundle")
	}
	err = filepath.Walk(output, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, forbidden := range []string{"actual-user", "actual-password", "ai.base_url", "api_key", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("forbidden value %q in %s", forbidden, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeFixtureJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
