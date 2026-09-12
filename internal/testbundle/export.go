package testbundle

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/config"
	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/portabletests"
	"github.com/sudo-jtcsec/noescope/internal/runtimeverify"
	"github.com/sudo-jtcsec/noescope/internal/testsmodel"
)

type ExportOptions struct {
	ProjectRoot string
	PackID      string
	Output      string
	RunnerPath  string
	Config      *config.Config
}

type Result struct {
	Root       string
	Tests      int
	RunnerPath string
	HTMLPath   string
	Markdown   string
}

func Export(options ExportOptions) (*Result, error) {
	if options.PackID == "" || options.Output == "" || options.Config == nil {
		return nil, fmt.Errorf("export requires a pack ID, output directory, and configuration")
	}
	packRoot, sourceRunRoot, err := locatePack(options.ProjectRoot, options.PackID)
	if err != nil {
		return nil, err
	}
	var pack testsmodel.TestPack
	if err := readJSON(filepath.Join(packRoot, "core-tests.json"), &pack); err != nil {
		return nil, err
	}
	var sourceExecution testsmodel.Execution
	if err := readJSON(filepath.Join(packRoot, "execution.json"), &sourceExecution); err != nil {
		return nil, err
	}
	var application model.Application
	if err := readJSON(filepath.Join(sourceRunRoot, "output", "application.json"), &application); err != nil {
		return nil, err
	}
	if err := testsmodel.ValidatePack(&pack, &application); err != nil {
		return nil, err
	}
	var runtime runtimeverify.Runtime
	if err := readJSON(filepath.Join(sourceRunRoot, "runtime", pack.RuntimeRunID, "runtime.json"), &runtime); err != nil {
		return nil, err
	}
	if runtime.Status != runtimeverify.RunStatusCompleted || runtime.SourceRunID != pack.SourceRunID || runtime.SourceGitCommit != pack.GitCommit {
		return nil, fmt.Errorf("source runtime is not compatible and completed")
	}
	tests := unionTests(pack.Tests, sourceExecution.Results)
	portable := make([]portabletests.Test, 0, len(tests))
	for _, test := range tests {
		converted, err := convertTest(test, &application, options.Config.Testing.Identity)
		if err != nil {
			return nil, err
		}
		portable = append(portable, converted)
	}
	sort.Slice(portable, func(i, j int) bool { return portable[i].ID < portable[j].ID })
	identities := []portabletests.IdentityReference{}
	for _, identity := range options.Config.Identities {
		if identity.ID == options.Config.Testing.Identity {
			reference := portabletests.IdentityReference{ID: identity.ID,
				UsernameEnv: identity.UsernameEnv, PasswordEnv: identity.PasswordEnv}
			if identity.TOTP != nil {
				reference.TOTP = &portabletests.TOTPReference{SecretEnv: identity.TOTP.SecretEnv,
					Period: identity.TOTP.Period, Digits: identity.TOTP.Digits, Algorithm: identity.TOTP.Algorithm}
			}
			identities = append(identities, reference)
		}
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("testing identity %q is not configured", options.Config.Testing.Identity)
	}
	manifest := portabletests.Manifest{
		SchemaVersion: portabletests.SchemaVersion, RunnerVersion: portabletests.RunnerVersion,
		PackID: pack.TestPackID, Project: application.Metadata.ProjectName,
		SourceRunID: pack.SourceRunID, RuntimeRunID: pack.RuntimeRunID, SourceCommit: pack.GitCommit,
		CreatedAt: pack.GeneratedAt.UTC(), DefaultTarget: runtime.BaseURL, TestCount: len(portable),
		Identities: identities, Authentication: portabletests.Authentication{LoginPath: loginPath(runtime)},
		Provenance: portabletests.Provenance{Generator: "noescope", SourceTestPackID: pack.TestPackID,
			SourceRunID: pack.SourceRunID, RuntimeRunID: pack.RuntimeRunID},
	}
	for _, test := range portable {
		manifest.TestIDs = append(manifest.TestIDs, test.ID)
	}
	output, err := prepareOutput(options.Output)
	if err != nil {
		return nil, err
	}
	if err := portabletests.WriteJSON(filepath.Join(output, "testpack.json"), manifest); err != nil {
		return nil, err
	}
	hashFiles := []string{"testpack.json"}
	for _, test := range portable {
		relative := filepath.ToSlash(filepath.Join("tests", test.ID+".json"))
		if err := portabletests.WriteJSON(filepath.Join(output, filepath.FromSlash(relative)), test); err != nil {
			return nil, err
		}
		hashFiles = append(hashFiles, relative)
	}
	if err := copyFile(options.RunnerPath, filepath.Join(output, "runner"), 0755); err != nil {
		return nil, err
	}
	hashFiles = append(hashFiles, "runner")
	onboarding := convertExecution(pack, sourceExecution, portable, runtime.BaseURL)
	onboardingRoot := filepath.Join(output, "runs", "onboarding")
	if err := portabletests.WriteJSON(filepath.Join(onboardingRoot, "execution.json"), onboarding); err != nil {
		return nil, err
	}
	if err := copyEvidence(filepath.Join(packRoot, "evidence.jsonl"), filepath.Join(onboardingRoot, "evidence.jsonl")); err != nil {
		return nil, err
	}
	evidence, err := portabletests.LoadEvidence(output)
	if err != nil {
		return nil, err
	}
	bundle := &portabletests.Bundle{Root: output, Manifest: manifest, Tests: portable,
		History: []portabletests.Execution{onboarding}, Evidence: evidence}
	if err := portabletests.WriteBundleReports(output, bundle); err != nil {
		return nil, err
	}
	if err := portabletests.WriteReports(onboardingRoot, bundle); err != nil {
		return nil, err
	}
	if err := portabletests.AtomicWrite(filepath.Join(output, "README.md"), readme(manifest), 0644); err != nil {
		return nil, err
	}
	lock, err := portabletests.BuildIntegrity(output, hashFiles)
	if err != nil {
		return nil, err
	}
	if err := portabletests.WriteJSON(filepath.Join(output, "testpack.lock.json"), lock); err != nil {
		return nil, err
	}
	if err := portabletests.VerifyIntegrity(output); err != nil {
		return nil, err
	}
	return &Result{Root: output, Tests: len(portable), RunnerPath: filepath.Join(output, "runner"),
		HTMLPath: filepath.Join(output, "report.html"), Markdown: filepath.Join(output, "report.md")}, nil
}

func locatePack(projectRoot, packID string) (string, string, error) {
	runsRoot := filepath.Join(projectRoot, ".noescope", "runs")
	entries, err := os.ReadDir(runsRoot)
	if err != nil {
		return "", "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runRoot := filepath.Join(runsRoot, entry.Name())
		packRoot := filepath.Join(runRoot, "tests", packID)
		if info, err := os.Stat(packRoot); err == nil && info.IsDir() {
			return packRoot, runRoot, nil
		}
	}
	return "", "", fmt.Errorf("Core Test Pack %q was not found", packID)
}

func unionTests(verified []testsmodel.TestCase, results []testsmodel.CandidateResult) []testsmodel.TestCase {
	byID := map[string]testsmodel.TestCase{}
	for _, test := range verified {
		byID[test.ID] = test
	}
	for _, result := range results {
		byID[result.Candidate.ID] = result.Candidate
	}
	values := make([]testsmodel.TestCase, 0, len(byID))
	for _, test := range byID {
		values = append(values, test)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values
}

func convertTest(test testsmodel.TestCase, application *model.Application, identity string) (portabletests.Test, error) {
	if err := testsmodel.ValidateTest(test, application); err != nil {
		return portabletests.Test{}, err
	}
	result := portabletests.Test{SchemaVersion: portabletests.SchemaVersion, ID: test.ID, Name: test.Name,
		Kind: test.Kind, Description: test.Description, Identity: identity,
		FeatureIDs: append([]string(nil), test.FeatureIDs...), InterfaceIDs: append([]string(nil), test.InterfaceIDs...),
		EntityIDs: append([]string(nil), test.EntityIDs...), Preconditions: portabletests.Preconditions{Authentication: test.Preconditions.Authentication},
		EvidenceIDs: append([]string(nil), test.EvidenceIDs...), Safety: portabletests.Safety{
			Classification: test.Safety.Classification, Mutating: test.Safety.Mutating,
			RequiresOwnedData: test.Safety.RequiresOwnedData, CleanupRequired: test.Safety.CleanupRequired,
			SelectionScore: test.Safety.SelectionScore, SelectionReasons: append([]string(nil), test.Safety.SelectionReasons...)},
	}
	interfaces := map[string]portabletests.Interface{}
	for _, item := range application.Surface.Interfaces {
		interfaces[item.ID] = portabletests.Interface{ID: item.ID, Type: item.Type, Name: item.Name,
			Path: item.Locator.Path, Method: item.Locator.Method, EntityIDs: append([]string(nil), item.EntityIDs...)}
	}
	for _, id := range test.InterfaceIDs {
		item, ok := interfaces[id]
		if !ok {
			return portabletests.Test{}, fmt.Errorf("test %q lacks canonical interface %q", test.ID, id)
		}
		result.Interfaces = append(result.Interfaces, item)
	}
	for _, value := range test.GeneratedValues {
		result.GeneratedValues = append(result.GeneratedValues, portabletests.ValueReference(value))
	}
	for _, step := range test.Steps {
		converted := portabletests.Step{Type: step.Type, InterfaceID: step.InterfaceID, Field: step.Field, Target: step.Target}
		if step.Value != nil {
			value := portabletests.ValueReference(*step.Value)
			converted.Value = &value
		}
		result.Steps = append(result.Steps, converted)
	}
	for _, assertion := range test.Assertions {
		result.Assertions = append(result.Assertions, portabletests.Assertion(assertion))
	}
	for _, cleanup := range test.Cleanup {
		result.Cleanup = append(result.Cleanup, portabletests.CleanupStep(cleanup))
	}
	if err := portabletests.ValidateTest(result); err != nil {
		return portabletests.Test{}, err
	}
	return result, nil
}

func convertExecution(pack testsmodel.TestPack, source testsmodel.Execution, tests []portabletests.Test, target string) portabletests.Execution {
	byID := map[string]testsmodel.CandidateResult{}
	for _, result := range source.Results {
		byID[result.Candidate.ID] = result
	}
	verified := map[string]struct{}{}
	for _, test := range pack.Tests {
		verified[test.ID] = struct{}{}
	}
	execution := portabletests.Execution{SchemaVersion: portabletests.SchemaVersion,
		ExecutionID: "onboarding_" + pack.TestPackID, PackID: pack.TestPackID, Target: target,
		StartedAt: source.StartedAt.UTC(), CompletedAt: source.CompletedAt.UTC(), Results: []portabletests.Result{}}
	for _, test := range tests {
		execution.SelectedIDs = append(execution.SelectedIDs, test.ID)
		if result, ok := byID[test.ID]; ok {
			converted := portabletests.Result{TestID: test.ID, Mutating: test.Safety.Mutating, Status: result.Status, Reason: result.Reason,
				WorkflowFailure: result.WorkflowFailure, CleanupFailure: result.CleanupFailure,
				EvidenceIDs: append([]string(nil), result.EvidenceIDs...)}
			for _, object := range result.OwnedObjects {
				converted.OwnedObjects = append(converted.OwnedObjects, portabletests.OwnedObject{
					OwnershipID: object.OwnershipID, ExecutionID: object.ExecutionID, EntityID: object.EntityID,
					TestID: object.CreatedByTestID, RuntimeIdentifier: object.RuntimeIdentifier,
					GeneratedFields: object.GeneratedFields, CleanupStatus: object.CleanupStatus})
			}
			execution.Results = append(execution.Results, converted)
		} else if _, ok := verified[test.ID]; ok {
			execution.Results = append(execution.Results, portabletests.Result{TestID: test.ID, Mutating: test.Safety.Mutating, Status: portabletests.StatusPassed,
				EvidenceIDs: append([]string(nil), test.EvidenceIDs...)})
		} else {
			execution.Results = append(execution.Results, portabletests.Result{TestID: test.ID, Mutating: test.Safety.Mutating, Status: portabletests.StatusNotRun})
		}
	}
	execution.Summary = portableSummary(execution.Results)
	return execution
}

func portableSummary(results []portabletests.Result) portabletests.Summary {
	s := portabletests.Summary{Total: len(results)}
	for _, result := range results {
		switch result.Status {
		case portabletests.StatusPassed:
			s.Passed++
		case portabletests.StatusFailed:
			s.Failed++
		case portabletests.StatusBlocked:
			s.Blocked++
		case portabletests.StatusCleanupFailed:
			s.CleanupFailed++
		case portabletests.StatusUnresolved:
			s.Unresolved++
		default:
			s.NotRun++
		}
	}
	return s
}

func loginPath(runtime runtimeverify.Runtime) string {
	parsed, err := url.Parse(runtime.Authentication.LoginURL)
	if err == nil && parsed.Path != "" {
		return parsed.EscapedPath()
	}
	return "/login"
}

func prepareOutput(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if entries, err := os.ReadDir(absolute); err == nil && len(entries) > 0 {
		return "", fmt.Errorf("export output %q is not empty", absolute)
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(absolute, 0755); err != nil {
		return "", err
	}
	return absolute, nil
}

func copyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open standalone runner: %w", err)
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func copyEvidence(source, destination string) error {
	input, err := os.Open(source)
	if os.IsNotExist(err) {
		return portabletests.AtomicWrite(destination, nil, 0600)
	}
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(input)
	writer := bufio.NewWriter(output)
	for scanner.Scan() {
		var record map[string]any
		if json.Unmarshal(scanner.Bytes(), &record) != nil {
			output.Close()
			return fmt.Errorf("source evidence is malformed")
		}
		scrubEvidenceMap(record)
		raw, _ := json.Marshal(record)
		if _, err := writer.Write(append(raw, '\n')); err != nil {
			output.Close()
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		output.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func scrubEvidenceMap(values map[string]any) {
	for key, value := range values {
		lower := strings.ToLower(key)
		if sensitiveKey(lower) {
			values[key] = "[REDACTED]"
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			scrubEvidenceMap(typed)
		case []any:
			for index, item := range typed {
				if nested, ok := item.(map[string]any); ok {
					scrubEvidenceMap(nested)
				} else if strings.Contains(lower, "url") || strings.Contains(lower, "action") || strings.Contains(lower, "location") {
					if text, ok := item.(string); ok {
						typed[index] = scrubURL(text)
					}
				}
			}
		case string:
			if strings.Contains(lower, "url") || strings.Contains(lower, "action") || strings.Contains(lower, "location") {
				values[key] = scrubURL(typed)
			}
		}
	}
}

func sensitiveKey(key string) bool {
	for _, term := range []string{"password", "token", "secret", "authorization", "cookie", "api_key", "apikey", "otp", "totp", "one_time", "one-time"} {
		if strings.Contains(key, term) {
			return true
		}
	}
	return false
}

func scrubURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	parsed.User = nil
	query := parsed.Query()
	for key := range query {
		if sensitiveKey(strings.ToLower(key)) {
			query.Set(key, "[REDACTED]")
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func readme(manifest portabletests.Manifest) []byte {
	totpNote := ""
	for _, identity := range manifest.Identities {
		if identity.TOTP != nil {
			totpNote = fmt.Sprintf(" If a TOTP challenge is observed, set %s in the runner environment.", identity.TOTP.SecretEnv)
			break
		}
	}
	return []byte(fmt.Sprintf(`# Portable Core Test Pack

This directory is self-contained. It does not require Noescope, source discovery artifacts, or an LLM.

Default target: %s

Commands:

    ./runner list
    ./runner show <test-id>
    ./runner test
    ./runner test --test <test-id>
    ./runner test --base-url https://staging.example.com
    ./runner serve

Credentials are resolved only at execution time from the environment-variable names in testpack.json.%s Mutating tests are disabled unless the runner is invoked with --mutations. When all tests are run, blocked mutating tests do not fail an otherwise passing read-only CI run. An explicitly selected blocked test returns a non-zero exit code.
`, manifest.DefaultTarget, totpNote))
}

func readJSON(path string, value any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, value); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
