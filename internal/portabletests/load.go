package portabletests

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var portableID = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
var portableEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Bundle struct {
	Root     string
	Manifest Manifest
	Tests    []Test
	History  []Execution
	Evidence []Evidence
}

func Load(root string) (*Bundle, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := VerifyIntegrity(root); err != nil {
		return nil, err
	}
	var manifest Manifest
	if err := readJSON(filepath.Join(root, "testpack.json"), &manifest); err != nil {
		return nil, err
	}
	if manifest.SchemaVersion != SchemaVersion || manifest.RunnerVersion != RunnerVersion {
		return nil, fmt.Errorf("bundle schema/runner compatibility is %q/%q, runner requires %q/%q",
			manifest.SchemaVersion, manifest.RunnerVersion, SchemaVersion, RunnerVersion)
	}
	if manifest.TestCount != len(manifest.TestIDs) {
		return nil, fmt.Errorf("bundle manifest test count does not match test IDs")
	}
	for _, identity := range manifest.Identities {
		if !portableEnvironmentName.MatchString(identity.UsernameEnv) || !portableEnvironmentName.MatchString(identity.PasswordEnv) {
			return nil, fmt.Errorf("bundle identity %q has invalid credential environment references", identity.ID)
		}
		if identity.TOTP != nil {
			if !portableEnvironmentName.MatchString(identity.TOTP.SecretEnv) {
				return nil, fmt.Errorf("bundle identity %q has invalid TOTP environment reference", identity.ID)
			}
			if identity.TOTP.Period != 0 && (identity.TOTP.Period < 5 || identity.TOTP.Period > 300) {
				return nil, fmt.Errorf("bundle identity %q has invalid TOTP period", identity.ID)
			}
			if identity.TOTP.Digits != 0 && identity.TOTP.Digits != 6 && identity.TOTP.Digits != 8 {
				return nil, fmt.Errorf("bundle identity %q has invalid TOTP digits", identity.ID)
			}
			algorithm := strings.ToUpper(identity.TOTP.Algorithm)
			if algorithm != "" && algorithm != "SHA1" && algorithm != "SHA256" && algorithm != "SHA512" {
				return nil, fmt.Errorf("bundle identity %q has invalid TOTP algorithm", identity.ID)
			}
		}
	}
	if err := verifyRequiredFiles(root, manifest); err != nil {
		return nil, err
	}
	tests := make([]Test, 0, len(manifest.TestIDs))
	seen := map[string]struct{}{}
	for _, testID := range manifest.TestIDs {
		if !portableID.MatchString(testID) {
			return nil, fmt.Errorf("bundle manifest contains invalid test ID %q", testID)
		}
		if _, exists := seen[testID]; exists {
			return nil, fmt.Errorf("bundle manifest duplicates test ID %q", testID)
		}
		seen[testID] = struct{}{}
		var test Test
		if err := readJSON(filepath.Join(root, "tests", testID+".json"), &test); err != nil {
			return nil, err
		}
		if err := ValidateTest(test); err != nil {
			return nil, err
		}
		tests = append(tests, test)
	}
	history, err := LoadHistory(root)
	if err != nil {
		return nil, err
	}
	evidence, err := LoadEvidence(root)
	if err != nil {
		return nil, err
	}
	return &Bundle{Root: root, Manifest: manifest, Tests: tests, History: history, Evidence: evidence}, nil
}

func verifyRequiredFiles(root string, manifest Manifest) error {
	var lock IntegrityLock
	if err := readJSON(filepath.Join(root, "testpack.lock.json"), &lock); err != nil {
		return err
	}
	required := []string{"testpack.json", "runner"}
	for _, id := range manifest.TestIDs {
		required = append(required, filepath.ToSlash(filepath.Join("tests", id+".json")))
	}
	for _, relative := range required {
		if lock.Files[relative] == "" {
			return fmt.Errorf("bundle integrity lock does not cover %s", relative)
		}
	}
	return nil
}

func LoadEvidence(root string) ([]Evidence, error) {
	runsRoot := filepath.Join(root, "runs")
	entries, err := os.ReadDir(runsRoot)
	if os.IsNotExist(err) {
		return []Evidence{}, nil
	}
	if err != nil {
		return nil, err
	}
	values := []Evidence{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		file, err := os.Open(filepath.Join(runsRoot, entry.Name(), "evidence.jsonl"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var raw struct {
				ID          string            `json:"id"`
				Type        string            `json:"type"`
				Kind        string            `json:"kind"`
				TestID      string            `json:"test_id"`
				InterfaceID string            `json:"interface_id"`
				Description string            `json:"description"`
				Summary     string            `json:"summary"`
				URL         string            `json:"url"`
				Attributes  map[string]string `json:"attributes"`
				CreatedAt   time.Time         `json:"created_at"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
				file.Close()
				return nil, err
			}
			kind, description := raw.Type, raw.Description
			if kind == "" {
				kind = raw.Kind
			}
			if description == "" {
				description = raw.Summary
			}
			for key, value := range raw.Attributes {
				lower := strings.ToLower(key)
				if sensitivePortableKey(lower) {
					raw.Attributes[key] = "[REDACTED]"
				} else if strings.Contains(lower, "url") || strings.Contains(lower, "action") || strings.Contains(lower, "location") {
					raw.Attributes[key] = sanitizeURL(value)
				}
			}
			values = append(values, Evidence{ID: raw.ID, Type: kind, TestID: raw.TestID,
				InterfaceID: raw.InterfaceID, Description: description, URL: sanitizeURL(raw.URL),
				Attributes: raw.Attributes, CreatedAt: raw.CreatedAt})
		}
		scanErr := scanner.Err()
		file.Close()
		if scanErr != nil {
			return nil, scanErr
		}
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].CreatedAt.Equal(values[j].CreatedAt) {
			return values[i].ID < values[j].ID
		}
		return values[i].CreatedAt.Before(values[j].CreatedAt)
	})
	return values, nil
}

func sensitivePortableKey(key string) bool {
	for _, term := range []string{"password", "token", "secret", "authorization", "cookie", "api_key", "apikey", "otp", "totp", "one_time", "one-time"} {
		if strings.Contains(key, term) {
			return true
		}
	}
	return false
}

func VerifyIntegrity(root string) error {
	var lock IntegrityLock
	if err := readJSON(filepath.Join(root, "testpack.lock.json"), &lock); err != nil {
		return fmt.Errorf("load bundle integrity lock: %w", err)
	}
	if lock.SchemaVersion != SchemaVersion || lock.RunnerVersion != RunnerVersion {
		return fmt.Errorf("integrity lock is incompatible")
	}
	paths := make([]string, 0, len(lock.Files))
	for path := range lock.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, relative := range paths {
		clean := filepath.Clean(relative)
		if filepath.IsAbs(clean) || clean == ".." || len(clean) >= 3 && clean[:3] == ".."+string(filepath.Separator) {
			return fmt.Errorf("integrity lock contains unsafe path %q", relative)
		}
		raw, err := os.ReadFile(filepath.Join(root, clean))
		if err != nil {
			return fmt.Errorf("verify %s: %w", relative, err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != lock.Files[relative] {
			return fmt.Errorf("bundle integrity check failed for %s", relative)
		}
	}
	return nil
}

func LoadHistory(root string) ([]Execution, error) {
	runsRoot := filepath.Join(root, "runs")
	entries, err := os.ReadDir(runsRoot)
	if os.IsNotExist(err) {
		return []Execution{}, nil
	}
	if err != nil {
		return nil, err
	}
	history := []Execution{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		var execution Execution
		if err := readJSON(filepath.Join(runsRoot, entry.Name(), "execution.json"), &execution); err != nil {
			continue
		}
		history = append(history, execution)
	}
	sort.Slice(history, func(i, j int) bool {
		if history[i].CompletedAt.Equal(history[j].CompletedAt) {
			return history[i].ExecutionID < history[j].ExecutionID
		}
		return history[i].CompletedAt.Before(history[j].CompletedAt)
	})
	return history, nil
}

func LatestResults(bundle *Bundle) map[string]Result {
	latest := map[string]Result{}
	for _, execution := range bundle.History {
		for _, result := range execution.Results {
			latest[result.TestID] = result
		}
	}
	return latest
}

func ValidateTest(test Test) error {
	if test.SchemaVersion != SchemaVersion || !portableID.MatchString(test.ID) || test.Name == "" || test.Description == "" {
		return fmt.Errorf("portable test %q is incomplete or incompatible", test.ID)
	}
	interfaces := map[string]struct{}{}
	for _, item := range test.Interfaces {
		if item.ID == "" || item.Path == "" {
			return fmt.Errorf("portable test %q has incomplete interface binding %q", test.ID, item.ID)
		}
		interfaces[item.ID] = struct{}{}
	}
	for _, id := range test.InterfaceIDs {
		if _, ok := interfaces[id]; !ok {
			return fmt.Errorf("portable test %q lacks execution binding for interface %q", test.ID, id)
		}
	}
	return nil
}

func readJSON(path string, destination any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
