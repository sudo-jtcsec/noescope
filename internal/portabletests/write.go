package portabletests

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func WriteJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWrite(path, append(raw, '\n'), 0600)
}

func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".portable-test-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func BuildIntegrity(root string, relativeFiles []string) (IntegrityLock, error) {
	lock := IntegrityLock{SchemaVersion: SchemaVersion, RunnerVersion: RunnerVersion, Files: map[string]string{}}
	for _, relative := range relativeFiles {
		raw, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			return lock, fmt.Errorf("hash %s: %w", relative, err)
		}
		sum := sha256.Sum256(raw)
		lock.Files[filepath.ToSlash(relative)] = hex.EncodeToString(sum[:])
	}
	return lock, nil
}

func writeEvidence(path string, values []Evidence) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".portable-evidence-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	writer := bufio.NewWriter(temporary)
	encoder := json.NewEncoder(writer)
	for _, value := range values {
		if err := encoder.Encode(value); err != nil {
			temporary.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
