package runtimeverify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeRedactionRemovesHeadersTokensURLsAndConfiguredSecrets(t *testing.T) {
	redactor := NewRedactor("test-user", "super-secret")
	value := redactor.String("Authorization: Bearer abc.def Cookie: sid=super-secret user=test-user")
	if strings.Contains(value, "abc.def") || strings.Contains(value, "super-secret") ||
		strings.Contains(value, "test-user") {
		t.Fatalf("secret remained after redaction: %q", value)
	}
	url := redactor.URL("https://test-user:super-secret@app.example/path?token=abc&view=list#fragment")
	if strings.Contains(url, "test-user") || strings.Contains(url, "super-secret") ||
		strings.Contains(url, "abc") || strings.Contains(url, "fragment") {
		t.Fatalf("URL was not sanitized: %q", url)
	}
}

func TestRuntimeEvidenceNeverPersistsSecrets(t *testing.T) {
	root := t.TempDir()
	store := NewEvidenceStore(root, NewRedactor("alice", "super-secret"))
	_, err := store.Add(EvidenceRecord{
		Kind: "network_request", Summary: "alice sent Authorization: Bearer super-secret",
		URL: "https://alice:super-secret@app.example/?api_key=super-secret",
		Attributes: map[string]string{
			"Cookie": "session=super-secret", "location_url": "https://app.example/?token=super-secret",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alice", "super-secret"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("runtime evidence contains secret %q: %s", secret, raw)
		}
	}
}
