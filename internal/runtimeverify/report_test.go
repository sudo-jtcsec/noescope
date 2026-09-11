package runtimeverify

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRuntimeJSONAndMarkdownRendering(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://user:password@app.example/?token=secret")
	if err != nil {
		t.Fatal(err)
	}
	session.Runtime.Application = ApplicationObservation{Reachable: true, Status: StatusVerified}
	session.Runtime.Status = RunStatusCompleted
	session.Runtime.Authentication = AuthenticationObservation{Attempted: true, Status: StatusVerified, Identity: "admin"}
	session.Runtime.Interfaces = []InterfaceObservation{{
		InterfaceID: "web.projects", State: "unauthenticated", Safety: SafetySafe,
		Status: StatusVerified, HTTPStatus: 200, FinalURL: "https://app.example/projects",
	}}
	session.Runtime.Features = FeatureCoverage(application, session.Runtime.Interfaces)
	jsonPath, markdownPath, err := session.Write()
	if err != nil {
		t.Fatal(err)
	}
	rawJSON, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Runtime
	if err := json.Unmarshal(rawJSON, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != SchemaVersion || decoded.SourceRunID != "run_source" ||
		strings.Contains(decoded.BaseURL, "user") || strings.Contains(decoded.BaseURL, "secret") {
		t.Fatalf("unexpected runtime JSON: %#v", decoded)
	}
	rawMarkdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rawMarkdown, []byte("# Runtime Verification")) ||
		!bytes.Contains(rawMarkdown, []byte("`web.projects`")) {
		t.Fatalf("unexpected runtime Markdown: %s", rawMarkdown)
	}
	first := Markdown(session.Runtime)
	second := Markdown(session.Runtime)
	if !bytes.Equal(first, second) {
		t.Fatal("runtime Markdown is not deterministic")
	}
}

func TestPartialRuntimeArtifactRetainsReachabilityAndSanitizedObservationError(t *testing.T) {
	application := runtimeApplicationFixture()
	session, err := NewSession(t.TempDir(), application, "https://app.example/")
	if err != nil {
		t.Fatal(err)
	}
	session.Runtime.Status = RunStatusPartial
	session.Runtime.Application = ApplicationObservation{Reachable: true, Status: StatusVerified}
	session.Runtime.ObservationErrors = []ObservationError{{
		Phase: "application", Operation: "cookies", State: "unauthenticated",
		Message: "inspect cookies: invalid context", EvidenceID: "ev-runtime-1",
	}}
	jsonPath, markdownPath, err := session.Write()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{jsonPath, markdownPath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, []byte("partial")) || !bytes.Contains(raw, []byte("invalid context")) {
			t.Fatalf("partial artifact omitted status or observation error: %s", raw)
		}
	}
}
