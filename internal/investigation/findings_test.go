package investigation

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeFindingsLeavesObjectUnchanged(t *testing.T) {
	raw := json.RawMessage("  {\"present\":true}  ")

	normalized, changed, err := NormalizeFindings(raw)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("object findings were reported as normalized")
	}
	if !bytes.Equal(normalized, raw) {
		t.Fatalf("object findings changed: %q", normalized)
	}
}

func TestNormalizeFindingsDecodesOneStringLevel(t *testing.T) {
	raw := json.RawMessage(`"{\"present\":true}"`)

	normalized, changed, err := NormalizeFindings(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("normalization was not reported")
	}
	if string(normalized) != `{"present":true}` {
		t.Fatalf("unexpected normalized findings: %s", normalized)
	}
}

func TestNormalizeFindingsRejectsInvalidStringContents(t *testing.T) {
	for name, raw := range map[string]json.RawMessage{
		"text":             json.RawMessage(`"hello"`),
		"array":            json.RawMessage(`"[1,2,3]"`),
		"null":             json.RawMessage(`"null"`),
		"recursive string": json.RawMessage(`"\"{\\\"present\\\":true}\""`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, changed, err := NormalizeFindings(raw); err == nil {
				t.Fatal("expected normalization rejection")
			} else if changed {
				t.Fatal("rejected findings were reported as normalized")
			}
		})
	}
}

func TestDecodeObjectFindingsAcceptsObject(t *testing.T) {
	var findings struct {
		Present bool `json:"present"`
	}

	if err := DecodeObjectFindings(
		json.RawMessage(`{"present":true}`),
		&findings,
		"test findings",
	); err != nil {
		t.Fatal(err)
	}
	if !findings.Present {
		t.Fatal("object findings were not decoded")
	}
}

func TestDecodeObjectFindingsRejectsNonObjects(t *testing.T) {
	for name, raw := range map[string]json.RawMessage{
		"string": json.RawMessage(`"{}"`),
		"array":  json.RawMessage(`[]`),
		"null":   json.RawMessage(`null`),
	} {
		t.Run(name, func(t *testing.T) {
			var findings struct{}
			err := DecodeObjectFindings(raw, &findings, "test findings")
			if err == nil || !strings.Contains(
				err.Error(),
				"test findings: expected object, got "+name,
			) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
