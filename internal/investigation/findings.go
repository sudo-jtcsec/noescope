package investigation

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// NormalizeFindings accepts canonical object findings as-is and handles one
// local-model compatibility case: a JSON string whose decoded contents are a
// JSON object. It never recursively unwraps strings or accepts another JSON
// value type.
func NormalizeFindings(
	raw json.RawMessage,
) (json.RawMessage, bool, error) {
	if !json.Valid(raw) {
		return nil, false, fmt.Errorf("findings: invalid JSON")
	}

	switch JSONValueKind(raw) {
	case "object":
		return raw, false, nil
	case "string":
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return nil, false, fmt.Errorf(
				"findings: decode JSON string: %w",
				err,
			)
		}

		decoded := json.RawMessage(bytes.TrimSpace([]byte(encoded)))
		if !json.Valid(decoded) {
			return nil, false, fmt.Errorf(
				"findings: JSON string does not contain valid JSON",
			)
		}
		if kind := JSONValueKind(decoded); kind != "object" {
			return nil, false, fmt.Errorf(
				"findings: decoded string must contain object, got %s",
				kind,
			)
		}

		return append(json.RawMessage(nil), decoded...), true, nil
	default:
		return nil, false, fmt.Errorf(
			"findings: expected object, got %s",
			JSONValueKind(raw),
		)
	}
}

// DecodeObjectFindings requires canonical findings to be a JSON object before
// decoding it into a concrete findings type. It remains strict; callers that
// intentionally support one-level normalization must do so first.
func DecodeObjectFindings(
	raw json.RawMessage,
	destination any,
	label string,
) error {
	kind := JSONValueKind(raw)
	if kind != "object" {
		return fmt.Errorf("%s: expected object, got %s", label, kind)
	}

	if err := json.Unmarshal(raw, destination); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}

	return nil
}

// JSONValueKind returns the JSON value kind without exposing its contents.
func JSONValueKind(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "missing"
	}

	switch trimmed[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		return "number"
	}
}
