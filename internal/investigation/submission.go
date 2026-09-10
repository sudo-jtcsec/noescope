package investigation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

var canonicalResultFields = map[string]struct{}{
	"status":     {},
	"summary":    {},
	"findings":   {},
	"claims":     {},
	"unresolved": {},
}

type JSONShape struct {
	Bytes  int
	Type   string
	Keys   []string
	Fields []JSONFieldShape
}

type JSONFieldShape struct {
	Name string
	Type string
}

func DescribeJSONShape(raw json.RawMessage) JSONShape {
	shape := JSONShape{Bytes: len(raw), Type: "invalid"}
	if !json.Valid(raw) {
		return shape
	}

	shape.Type = JSONValueKind(raw)
	if shape.Type != "object" {
		return shape
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		shape.Type = "invalid"
		return shape
	}

	shape.Keys = make([]string, 0, len(fields))
	for key := range fields {
		shape.Keys = append(shape.Keys, key)
	}
	sort.Strings(shape.Keys)

	shape.Fields = make([]JSONFieldShape, 0, len(shape.Keys))
	for _, key := range shape.Keys {
		shape.Fields = append(shape.Fields, JSONFieldShape{
			Name: key,
			Type: JSONValueKind(fields[key]),
		})
	}

	return shape
}

func (s JSONShape) Summary() string {
	return fmt.Sprintf(
		"bytes=%d type=%s keys=[%s]",
		s.Bytes,
		s.Type,
		strings.Join(s.Keys, " "),
	)
}

func (s JSONShape) FieldSummary() string {
	parts := make([]string, 0, len(s.Fields))
	for _, field := range s.Fields {
		parts = append(parts, field.Name+"="+field.Type)
	}
	return strings.Join(parts, " ")
}

func parseSubmittedResult(
	raw json.RawMessage,
) (*Result, JSONShape, error) {
	shape := DescribeJSONShape(raw)
	if shape.Type != "object" {
		return nil, shape, fmt.Errorf(
			"submit result: expected object, got %s",
			shape.Type,
		)
	}

	keys := make(map[string]bool, len(shape.Keys))
	unknown := make([]string, 0)
	for _, key := range shape.Keys {
		keys[key] = true
		if _, ok := canonicalResultFields[key]; !ok {
			unknown = append(unknown, key)
		}
	}

	missing := make([]string, 0, 3)
	for _, required := range []string{"status", "summary", "findings"} {
		if !keys[required] {
			missing = append(missing, required)
		}
	}
	if len(missing) > 0 {
		return nil, shape, fmt.Errorf(
			"submit result: expected fields status, summary, findings; got keys [%s]",
			strings.Join(shape.Keys, " "),
		)
	}
	if len(unknown) > 0 {
		return nil, shape, fmt.Errorf(
			"submit result: unexpected fields [%s]",
			strings.Join(unknown, " "),
		)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result Result
	if err := decoder.Decode(&result); err != nil {
		return nil, shape, fmt.Errorf("submit result: %w", err)
	}

	return &result, shape, nil
}
