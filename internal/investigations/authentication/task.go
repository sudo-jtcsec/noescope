package authentication

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
)

var submitSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "status": {
      "type": "string",
      "enum": ["completed", "partial", "blocked"]
    },
    "summary": {"type": "string"},
    "findings": {
      "type": "object",
      "properties": {
        "authentication_present": {"type": "boolean"},
        "confidence": {
          "type": "number",
          "minimum": 0,
          "maximum": 1
        },
        "evidence_ids": {
          "type": "array",
          "items": {"type": "string"}
        },
        "mechanisms": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "id": {"type": "string"},
              "type": {
                "type": "string",
                "enum": [
                  "form_session",
                  "bearer",
                  "basic",
                  "oauth",
                  "oidc",
                  "saml",
                  "api_key",
                  "totp",
                  "custom"
                ]
              },
              "login_entrypoints": {
                "type": "array",
                "items": {"type": "string"}
              },
              "credential_fields": {
                "type": "array",
                "items": {"type": "string"}
              },
              "session": {
                "type": "object",
                "properties": {
                  "type": {"type": "string"},
                  "name": {"type": "string"},
                  "storage": {"type": "string"}
                },
                "required": ["type"],
                "additionalProperties": false
              },
              "established_by": {
                "type": "array",
                "items": {"type": "string"}
              },
              "checked_by": {
                "type": "array",
                "items": {"type": "string"}
              },
              "logout": {
                "type": "object",
                "properties": {
                  "entrypoints": {
                    "type": "array",
                    "items": {"type": "string"}
                  },
                  "behavior": {"type": "string"}
                },
                "required": ["entrypoints", "behavior"],
                "additionalProperties": false
              },
              "source_components": {
                "type": "array",
                "items": {"type": "string"}
              },
              "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 1
              },
              "evidence_ids": {
                "type": "array",
                "items": {"type": "string"}
              }
            },
            "required": [
              "id",
              "type",
              "login_entrypoints",
              "credential_fields",
              "established_by",
              "checked_by",
              "source_components",
              "confidence",
              "evidence_ids"
            ],
            "additionalProperties": false
          }
        }
      },
      "required": [
        "authentication_present",
        "confidence",
        "evidence_ids",
        "mechanisms"
      ],
      "additionalProperties": false
    },
    "claims": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "subject": {"type": "string"},
          "statement": {"type": "string"},
          "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1
          },
          "evidence_ids": {
            "type": "array",
            "items": {"type": "string"}
          }
        },
        "required": [
          "subject",
          "statement",
          "confidence",
          "evidence_ids"
        ],
        "additionalProperties": false
      }
    },
    "unresolved": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "question": {"type": "string"},
          "priority": {"type": "string"},
          "reason": {"type": "string"},
          "suggested_investigation": {"type": "string"},
          "evidence_ids": {
            "type": "array",
            "items": {"type": "string"}
          }
        },
        "required": ["question", "priority", "reason"],
        "additionalProperties": false
      }
    }
  },
  "required": ["status", "summary", "findings"],
  "additionalProperties": false
}`)

var mechanismTypes = map[string]struct{}{
	"form_session": {},
	"bearer":       {},
	"basic":        {},
	"oauth":        {},
	"oidc":         {},
	"saml":         {},
	"api_key":      {},
	"totp":         {},
	"custom":       {},
}

func Task() investigation.Task {
	return investigation.Task{
		ID:   "authentication",
		Name: "Authentication Discovery",

		Objective: `Analyze the source repository and determine how user or client identity is authenticated.

Determine:
- whether authentication exists
- each authentication mechanism in use
- whether a TOTP/OTP second factor is supported and its source-backed invocation entrypoint
- login entrypoints
- credential or input fields, when discoverable
- session or token representation
- how authenticated state is established
- how authenticated state is checked or enforced
- logout entrypoints and behavior
- relevant source components
- unresolved questions

A repository with no authentication is a valid completed result. In that case, return authentication_present=false, a supported confidence and evidence_ids conclusion, and mechanisms=[].

Do not investigate authorization roles, permissions, or access-control policy except where a minimal distinction is necessary to determine whether code performs authentication or authorization.`,

		Instructions: `Use the previously validated Architecture findings to target likely components and avoid rediscovering basic repository structure.

Search for authentication indicators such as login, logout, session, cookie, token, bearer, password, credential, authentication, auth middleware, user identity, TOTP, authenticator, one-time code, and two-factor. Inspect only the most relevant routes, handlers, middleware, services, configuration, and client code.

Report a source-backed TOTP mechanism when support is present, including its entrypoint, credential field, source components, confidence, and evidence. Source support does not prove that TOTP is mandatory for every identity: do not claim a configured identity is required to use TOTP unless source evidence explicitly establishes that fact. Runtime observation decides whether the selected identity is actually challenged.

When concluding authentication is absent, collect representative evidence for that conclusion. Relevant evidence may include targeted searches showing no runtime authentication implementation, inspection of central configuration and entrypoints, or confirmation that outbound API credentials are client credentials only. Do not try to prove a universal negative by reading every file.

Prefer targeted search and bounded file reads. Stop once the authentication behavior can be described confidently. If evidence is incomplete or ambiguous, report the uncertainty under unresolved instead of reading files indefinitely.

The top-level authentication conclusion and every authentication mechanism with confidence greater than zero must reference valid evidence IDs. A negative authentication conclusion always requires evidence. Do not report unsupported mechanisms or behavior. Call submit_investigation_result as soon as the completion criteria are satisfied.`,

		ToolNames: []string{
			"repo_info",
			"list_files",
			"find_files",
			"file_info",
			"read_file",
			"search",
		},

		SubmitSchema:   submitSchema,
		ValidateResult: validateResult,

		Budget: investigation.Budget{
			MaxTurns:           15,
			MaxToolCalls:       100,
			MaxFormatRepairs:   2,
			MaxSemanticRepairs: 2,
			FinalizeTurns:      2,
			MaxDuration:        10 * time.Minute,
		},
	}
}

func Run(
	ctx context.Context,
	runner *investigation.Runner,
	taskContext json.RawMessage,
) (*Findings, *investigation.Result, error) {
	task := Task()
	task.Context = append(json.RawMessage(nil), taskContext...)

	result, err := runner.Run(ctx, task)
	if err != nil {
		return nil, nil, err
	}

	findings, err := decodeFindings(result.Findings)
	if err != nil {
		return nil, result, err
	}

	return findings, result, nil
}

func validateResult(
	result *investigation.Result,
	evidence investigation.EvidenceLookup,
) error {
	findings, err := decodeFindings(result.Findings)
	if err != nil {
		return investigation.NewSubmissionFormatError(err)
	}

	if err := validateEvidence(
		"authentication conclusion",
		findings.Confidence,
		findings.EvidenceIDs,
		evidence,
	); err != nil {
		return err
	}

	if !findings.AuthenticationPresent && len(findings.EvidenceIDs) == 0 {
		return fmt.Errorf(
			"authentication_present is false but the conclusion has no evidence",
		)
	}

	if !findings.AuthenticationPresent && len(findings.Mechanisms) > 0 {
		return fmt.Errorf(
			"authentication_present is false but mechanisms is not empty",
		)
	}

	if findings.AuthenticationPresent && len(findings.Mechanisms) == 0 {
		return fmt.Errorf(
			"authentication_present is true but mechanisms is empty",
		)
	}

	supportedMechanism := false

	for i, mechanism := range findings.Mechanisms {
		name := fmt.Sprintf(
			"mechanisms[%d] %q",
			i,
			mechanism.ID,
		)

		if mechanism.ID == "" {
			return fmt.Errorf("mechanisms[%d] has no id", i)
		}

		if _, ok := mechanismTypes[mechanism.Type]; !ok {
			return fmt.Errorf(
				"%s has invalid type %q",
				name,
				mechanism.Type,
			)
		}

		if err := validateEvidence(
			name,
			mechanism.Confidence,
			mechanism.EvidenceIDs,
			evidence,
		); err != nil {
			return err
		}

		if mechanism.Confidence > 0 {
			supportedMechanism = true
		}
	}

	if findings.AuthenticationPresent && !supportedMechanism {
		return fmt.Errorf(
			"authentication_present is true but no mechanism has positive confidence",
		)
	}

	for i, unresolved := range result.Unresolved {
		for _, evidenceID := range unresolved.EvidenceIDs {
			if !evidence.Exists(evidenceID) {
				return fmt.Errorf(
					"unresolved[%d] references unknown evidence ID %q",
					i,
					evidenceID,
				)
			}
		}
	}

	return nil
}

func decodeFindings(data json.RawMessage) (*Findings, error) {
	var raw struct {
		AuthenticationPresent *bool           `json:"authentication_present"`
		Confidence            *float64        `json:"confidence"`
		EvidenceIDs           json.RawMessage `json:"evidence_ids"`
		Mechanisms            json.RawMessage `json:"mechanisms"`
	}
	if err := investigation.DecodeObjectFindings(
		data,
		&raw,
		"authentication findings",
	); err != nil {
		return nil, err
	}

	if raw.AuthenticationPresent == nil {
		return nil, fmt.Errorf("authentication_present is required")
	}
	if raw.Confidence == nil {
		return nil, fmt.Errorf("authentication confidence is required")
	}
	if err := requireJSONKind(
		"authentication evidence_ids",
		raw.EvidenceIDs,
		"array",
	); err != nil {
		return nil, err
	}
	if err := requireJSONKind("mechanisms", raw.Mechanisms, "array"); err != nil {
		return nil, err
	}

	var rawMechanisms []json.RawMessage
	if err := json.Unmarshal(raw.Mechanisms, &rawMechanisms); err != nil {
		return nil, fmt.Errorf("parse authentication mechanisms: %w", err)
	}
	if rawMechanisms == nil {
		return nil, fmt.Errorf("mechanisms array is required")
	}
	for i, rawMechanism := range rawMechanisms {
		path := fmt.Sprintf("mechanisms[%d]", i)
		if err := requireJSONKind(path, rawMechanism, "object"); err != nil {
			return nil, err
		}

		var fields struct {
			LoginEntrypoints json.RawMessage `json:"login_entrypoints"`
			CredentialFields json.RawMessage `json:"credential_fields"`
			Session          json.RawMessage `json:"session"`
			EstablishedBy    json.RawMessage `json:"established_by"`
			CheckedBy        json.RawMessage `json:"checked_by"`
			Logout           json.RawMessage `json:"logout"`
			SourceComponents json.RawMessage `json:"source_components"`
			EvidenceIDs      json.RawMessage `json:"evidence_ids"`
		}
		if err := investigation.DecodeObjectFindings(
			rawMechanism,
			&fields,
			path,
		); err != nil {
			return nil, err
		}

		for _, field := range []struct {
			name     string
			data     json.RawMessage
			required bool
			kind     string
		}{
			{name: "session", data: fields.Session, kind: "object"},
			{name: "logout", data: fields.Logout, kind: "object"},
			{
				name:     "login_entrypoints",
				data:     fields.LoginEntrypoints,
				required: true,
				kind:     "array",
			},
			{
				name:     "credential_fields",
				data:     fields.CredentialFields,
				required: true,
				kind:     "array",
			},
			{
				name:     "established_by",
				data:     fields.EstablishedBy,
				required: true,
				kind:     "array",
			},
			{
				name:     "checked_by",
				data:     fields.CheckedBy,
				required: true,
				kind:     "array",
			},
			{
				name:     "source_components",
				data:     fields.SourceComponents,
				required: true,
				kind:     "array",
			},
			{
				name:     "evidence_ids",
				data:     fields.EvidenceIDs,
				required: true,
				kind:     "array",
			},
		} {
			if !field.required && len(field.data) == 0 {
				continue
			}
			if err := requireJSONKind(
				path+"."+field.name,
				field.data,
				field.kind,
			); err != nil {
				return nil, err
			}
		}
	}

	var findings Findings
	if err := investigation.DecodeObjectFindings(
		data,
		&findings,
		"authentication findings",
	); err != nil {
		return nil, err
	}
	if findings.EvidenceIDs == nil {
		return nil, fmt.Errorf("authentication evidence_ids array is required")
	}
	if findings.Mechanisms == nil {
		return nil, fmt.Errorf("mechanisms array is required")
	}

	return &findings, nil
}

func requireJSONKind(path string, data json.RawMessage, expected string) error {
	actual := investigation.JSONValueKind(data)
	if actual != expected {
		return fmt.Errorf("%s: expected %s, got %s", path, expected, actual)
	}

	return nil
}

func validateEvidence(
	name string,
	confidence float64,
	evidenceIDs []string,
	evidence investigation.EvidenceLookup,
) error {
	if confidence < 0 || confidence > 1 {
		return fmt.Errorf(
			"%s has invalid confidence %.2f",
			name,
			confidence,
		)
	}

	if confidence > 0 && len(evidenceIDs) == 0 {
		return fmt.Errorf(
			"%s has confidence %.2f but no evidence",
			name,
			confidence,
		)
	}

	for _, evidenceID := range evidenceIDs {
		if !evidence.Exists(evidenceID) {
			return fmt.Errorf(
				"%s references unknown evidence ID %q",
				name,
				evidenceID,
			)
		}
	}

	return nil
}
