package authorization

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
        "authorization_present": {"type": "boolean"},
        "confidence": {
          "type": "number",
          "minimum": 0,
          "maximum": 1
        },
        "evidence_ids": {
          "type": "array",
          "items": {"type": "string"}
        },
        "model": {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "enum": [
                "rbac",
                "permission_based",
                "acl",
                "abac",
                "role_hierarchy",
                "custom",
                "unknown"
              ]
            },
            "description": {"type": "string"},
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
          "required": ["type", "description", "confidence", "evidence_ids"]
        },
        "roles": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "id": {"type": "string"},
              "name": {"type": "string"},
              "description": {"type": "string"},
              "inherits": {
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
              "name",
              "description",
              "inherits",
              "confidence",
              "evidence_ids"
            ]
          }
        },
        "permissions": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "id": {"type": "string"},
              "name": {"type": "string"},
              "description": {"type": "string"},
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
              "name",
              "description",
              "confidence",
              "evidence_ids"
            ]
          }
        },
        "role_permissions": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "role_id": {"type": "string"},
              "permission_ids": {
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
              "role_id",
              "permission_ids",
              "confidence",
              "evidence_ids"
            ]
          }
        },
        "enforcement": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "type": {
                "type": "string",
                "enum": [
                  "function",
                  "middleware",
                  "controller",
                  "route",
                  "template",
                  "policy",
                  "annotation",
                  "database",
                  "custom"
                ]
              },
              "name": {"type": "string"},
              "path": {"type": "string"},
              "symbol": {"type": "string"},
              "description": {"type": "string"},
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
              "type",
              "name",
              "description",
              "confidence",
              "evidence_ids"
            ]
          }
        }
      },
      "required": [
        "authorization_present",
        "confidence",
        "evidence_ids",
        "roles",
        "permissions",
        "role_permissions",
        "enforcement"
      ]
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
        ]
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
        "required": ["question", "priority", "reason"]
      }
    }
  },
  "required": ["status", "summary", "findings"]
}`)

var modelTypes = map[string]struct{}{
	"rbac":             {},
	"permission_based": {},
	"acl":              {},
	"abac":             {},
	"role_hierarchy":   {},
	"custom":           {},
	"unknown":          {},
}

var enforcementTypes = map[string]struct{}{
	"function":   {},
	"middleware": {},
	"controller": {},
	"route":      {},
	"template":   {},
	"policy":     {},
	"annotation": {},
	"database":   {},
	"custom":     {},
}

func Task() investigation.Task {
	return investigation.Task{
		ID:   "authorization",
		Name: "Authorization Discovery",

		Objective: `Analyze the source repository and document its intended application-user authorization model.

Authorization answers "What is this authenticated user or client allowed to do?" Authentication only answers "Who is the user or client?" Keep these concepts separate. Login, session, token, or identity checks alone are not authorization.

Determine:
- whether an application-user authorization system exists
- the authorization model
- roles
- permissions or capabilities
- role-to-permission relationships
- role hierarchy or inheritance, when present
- authorization enforcement mechanisms and check locations
- relevant source components
- unresolved questions

A repository with no user authorization system is a valid completed result. In that case, return authorization_present=false with a supported confidence and evidence_ids conclusion, omit model, and return roles=[], permissions=[], role_permissions=[], and enforcement=[].

Filesystem permissions, Go visibility, repository-hosting permissions, LLM or service API keys, and CLI configuration do not by themselves constitute application-user authorization. In particular, using an API key to authenticate an outbound LLM or service request is authentication of that client request, not authorization of an application user.`,

		Instructions: `Use the previously validated Architecture and Authentication findings to target the most likely components without rediscovering the repository structure or re-investigating authentication.

Search selectively for role, roles, permission, permissions, capability, capabilities, authorize, authorization, access, allowed, denied, forbidden, policy, policies, ACL, RBAC, admin, isAdmin, hasPermission, canAccess, middleware, 403, owner, and ownership. Inspect likely route, middleware, controller, policy, template, database, and helper code only where search results warrant it.

Do not classify documentation, test fixtures, investigation prompts/schemas, or code that merely searches for or describes authorization as an authorization system. Require evidence that application runtime behavior actually grants, denies, or limits user actions.

If Authentication reports authentication_present=false, treat that as a strong hint but not proof that authorization is absent. Verify against source. When reporting authorization_present=false, collect representative evidence for the conclusion without fabricating roles, permissions, or enforcement records. Relevant evidence may include targeted searches showing no runtime authorization enforcement, inspection of central configuration and request handling, or confirmation that apparent credentials are only outbound client credentials. Do not try to prove a universal negative by reading every file.

Document only the intended authorization model. Do not investigate business functionality, build a feature hierarchy, perform security analysis, or look for authorization bypasses.

Prefer targeted search and bounded reads. Stop once the authorization system can be described confidently. Report ambiguity under unresolved instead of continuing indefinitely.

The top-level authorization conclusion and every model, role, permission, role-permission mapping, and enforcement record with confidence greater than zero must reference valid evidence IDs. A negative authorization conclusion always requires evidence. Call submit_investigation_result as soon as the completion criteria are satisfied.`,

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
			MaxTurns:         15,
			MaxToolCalls:     100,
			MaxResultRepairs: 2,
			FinalizeTurns:    2,
			MaxDuration:      10 * time.Minute,
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

	var findings Findings
	if err := json.Unmarshal(result.Findings, &findings); err != nil {
		return nil, result, fmt.Errorf(
			"parse authorization findings: %w",
			err,
		)
	}

	return &findings, result, nil
}

func validateResult(
	result *investigation.Result,
	evidence investigation.EvidenceLookup,
) error {
	findings, err := decodeFindings(result.Findings)
	if err != nil {
		return err
	}

	if err := validateEvidence(
		"authorization conclusion",
		findings.Confidence,
		findings.EvidenceIDs,
		evidence,
	); err != nil {
		return err
	}

	if !findings.AuthorizationPresent && len(findings.EvidenceIDs) == 0 {
		return fmt.Errorf(
			"authorization_present is false but the conclusion has no evidence",
		)
	}

	if !findings.AuthorizationPresent {
		if findings.Model != nil ||
			len(findings.Roles) > 0 ||
			len(findings.Permissions) > 0 ||
			len(findings.RolePermissions) > 0 ||
			len(findings.Enforcement) > 0 {
			return fmt.Errorf(
				"authorization_present is false but authorization findings are not empty",
			)
		}

		return validateUnresolved(result.Unresolved, evidence)
	}

	if findings.Model == nil {
		return fmt.Errorf(
			"authorization_present is true but model is missing",
		)
	}

	supportedFinding := false
	if _, ok := modelTypes[findings.Model.Type]; !ok {
		return fmt.Errorf(
			"model has invalid type %q",
			findings.Model.Type,
		)
	}
	if err := validateEvidence(
		"model",
		findings.Model.Confidence,
		findings.Model.EvidenceIDs,
		evidence,
	); err != nil {
		return err
	}
	if findings.Model.Confidence > 0 {
		supportedFinding = true
	}

	roleIDs := make(map[string]struct{}, len(findings.Roles))
	for i, role := range findings.Roles {
		name := fmt.Sprintf("roles[%d] %q", i, role.ID)
		if role.ID == "" {
			return fmt.Errorf("roles[%d] has no id", i)
		}
		if _, exists := roleIDs[role.ID]; exists {
			return fmt.Errorf("duplicate role ID %q", role.ID)
		}
		roleIDs[role.ID] = struct{}{}

		if err := validateEvidence(
			name,
			role.Confidence,
			role.EvidenceIDs,
			evidence,
		); err != nil {
			return err
		}
		if role.Confidence > 0 {
			supportedFinding = true
		}
	}

	permissionIDs := make(map[string]struct{}, len(findings.Permissions))
	for i, permission := range findings.Permissions {
		name := fmt.Sprintf("permissions[%d] %q", i, permission.ID)
		if permission.ID == "" {
			return fmt.Errorf("permissions[%d] has no id", i)
		}
		if _, exists := permissionIDs[permission.ID]; exists {
			return fmt.Errorf(
				"duplicate permission ID %q",
				permission.ID,
			)
		}
		permissionIDs[permission.ID] = struct{}{}

		if err := validateEvidence(
			name,
			permission.Confidence,
			permission.EvidenceIDs,
			evidence,
		); err != nil {
			return err
		}
		if permission.Confidence > 0 {
			supportedFinding = true
		}
	}

	for i, role := range findings.Roles {
		for _, inheritedRoleID := range role.Inherits {
			if _, ok := roleIDs[inheritedRoleID]; !ok {
				return fmt.Errorf(
					"roles[%d] %q inherits unknown role %q",
					i,
					role.ID,
					inheritedRoleID,
				)
			}
		}
	}

	for i, mapping := range findings.RolePermissions {
		name := fmt.Sprintf(
			"role_permissions[%d] %q",
			i,
			mapping.RoleID,
		)
		if _, ok := roleIDs[mapping.RoleID]; !ok {
			return fmt.Errorf(
				"%s references unknown role",
				name,
			)
		}
		if len(mapping.PermissionIDs) == 0 {
			return fmt.Errorf("%s has no permission IDs", name)
		}
		for _, permissionID := range mapping.PermissionIDs {
			if _, ok := permissionIDs[permissionID]; !ok {
				return fmt.Errorf(
					"%s references unknown permission %q",
					name,
					permissionID,
				)
			}
		}

		if err := validateEvidence(
			name,
			mapping.Confidence,
			mapping.EvidenceIDs,
			evidence,
		); err != nil {
			return err
		}
		if mapping.Confidence > 0 {
			supportedFinding = true
		}
	}

	for i, enforcement := range findings.Enforcement {
		name := fmt.Sprintf(
			"enforcement[%d] %q",
			i,
			enforcement.Name,
		)
		if enforcement.Name == "" {
			return fmt.Errorf("enforcement[%d] has no name", i)
		}
		if _, ok := enforcementTypes[enforcement.Type]; !ok {
			return fmt.Errorf(
				"%s has invalid type %q",
				name,
				enforcement.Type,
			)
		}

		if err := validateEvidence(
			name,
			enforcement.Confidence,
			enforcement.EvidenceIDs,
			evidence,
		); err != nil {
			return err
		}
		if enforcement.Confidence > 0 {
			supportedFinding = true
		}
	}

	if !supportedFinding {
		return fmt.Errorf(
			"authorization_present is true but no finding has positive confidence",
		)
	}

	return validateUnresolved(result.Unresolved, evidence)
}

func decodeFindings(data json.RawMessage) (*Findings, error) {
	var rawFindings map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawFindings); err != nil {
		return nil, fmt.Errorf("parse authorization findings: %w", err)
	}

	presentJSON, ok := rawFindings["authorization_present"]
	if !ok {
		return nil, fmt.Errorf("authorization_present is required")
	}

	var present *bool
	if err := json.Unmarshal(presentJSON, &present); err != nil {
		return nil, fmt.Errorf("parse authorization_present: %w", err)
	}
	if present == nil {
		return nil, fmt.Errorf("authorization_present is required")
	}

	confidenceJSON, ok := rawFindings["confidence"]
	if !ok {
		return nil, fmt.Errorf("authorization confidence is required")
	}

	var confidence *float64
	if err := json.Unmarshal(confidenceJSON, &confidence); err != nil {
		return nil, fmt.Errorf("parse authorization confidence: %w", err)
	}
	if confidence == nil {
		return nil, fmt.Errorf("authorization confidence is required")
	}

	evidenceIDs, err := decodeRequiredArray[string](
		rawFindings,
		"evidence_ids",
	)
	if err != nil {
		return nil, err
	}

	roles, err := decodeRequiredArray[Role](rawFindings, "roles")
	if err != nil {
		return nil, err
	}
	permissions, err := decodeRequiredArray[Permission](
		rawFindings,
		"permissions",
	)
	if err != nil {
		return nil, err
	}
	rolePermissions, err := decodeRequiredArray[RolePermission](
		rawFindings,
		"role_permissions",
	)
	if err != nil {
		return nil, err
	}
	enforcement, err := decodeRequiredArray[Enforcement](
		rawFindings,
		"enforcement",
	)
	if err != nil {
		return nil, err
	}

	var model *Model
	if modelJSON, ok := rawFindings["model"]; ok {
		if err := json.Unmarshal(modelJSON, &model); err != nil {
			return nil, fmt.Errorf("parse authorization model: %w", err)
		}
	}

	return &Findings{
		AuthorizationPresent: *present,
		Confidence:           *confidence,
		EvidenceIDs:          evidenceIDs,
		Model:                model,
		Roles:                roles,
		Permissions:          permissions,
		RolePermissions:      rolePermissions,
		Enforcement:          enforcement,
	}, nil
}

func decodeRequiredArray[T any](
	rawFindings map[string]json.RawMessage,
	name string,
) ([]T, error) {
	data, ok := rawFindings[name]
	if !ok {
		return nil, fmt.Errorf("%s array is required", name)
	}

	var items *[]T
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("parse authorization %s: %w", name, err)
	}
	if items == nil {
		return nil, fmt.Errorf("%s array is required", name)
	}

	return *items, nil
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

func validateUnresolved(
	unresolved []investigation.UnresolvedQuestion,
	evidence investigation.EvidenceLookup,
) error {
	for i, question := range unresolved {
		for _, evidenceID := range question.EvidenceIDs {
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
