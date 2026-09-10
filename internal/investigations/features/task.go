package features

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
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
        "features": {
          "type": "array",
          "items": {"$ref": "#/$defs/feature_node"}
        }
      },
      "required": ["features"],
      "additionalProperties": false
    },
    "claims": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "subject": {"type": "string"},
          "statement": {"type": "string"},
          "confidence": {"type": "number", "minimum": 0, "maximum": 1},
          "evidence_ids": {
            "type": "array",
            "items": {"type": "string"}
          }
        },
        "required": ["subject", "statement", "confidence", "evidence_ids"],
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
  "additionalProperties": false,
  "$defs": {
    "access": {
      "type": "object",
      "properties": {
        "authentication": {
          "type": "string",
          "enum": ["required", "not_required", "unknown"]
        },
        "role_ids": {
          "type": "array",
          "items": {"type": "string"}
        },
        "permission_ids": {
          "type": "array",
          "items": {"type": "string"}
        }
      },
      "required": ["authentication", "role_ids", "permission_ids"],
      "additionalProperties": false
    },
    "source_component": {
      "type": "object",
      "properties": {
        "path": {"type": "string"},
        "symbol": {"type": "string"}
      },
      "required": ["path"],
      "additionalProperties": false
    },
    "feature_node": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "pattern": "^[a-z][a-z0-9]*(\\.[a-z][a-z0-9]*)*$"
        },
        "name": {"type": "string"},
        "type": {
          "type": "string",
          "enum": ["module", "feature", "action"]
        },
        "description": {"type": "string"},
        "access": {"$ref": "#/$defs/access"},
        "entity_ids": {
          "type": "array",
          "items": {"type": "string"}
        },
        "interface_ids": {
          "type": "array",
          "items": {"type": "string"}
        },
        "source_components": {
          "type": "array",
          "items": {"$ref": "#/$defs/source_component"}
        },
        "children": {
          "type": "array",
          "items": {"$ref": "#/$defs/feature_node"}
        },
        "confidence": {"type": "number", "exclusiveMinimum": 0, "maximum": 1},
        "evidence_ids": {
          "type": "array",
          "items": {"type": "string"},
          "minItems": 1
        }
      },
      "required": [
        "id",
        "name",
        "type",
        "description",
        "access",
        "entity_ids",
        "interface_ids",
        "children",
        "confidence",
        "evidence_ids"
      ],
      "additionalProperties": false
    }
  }
}`)

var semanticIDPattern = regexp.MustCompile(
	`^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$`,
)

var nodeTypes = map[string]struct{}{
	"module":  {},
	"feature": {},
	"action":  {},
}

var authenticationAccessValues = map[string]struct{}{
	"required":     {},
	"not_required": {},
	"unknown":      {},
}

type priorReferences struct {
	entityIDs      map[string]struct{}
	interfaceIDs   map[string]struct{}
	integrationIDs map[string]struct{}
	roleIDs        map[string]struct{}
	permissionIDs  map[string]struct{}
}

func Task() investigation.Task {
	return investigation.Task{
		ID:   "features",
		Name: "Feature Discovery",

		Objective: `Analyze the validated application model and targeted repository evidence to identify the meaningful functionality this application provides.

Answer: "What meaningful functionality does this application provide?"

Build a semantic hierarchy using only module, feature, and action nodes. A module is a broad user-recognizable functional area, a feature is a coherent capability within a module, and an action is a concrete meaningful operation available to a user or client.

Feature Discovery is the semantic layer above Technical Surface. Do not create one feature per route, command, controller, or interface. Group related concrete interfaces into capabilities a product owner or developer would recognize. For example, GET /tasks, POST /tasks, and POST /task/{id}/move can support a Tasks module with View Tasks, Create Task, and Move Task actions.

Do not mechanically mirror route, controller, model, or template trees. Controllers, Models, Templates, Pimple, PicoDb, JSON-RPC, databases, SMTP, object storage, and outbound APIs are not automatically product features. An integration may support a capability, but represent the user-facing capability rather than the dependency itself.

Do not perform workflow discovery, browser/runtime exploration, generated testing, DAST, vulnerability analysis, or application documentation generation.`,

		Instructions: `Start from the compact validated context in this order: Domain Entities, Technical Surface interfaces and relationships, Authorization permissions, then Authentication. Use Architecture only to interpret implementation conventions. Primarily reason from those existing structured findings; use repository tools only for targeted clarification of ambiguous groupings.

Keep the hierarchy coherent and selective. Prefer the major user-recognizable modules and their meaningful capabilities over microscopic completeness. Multiple interfaces may support one action, and one interface may support a broader feature. Put interface references at the lowest useful semantic level rather than copying hundreds onto module nodes.

Every node must include effective access metadata explicitly: authentication is required, not_required, or unknown, with canonical role_ids and permission_ids. Do not implement access inheritance and do not invent role or permission IDs. This documents intended access only and must not look for bypasses.

Entity IDs and interface IDs must be copied exactly from validated prior findings. Integrations are not interfaces and integration IDs must never appear in interface_ids. Source components are optional and should be included only when they materially clarify the feature; do not duplicate the Surface handler inventory.

Use lowercase concise globally unique semantic IDs. Children should normally start with the parent ID followed by a dot, such as projects.members and projects.members.add. Actions cannot have children. Do not generate UUIDs.

Every node must have confidence greater than zero and cite valid run-scoped evidence IDs. Existing evidence IDs included in the projected context may be reused when they support the semantic claim. Use targeted repository reads only when the grouping needs evidence not already available. Unsupported candidates belong under unresolved or should be omitted; an empty feature tree is valid.

Internal analysis or discovery stages must not automatically become separate end-user actions. Treat all examples as classification guidance only, never as evidence about the target repository.

Stop once the major functionality is represented coherently. Do not broadly rediscover the repository or keep reading files merely to enumerate minor actions.

TODO for future large repositories: split feature discovery into a top-level module investigation followed by serial per-module expansion. Do not attempt that segmentation in this v0.1 task.`,

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
			MaxTurns:           20,
			MaxToolCalls:       150,
			MaxFormatRepairs:   2,
			MaxSemanticRepairs: 2,
			FinalizeTurns:      2,
			MaxDuration:        15 * time.Minute,
		},
	}
}

func Run(
	ctx context.Context,
	runner *investigation.Runner,
	taskContext json.RawMessage,
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
	surfaceFindings *surface.Findings,
) (*Findings, *investigation.Result, error) {
	references := referencesFromFindings(
		authorizationFindings,
		entityFindings,
		surfaceFindings,
	)

	task := Task()
	task.Context = append(json.RawMessage(nil), taskContext...)
	task.ValidateResult = func(
		result *investigation.Result,
		evidence investigation.EvidenceLookup,
	) error {
		return validateResultWithReferences(result, evidence, references)
	}

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
	return validateResultWithReferences(result, evidence, priorReferences{
		entityIDs:      map[string]struct{}{},
		interfaceIDs:   map[string]struct{}{},
		integrationIDs: map[string]struct{}{},
		roleIDs:        map[string]struct{}{},
		permissionIDs:  map[string]struct{}{},
	})
}

func validateResultWithReferences(
	result *investigation.Result,
	evidence investigation.EvidenceLookup,
	references priorReferences,
) error {
	findings, err := decodeFindings(result.Findings)
	if err != nil {
		return investigation.NewSubmissionFormatError(err)
	}

	seenIDs := make(map[string]struct{})
	for i := range findings.Features {
		if err := validateNode(
			&findings.Features[i],
			fmt.Sprintf("features[%d]", i),
			"",
			seenIDs,
			references,
			evidence,
		); err != nil {
			return err
		}
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

func validateNode(
	node *Node,
	path string,
	parentID string,
	seenIDs map[string]struct{},
	references priorReferences,
	evidence investigation.EvidenceLookup,
) error {
	label := fmt.Sprintf("%s %q", path, node.ID)
	if !semanticIDPattern.MatchString(node.ID) {
		return fmt.Errorf("%s has invalid semantic ID", label)
	}
	if _, exists := seenIDs[node.ID]; exists {
		return fmt.Errorf("duplicate feature ID %q", node.ID)
	}
	seenIDs[node.ID] = struct{}{}
	if parentID != "" && !strings.HasPrefix(node.ID, parentID+".") {
		return fmt.Errorf(
			"%s is not within parent hierarchy %q",
			label,
			parentID,
		)
	}
	if _, ok := nodeTypes[node.Type]; !ok {
		return fmt.Errorf("%s has invalid type %q", label, node.Type)
	}
	if node.Type == "action" && len(node.Children) > 0 {
		return fmt.Errorf("%s is an action and cannot have children", label)
	}
	if node.Name == "" {
		return fmt.Errorf("%s has no name", label)
	}
	if node.Description == "" {
		return fmt.Errorf("%s has no description", label)
	}
	if _, ok := authenticationAccessValues[node.Access.Authentication]; !ok {
		return fmt.Errorf(
			"%s has invalid authentication access %q",
			label,
			node.Access.Authentication,
		)
	}
	for _, roleID := range node.Access.RoleIDs {
		if _, ok := references.roleIDs[roleID]; !ok {
			return fmt.Errorf("%s references unknown role %q", label, roleID)
		}
	}
	for _, permissionID := range node.Access.PermissionIDs {
		if _, ok := references.permissionIDs[permissionID]; !ok {
			return fmt.Errorf(
				"%s references unknown permission %q",
				label,
				permissionID,
			)
		}
	}
	for _, entityID := range node.EntityIDs {
		if _, ok := references.entityIDs[entityID]; !ok {
			return fmt.Errorf("%s references unknown entity %q", label, entityID)
		}
	}
	for _, interfaceID := range node.InterfaceIDs {
		if _, integration := references.integrationIDs[interfaceID]; integration {
			return fmt.Errorf(
				"%s uses integration %q as an interface",
				label,
				interfaceID,
			)
		}
		if _, ok := references.interfaceIDs[interfaceID]; !ok {
			return fmt.Errorf(
				"%s references unknown interface %q",
				label,
				interfaceID,
			)
		}
	}
	for i, component := range node.SourceComponents {
		if component.Path == "" {
			return fmt.Errorf("%s source_components[%d] has no path", label, i)
		}
	}
	if node.Confidence <= 0 || node.Confidence > 1 {
		return fmt.Errorf(
			"%s confidence %.2f must be greater than 0 and at most 1",
			label,
			node.Confidence,
		)
	}
	if len(node.EvidenceIDs) == 0 {
		return fmt.Errorf(
			"%s has confidence %.2f but no evidence",
			label,
			node.Confidence,
		)
	}
	for _, evidenceID := range node.EvidenceIDs {
		if !evidence.Exists(evidenceID) {
			return fmt.Errorf(
				"%s references unknown evidence ID %q",
				label,
				evidenceID,
			)
		}
	}
	for i := range node.Children {
		if err := validateNode(
			&node.Children[i],
			fmt.Sprintf("%s.children[%d]", path, i),
			node.ID,
			seenIDs,
			references,
			evidence,
		); err != nil {
			return err
		}
	}
	return nil
}

func referencesFromFindings(
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
	surfaceFindings *surface.Findings,
) priorReferences {
	references := priorReferences{
		entityIDs:      make(map[string]struct{}),
		interfaceIDs:   make(map[string]struct{}),
		integrationIDs: make(map[string]struct{}),
		roleIDs:        make(map[string]struct{}),
		permissionIDs:  make(map[string]struct{}),
	}
	if authorizationFindings != nil {
		for _, role := range authorizationFindings.Roles {
			references.roleIDs[role.ID] = struct{}{}
		}
		for _, permission := range authorizationFindings.Permissions {
			references.permissionIDs[permission.ID] = struct{}{}
		}
	}
	if entityFindings != nil {
		for _, entity := range entityFindings.Entities {
			references.entityIDs[entity.ID] = struct{}{}
		}
	}
	if surfaceFindings != nil {
		for _, item := range surfaceFindings.Interfaces {
			references.interfaceIDs[item.ID] = struct{}{}
		}
		for _, integration := range surfaceFindings.Integrations {
			references.integrationIDs[integration.ID] = struct{}{}
		}
	}
	return references
}

func decodeFindings(raw json.RawMessage) (*Findings, error) {
	if err := validateFindingsStructure(raw); err != nil {
		return nil, err
	}
	var findings Findings
	if err := investigation.DecodeObjectFindings(
		raw,
		&findings,
		"feature findings",
	); err != nil {
		return nil, err
	}
	return &findings, nil
}

func validateFindingsStructure(raw json.RawMessage) error {
	if investigation.JSONValueKind(raw) != "object" {
		return fmt.Errorf(
			"feature findings: expected object, got %s",
			investigation.JSONValueKind(raw),
		)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("feature findings: %w", err)
	}
	featuresRaw, ok := fields["features"]
	if !ok {
		return fmt.Errorf("feature findings field features: required")
	}
	if kind := investigation.JSONValueKind(featuresRaw); kind != "array" {
		return fmt.Errorf(
			"feature findings field features: expected array, got %s",
			kind,
		)
	}
	return nil
}
