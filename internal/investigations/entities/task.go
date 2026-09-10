package entities

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
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
        "entities": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "id": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9]*(\\.[a-z][a-z0-9]*)*$"
              },
              "name": {"type": "string"},
              "description": {"type": "string"},
              "aliases": {
                "type": "array",
                "items": {"type": "string"}
              },
              "source_components": {
                "type": "array",
                "items": {
                  "type": "object",
                  "properties": {
                    "path": {"type": "string"},
                    "symbol": {"type": "string"}
                  },
                  "required": ["path"]
                }
              },
              "persistence": {
                "type": "array",
                "items": {
                  "type": "object",
                  "properties": {
                    "type": {
                      "type": "string",
                      "enum": [
                        "database_table",
                        "file",
                        "external_service",
                        "memory",
                        "unknown"
                      ]
                    },
                    "name": {"type": "string"},
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
                    "confidence",
                    "evidence_ids"
                  ]
                }
              },
              "relationships": {
                "type": "array",
                "items": {
                  "type": "object",
                  "properties": {
                    "type": {
                      "type": "string",
                      "enum": [
                        "belongs_to",
                        "has_many",
                        "has_one",
                        "references",
                        "owns",
                        "custom"
                      ]
                    },
                    "target_entity_id": {"type": "string"},
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
                    "target_entity_id",
                    "description",
                    "confidence",
                    "evidence_ids"
                  ]
                }
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
              "aliases",
              "source_components",
              "persistence",
              "relationships",
              "confidence",
              "evidence_ids"
            ]
          }
        }
      },
      "required": ["entities"]
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

var entityIDPattern = regexp.MustCompile(
	`^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$`,
)

var persistenceTypes = map[string]struct{}{
	"database_table":   {},
	"file":             {},
	"external_service": {},
	"memory":           {},
	"unknown":          {},
}

var relationshipTypes = map[string]struct{}{
	"belongs_to": {},
	"has_many":   {},
	"has_one":    {},
	"references": {},
	"owns":       {},
	"custom":     {},
}

func Task() investigation.Task {
	return investigation.Task{
		ID:   "entities",
		Name: "Domain Entity Discovery",

		Objective: `Analyze the source repository and identify its major business or application-domain entities.

Answer: "What meaningful things does this application operate on?"

An entity is a meaningful concept such as Customer, User, Organization, Assessment, Project, Invoice, Report, Order, Ticket, or Asset. Multiple artifacts such as a controller, service, repository, table, and route may all provide evidence for one entity.

Do not mechanically classify every struct, class, table, or source noun as an entity. Config, Logger, HTTPClient, Request, Response, Repository, Controller, Middleware, Tool, Registry, Context, Result, and Cache are normally implementation concepts rather than domain entities. A concept such as User, Token, Session, Run, or Evidence is an entity only when this application treats it as meaningful first-class state or behavior.

An empty entity list is valid. Do not fabricate entities merely to produce output.

For each supported entity, provide a semantic lowercase ID, description, important aliases and canonical source components, supported persistence records, supported relationships to other declared entities, confidence, and evidence IDs.

Do not perform technical surface, feature, workflow, browser/runtime, database-schema reconstruction, or security discovery in this task.`,

		Instructions: `Use the validated Architecture, Authentication, and Authorization findings as read-only context. Choose an investigation plan appropriate to the detected architecture instead of rediscovering it.

For Laravel, inspect likely models, migrations, routes/controllers, repositories, and services. For Rails, inspect models, routes, and controllers. For Django, inspect models, views, serializers, and migrations. For custom PHP, inspect application classes, controllers, database queries, forms, and domain-specific directories. For Go, inspect packages, persisted structs, service/repository boundaries, and concepts exposed by the CLI or application.

Strong signals include domain/model classes, persistent records, concept-centered repository or service logic, controllers/routes/API resources, CRUD operations, dedicated pages/templates, authorization permissions, repeated business nouns, and evidenced relationships.

Search selectively for patterns such as model, entity, repository, service, controller, CREATE TABLE, INSERT INTO, UPDATE, SELECT, struct, class, schema, and migration only when appropriate for this repository. Do not blindly run every search.

Generate concise lowercase semantic IDs. Use dotted IDs only for meaningful distinctions such as assessment.result. Do not derive IDs mechanically from filenames and do not generate UUIDs.

Attach only canonical implementation locations as source_components. Persistence is optional and must not enumerate table columns or reconstruct complete schemas. Relationships must be explicitly supported; do not infer them merely because names occur near one another.

Be conservative when analyzing Noescope itself: Investigation, Evidence, or Run may be entities only if source shows they are first-class application concepts rather than implementation machinery. Omit zero-confidence candidates and put genuine uncertainty under unresolved.

Prefer targeted searches and bounded reads. Stop once the major entities are reasonably understood. Do not keep exploring only to find minor internal concepts; report uncertainty under unresolved.

Every positive-confidence entity, persistence record, and relationship must reference valid evidence IDs. Call submit_investigation_result as soon as the completion criteria are satisfied.`,

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
			"parse entity findings: %w",
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

	entityIDs := make(map[string]struct{}, len(findings.Entities))
	for i, entity := range findings.Entities {
		name := fmt.Sprintf("entities[%d] %q", i, entity.ID)

		if !entityIDPattern.MatchString(entity.ID) {
			return fmt.Errorf("%s has invalid semantic ID", name)
		}
		if entity.Name == "" {
			return fmt.Errorf("%s has no name", name)
		}
		if entity.Description == "" {
			return fmt.Errorf("%s has no description", name)
		}
		if _, exists := entityIDs[entity.ID]; exists {
			return fmt.Errorf("duplicate entity ID %q", entity.ID)
		}
		entityIDs[entity.ID] = struct{}{}

		if err := validateEvidence(
			name,
			entity.Confidence,
			entity.EvidenceIDs,
			evidence,
		); err != nil {
			return err
		}
		if entity.Confidence == 0 {
			return fmt.Errorf(
				"%s has zero confidence and must be omitted or unresolved",
				name,
			)
		}

		for j, component := range entity.SourceComponents {
			if component.Path == "" {
				return fmt.Errorf(
					"%s source_components[%d] has no path",
					name,
					j,
				)
			}
		}

		for j, persistence := range entity.Persistence {
			persistenceName := fmt.Sprintf(
				"%s persistence[%d] %q",
				name,
				j,
				persistence.Name,
			)
			if _, ok := persistenceTypes[persistence.Type]; !ok {
				return fmt.Errorf(
					"%s has invalid type %q",
					persistenceName,
					persistence.Type,
				)
			}
			if persistence.Name == "" {
				return fmt.Errorf("%s has no name", persistenceName)
			}
			if err := validateEvidence(
				persistenceName,
				persistence.Confidence,
				persistence.EvidenceIDs,
				evidence,
			); err != nil {
				return err
			}
			if persistence.Confidence == 0 {
				return fmt.Errorf(
					"%s has zero confidence and must be omitted or unresolved",
					persistenceName,
				)
			}
		}
	}

	for i, entity := range findings.Entities {
		for j, relationship := range entity.Relationships {
			name := fmt.Sprintf(
				"entities[%d] %q relationships[%d]",
				i,
				entity.ID,
				j,
			)

			if _, ok := relationshipTypes[relationship.Type]; !ok {
				return fmt.Errorf(
					"%s has invalid type %q",
					name,
					relationship.Type,
				)
			}
			if _, ok := entityIDs[relationship.TargetEntityID]; !ok {
				return fmt.Errorf(
					"%s references undeclared entity %q",
					name,
					relationship.TargetEntityID,
				)
			}
			if err := validateEvidence(
				name,
				relationship.Confidence,
				relationship.EvidenceIDs,
				evidence,
			); err != nil {
				return err
			}
			if relationship.Confidence == 0 {
				return fmt.Errorf(
					"%s has zero confidence and must be omitted or unresolved",
					name,
				)
			}
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

func decodeFindings(data json.RawMessage) (*Findings, error) {
	var rawFindings map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawFindings); err != nil {
		return nil, fmt.Errorf("parse entity findings: %w", err)
	}

	entitiesJSON, ok := rawFindings["entities"]
	if !ok {
		return nil, fmt.Errorf("entities array is required")
	}

	var entityList *[]Entity
	if err := json.Unmarshal(entitiesJSON, &entityList); err != nil {
		return nil, fmt.Errorf("parse entities: %w", err)
	}
	if entityList == nil {
		return nil, fmt.Errorf("entities array is required")
	}

	return &Findings{Entities: *entityList}, nil
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
