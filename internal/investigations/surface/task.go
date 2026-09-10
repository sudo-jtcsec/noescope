package surface

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
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
        "interfaces": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "id": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9]*(\\.[a-z][a-z0-9]*)*$"
              },
              "type": {
                "type": "string",
                "enum": [
                  "web_page",
                  "api_endpoint",
                  "cli_command",
                  "form_action",
                  "websocket",
                  "scheduled_job",
                  "worker",
                  "event_consumer",
                  "script",
                  "other"
                ]
              },
              "name": {"type": "string"},
              "description": {"type": "string"},
              "locator": {
                "type": "object",
                "properties": {
                  "path": {"type": "string"},
                  "method": {"type": "string"},
                  "command": {"type": "string"},
                  "schedule": {"type": "string"},
                  "event": {"type": "string"}
                },
                "additionalProperties": false
              },
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
                  "authentication",
                  "role_ids",
                  "permission_ids",
                  "confidence",
                  "evidence_ids"
                ],
                "additionalProperties": false
              },
              "input_names": {
                "type": "array",
                "items": {"type": "string"}
              },
              "entity_ids": {
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
                  "required": ["path"],
                  "additionalProperties": false
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
              "type",
              "name",
              "description",
              "locator",
              "entity_ids",
              "source_components",
              "confidence",
              "evidence_ids"
            ],
            "additionalProperties": false
          }
        },
        "integrations": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "id": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9]*(\\.[a-z][a-z0-9]*)*$"
              },
              "type": {
                "type": "string",
                "enum": [
                  "http_api",
                  "database",
                  "object_storage",
                  "cache",
                  "message_broker",
                  "email",
                  "filesystem",
                  "external_process",
                  "other"
                ]
              },
              "name": {"type": "string"},
              "description": {"type": "string"},
              "locator": {
                "type": "object",
                "properties": {
                  "base_url": {"type": "string"},
                  "path": {"type": "string"},
                  "method": {"type": "string"},
                  "name": {"type": "string"},
                  "command": {"type": "string"}
                },
                "additionalProperties": false
              },
              "authentication": {
                "type": "object",
                "properties": {
                  "type": {
                    "type": "string",
                    "enum": [
                      "none",
                      "bearer",
                      "basic",
                      "api_key",
                      "oauth",
                      "certificate",
                      "custom",
                      "unknown"
                    ]
                  },
                  "credential_source": {"type": "string"}
                },
                "required": ["type"],
                "additionalProperties": false
              },
              "entity_ids": {
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
                  "required": ["path"],
                  "additionalProperties": false
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
              "type",
              "name",
              "description",
              "locator",
              "authentication",
              "entity_ids",
              "source_components",
              "confidence",
              "evidence_ids"
            ],
            "additionalProperties": false
          }
        },
        "handlers": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "id": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9]*(\\.[a-z][a-z0-9]*)*$"
              },
              "type": {
                "type": "string",
                "enum": [
                  "controller",
                  "handler",
                  "command_handler",
                  "function",
                  "method",
                  "script",
                  "worker",
                  "other"
                ]
              },
              "name": {"type": "string"},
              "path": {"type": "string"},
              "symbol": {"type": "string"},
              "interface_ids": {
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
              "name",
              "path",
              "interface_ids",
              "confidence",
              "evidence_ids"
            ],
            "additionalProperties": false
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
                  "navigation",
                  "redirect",
                  "form_submit",
                  "api_call",
                  "command_flow",
                  "event_flow",
                  "integration_call",
                  "other"
                ]
              },
              "from_interface_id": {"type": "string"},
              "to_interface_id": {"type": "string"},
              "to_integration_id": {"type": "string"},
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
              "from_interface_id",
              "description",
              "confidence",
              "evidence_ids"
            ],
            "additionalProperties": false
          }
        }
      },
      "required": [
        "interfaces",
        "integrations",
        "handlers",
        "relationships"
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

var semanticIDPattern = regexp.MustCompile(
	`^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$`,
)

var interfaceTypes = map[string]struct{}{
	"web_page":       {},
	"api_endpoint":   {},
	"cli_command":    {},
	"form_action":    {},
	"websocket":      {},
	"scheduled_job":  {},
	"worker":         {},
	"event_consumer": {},
	"script":         {},
	"other":          {},
}

var handlerTypes = map[string]struct{}{
	"controller":      {},
	"handler":         {},
	"command_handler": {},
	"function":        {},
	"method":          {},
	"script":          {},
	"worker":          {},
	"other":           {},
}

var integrationTypes = map[string]struct{}{
	"http_api":         {},
	"database":         {},
	"object_storage":   {},
	"cache":            {},
	"message_broker":   {},
	"email":            {},
	"filesystem":       {},
	"external_process": {},
	"other":            {},
}

var integrationAuthenticationTypes = map[string]struct{}{
	"none":        {},
	"bearer":      {},
	"basic":       {},
	"api_key":     {},
	"oauth":       {},
	"certificate": {},
	"custom":      {},
	"unknown":     {},
}

var relationshipTypes = map[string]struct{}{
	"navigation":       {},
	"redirect":         {},
	"form_submit":      {},
	"api_call":         {},
	"command_flow":     {},
	"event_flow":       {},
	"integration_call": {},
	"other":            {},
}

var authenticationAccessValues = map[string]struct{}{
	"required":     {},
	"not_required": {},
	"unknown":      {},
}

type priorReferences struct {
	entityIDs     map[string]struct{}
	roleIDs       map[string]struct{}
	permissionIDs map[string]struct{}
}

func Task() investigation.Task {
	return investigation.Task{
		ID:   "surface",
		Name: "Technical Surface Discovery",

		Objective: `Analyze the source repository and inventory its major externally meaningful application interfaces and external integrations.

Answer: "How can a user, client, process, or external system interact with this application, what source code handles those interactions, and what external systems does the application call or depend on?"

An APPLICATION INTERFACE is something a caller invokes on this application. Examples include concrete web pages, inbound HTTP/API endpoints, CLI commands, form actions, WebSocket endpoints, scheduled jobs owned by the application, externally triggered workers or event consumers, and executable application scripts.

An EXTERNAL INTEGRATION is a system or service that this application invokes or depends on. Examples include outbound HTTP APIs, databases, object storage, caches, message brokers, email providers, filesystems, and external processes.

Do not mix these concepts. POST /api/customers exposed by the target is an interface. POST https://api.stripe.com made by the target is an integration. noescope discover is an interface. The OpenAI-compatible chat completions service called by Noescope is an integration.

Capture primary handlers only for application interfaces. Place outbound client implementations under the integration's source_components. Capture useful evidence-backed connections between interfaces, plus calls from application interfaces to integrations.

This is not Feature Discovery. Do not group routes or commands into business features such as Customer Management, Assess, or Administration. Produce the factual interaction inventory that a later feature investigation can group. Do not perform workflow modeling, browser/runtime exploration, generated testing, DAST, or security analysis.`,

		Instructions: `Use the validated Architecture, Authentication, Authorization, and Entity findings as read-only context. Architecture should determine the exploration strategy. Use authentication and authorization only to document intended access, never to look for bypasses. Associate interfaces with prior entity IDs only where clearly supported.

An application interface must be intentionally reachable or invokable from outside its implementation component. Ordinary helpers, repository methods, outbound API client calls, JSON marshaling, cache operations, and internal calls are not interfaces. Handlers are the primary controller, command callback, function, method, script, or worker boundary that receives or processes an application interface; do not inventory every transitively called helper.

An external integration is outbound from the application. Record its provider-neutral type, locator, integration authentication, relevant entity IDs, and canonical client or adapter source components. Integration authentication describes how the application authenticates to the dependency. It is separate from application-user authentication and must never contain application roles or permissions.

For custom PHP, inspect entry PHP files, routing, forms/actions, templates, controllers/includes, and relevant server routing configuration. For Laravel, inspect web/API routes, controllers, console commands, and schedules. For Rails, inspect routes, controllers, and jobs. For Django, inspect URL configuration, views, routers/viewsets, management commands, and tasks. For Go web applications, inspect router registration, HTTP handlers, CLI commands, and workers/jobs. For CLI applications, inspect the Cobra, urfave, or flag command tree, executable subcommands, and their callbacks.

For Noescope, likely application interfaces include cli.root, cli.version, cli.init, and cli.discover. The OpenAI-compatible LLM API called by Noescope belongs in integrations as integration.llm, not in interfaces as api.llm.chat.completions. Client.Chat belongs in that integration's source_components and is not an application-interface handler. Do not invent inbound HTTP endpoints, web pages, authentication endpoints, or any other unsupported surface.

Use stable lowercase semantic IDs such as cli.root, cli.discover, customer.list, or api.customer.create. Do not generate UUIDs or derive IDs mechanically from filenames.

Locators should contain only relevant fields: method/path for HTTP, command for CLI or scripts, schedule and command for scheduled jobs, or event for event consumers. A form submission may include a small input_names list when clearly visible, but do not reconstruct validation schemas.

Access is optional. Use required, not_required, or unknown for authentication. Do not invent role or permission IDs. Positive-confidence access metadata must cite repository evidence or evidence already referenced by the validated prior findings. If prior findings establish that authentication and authorization are absent, not_required with empty role and permission lists is usually appropriate when supported. Use unknown when access cannot be established.

Integration authentication types are none, bearer, basic, api_key, oauth, certificate, custom, or unknown. Credential sources may identify configuration keys such as ai.api_key, but never application-user roles or permissions. Do not expose credential values.

Relationships are limited to useful concrete navigation, redirect, form submission, API call, command flow, or event flow edges between application interfaces, plus integration_call edges from a declared interface to a declared integration. Do not turn them into full workflows.

Future Feature Discovery should derive functionality primarily from application interfaces and entities. Integrations are supporting context and must not automatically become features.

Every interface, integration, handler, and relationship must have confidence greater than zero and cite valid evidence IDs. Every referenced entity, role, permission, interface, and integration ID must resolve to a declared or validated prior finding. An empty interface or integration list is valid. Omit unsupported candidates and report meaningful uncertainty under unresolved.

Explore selectively and stop once the major externally meaningful surfaces and primary handlers are understood. Do not keep reading implementation files merely to enumerate helpers. Call submit_investigation_result as soon as the completion criteria are satisfied.`,

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
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
) (*Findings, *investigation.Result, error) {
	references := referencesFromFindings(
		authorizationFindings,
		entityFindings,
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
	return validateResultWithReferences(
		result,
		evidence,
		priorReferences{
			entityIDs:     map[string]struct{}{},
			roleIDs:       map[string]struct{}{},
			permissionIDs: map[string]struct{}{},
		},
	)
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

	interfaceIDs := make(map[string]struct{}, len(findings.Interfaces))
	for i, item := range findings.Interfaces {
		name := fmt.Sprintf("interfaces[%d] %q", i, item.ID)
		if !semanticIDPattern.MatchString(item.ID) {
			return fmt.Errorf("%s has invalid semantic ID", name)
		}
		if _, exists := interfaceIDs[item.ID]; exists {
			return fmt.Errorf("duplicate interface ID %q", item.ID)
		}
		interfaceIDs[item.ID] = struct{}{}

		if _, ok := interfaceTypes[item.Type]; !ok {
			return fmt.Errorf("%s has invalid type %q", name, item.Type)
		}
		if item.Name == "" {
			return fmt.Errorf("%s has no name", name)
		}
		if item.Description == "" {
			return fmt.Errorf("%s has no description", name)
		}
		if err := validateLocator(name, item.Type, item.Locator); err != nil {
			return err
		}
		if len(item.SourceComponents) == 0 {
			return fmt.Errorf("%s has no source components", name)
		}
		for j, component := range item.SourceComponents {
			if component.Path == "" {
				return fmt.Errorf("%s source_components[%d] has no path", name, j)
			}
		}
		if err := validateSupportedEvidence(
			name,
			item.Confidence,
			item.EvidenceIDs,
			evidence,
		); err != nil {
			return err
		}

		for _, entityID := range item.EntityIDs {
			if _, ok := references.entityIDs[entityID]; !ok {
				return fmt.Errorf("%s references unknown entity %q", name, entityID)
			}
		}

		if item.Access != nil {
			if err := validateAccess(name, item.Access, evidence, references); err != nil {
				return err
			}
		}
	}

	integrationIDs := make(map[string]struct{}, len(findings.Integrations))
	for i, integration := range findings.Integrations {
		name := fmt.Sprintf("integrations[%d] %q", i, integration.ID)
		if !semanticIDPattern.MatchString(integration.ID) {
			return fmt.Errorf("%s has invalid semantic ID", name)
		}
		if _, exists := integrationIDs[integration.ID]; exists {
			return fmt.Errorf("duplicate integration ID %q", integration.ID)
		}
		integrationIDs[integration.ID] = struct{}{}
		if _, ok := integrationTypes[integration.Type]; !ok {
			return fmt.Errorf("%s has invalid type %q", name, integration.Type)
		}
		if integration.Name == "" {
			return fmt.Errorf("%s has no name", name)
		}
		if integration.Description == "" {
			return fmt.Errorf("%s has no description", name)
		}
		if err := validateIntegrationLocator(
			name,
			integration.Type,
			integration.Locator,
		); err != nil {
			return err
		}
		authenticationType := integration.Authentication.Type
		if _, ok := integrationAuthenticationTypes[authenticationType]; !ok {
			return fmt.Errorf(
				"%s has invalid authentication type %q",
				name,
				integration.Authentication.Type,
			)
		}
		if integration.Authentication.Type == "none" &&
			integration.Authentication.CredentialSource != "" {
			return fmt.Errorf(
				"%s uses no authentication but has a credential source",
				name,
			)
		}
		if len(integration.SourceComponents) == 0 {
			return fmt.Errorf("%s has no source components", name)
		}
		for j, component := range integration.SourceComponents {
			if component.Path == "" {
				return fmt.Errorf(
					"%s source_components[%d] has no path",
					name,
					j,
				)
			}
		}
		for _, entityID := range integration.EntityIDs {
			if _, ok := references.entityIDs[entityID]; !ok {
				return fmt.Errorf(
					"%s references unknown entity %q",
					name,
					entityID,
				)
			}
		}
		if err := validateSupportedEvidence(
			name,
			integration.Confidence,
			integration.EvidenceIDs,
			evidence,
		); err != nil {
			return err
		}
	}

	handlerIDs := make(map[string]struct{}, len(findings.Handlers))
	for i, handler := range findings.Handlers {
		name := fmt.Sprintf("handlers[%d] %q", i, handler.ID)
		if !semanticIDPattern.MatchString(handler.ID) {
			return fmt.Errorf("%s has invalid semantic ID", name)
		}
		if _, exists := handlerIDs[handler.ID]; exists {
			return fmt.Errorf("duplicate handler ID %q", handler.ID)
		}
		handlerIDs[handler.ID] = struct{}{}
		if _, ok := handlerTypes[handler.Type]; !ok {
			return fmt.Errorf("%s has invalid type %q", name, handler.Type)
		}
		if handler.Name == "" {
			return fmt.Errorf("%s has no name", name)
		}
		if handler.Path == "" {
			return fmt.Errorf("%s has no path", name)
		}
		if len(handler.InterfaceIDs) == 0 {
			return fmt.Errorf("%s has no interface IDs", name)
		}
		for _, interfaceID := range handler.InterfaceIDs {
			if _, ok := interfaceIDs[interfaceID]; !ok {
				return fmt.Errorf("%s references unknown interface %q", name, interfaceID)
			}
		}
		if err := validateSupportedEvidence(
			name,
			handler.Confidence,
			handler.EvidenceIDs,
			evidence,
		); err != nil {
			return err
		}
	}

	for i, relationship := range findings.Relationships {
		name := fmt.Sprintf("relationships[%d]", i)
		if _, ok := relationshipTypes[relationship.Type]; !ok {
			return fmt.Errorf("%s has invalid type %q", name, relationship.Type)
		}
		if _, ok := interfaceIDs[relationship.FromInterfaceID]; !ok {
			return fmt.Errorf(
				"%s references unknown from interface %q",
				name,
				relationship.FromInterfaceID,
			)
		}
		if relationship.Type == "integration_call" {
			if relationship.ToInterfaceID != "" {
				return fmt.Errorf(
					"%s integration_call must not reference a to interface",
					name,
				)
			}
			if _, ok := integrationIDs[relationship.ToIntegrationID]; !ok {
				return fmt.Errorf(
					"%s references unknown integration %q",
					name,
					relationship.ToIntegrationID,
				)
			}
		} else {
			if relationship.ToIntegrationID != "" {
				return fmt.Errorf(
					"%s type %q must not reference an integration",
					name,
					relationship.Type,
				)
			}
			if _, ok := interfaceIDs[relationship.ToInterfaceID]; !ok {
				return fmt.Errorf(
					"%s references unknown to interface %q",
					name,
					relationship.ToInterfaceID,
				)
			}
		}
		if relationship.Description == "" {
			return fmt.Errorf("%s has no description", name)
		}
		if err := validateSupportedEvidence(
			name,
			relationship.Confidence,
			relationship.EvidenceIDs,
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

func validateLocator(
	name string,
	interfaceType string,
	locator InterfaceLocator,
) error {
	if locator.Path == "" &&
		locator.Command == "" &&
		locator.Schedule == "" &&
		locator.Event == "" {
		return fmt.Errorf("%s has no usable locator", name)
	}

	switch interfaceType {
	case "web_page", "api_endpoint", "form_action", "websocket":
		if locator.Path == "" {
			return fmt.Errorf("%s requires a path locator", name)
		}
	case "cli_command":
		if locator.Command == "" {
			return fmt.Errorf("%s requires a command locator", name)
		}
	case "event_consumer":
		if locator.Event == "" {
			return fmt.Errorf("%s requires an event locator", name)
		}
	case "scheduled_job":
		if locator.Schedule == "" && locator.Command == "" {
			return fmt.Errorf("%s requires a schedule or command locator", name)
		}
	case "worker":
		if locator.Event == "" && locator.Command == "" {
			return fmt.Errorf("%s requires an event or command locator", name)
		}
	case "script":
		if locator.Path == "" && locator.Command == "" {
			return fmt.Errorf("%s requires a path or command locator", name)
		}
	}

	return nil
}

func validateIntegrationLocator(
	name string,
	integrationType string,
	locator IntegrationLocator,
) error {
	if locator.BaseURL == "" &&
		locator.Path == "" &&
		locator.Name == "" &&
		locator.Command == "" {
		return fmt.Errorf("%s has no usable locator", name)
	}

	switch integrationType {
	case "http_api":
		if locator.BaseURL == "" && locator.Path == "" {
			return fmt.Errorf("%s requires a base URL or path locator", name)
		}
	case "filesystem":
		if locator.Path == "" {
			return fmt.Errorf("%s requires a path locator", name)
		}
	case "external_process":
		if locator.Command == "" {
			return fmt.Errorf("%s requires a command locator", name)
		}
	}

	return nil
}

func validateAccess(
	interfaceName string,
	access *Access,
	evidence investigation.EvidenceLookup,
	references priorReferences,
) error {
	name := interfaceName + " access"
	if _, ok := authenticationAccessValues[access.Authentication]; !ok {
		return fmt.Errorf(
			"%s has invalid authentication value %q",
			name,
			access.Authentication,
		)
	}

	if access.Authentication == "unknown" {
		if len(access.RoleIDs) > 0 || len(access.PermissionIDs) > 0 {
			return fmt.Errorf("%s is unknown but contains authorization IDs", name)
		}
	} else if access.Confidence == 0 {
		return fmt.Errorf("%s makes a supported claim with zero confidence", name)
	}

	if err := validateEvidence(
		name,
		access.Confidence,
		access.EvidenceIDs,
		evidence,
	); err != nil {
		return err
	}

	for _, roleID := range access.RoleIDs {
		if _, ok := references.roleIDs[roleID]; !ok {
			return fmt.Errorf("%s references unknown role %q", name, roleID)
		}
	}
	for _, permissionID := range access.PermissionIDs {
		if _, ok := references.permissionIDs[permissionID]; !ok {
			return fmt.Errorf(
				"%s references unknown permission %q",
				name,
				permissionID,
			)
		}
	}

	return nil
}

func validateSupportedEvidence(
	name string,
	confidence float64,
	evidenceIDs []string,
	evidence investigation.EvidenceLookup,
) error {
	if confidence <= 0 || confidence > 1 {
		return fmt.Errorf(
			"%s must have confidence greater than zero and at most one",
			name,
		)
	}

	return validateEvidence(name, confidence, evidenceIDs, evidence)
}

func validateEvidence(
	name string,
	confidence float64,
	evidenceIDs []string,
	evidence investigation.EvidenceLookup,
) error {
	if confidence < 0 || confidence > 1 {
		return fmt.Errorf("%s has invalid confidence %.2f", name, confidence)
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

func decodeFindings(data json.RawMessage) (*Findings, error) {
	var rawFindings struct {
		Interfaces    json.RawMessage `json:"interfaces"`
		Integrations  json.RawMessage `json:"integrations"`
		Handlers      json.RawMessage `json:"handlers"`
		Relationships json.RawMessage `json:"relationships"`
	}
	if err := investigation.DecodeObjectFindings(
		data,
		&rawFindings,
		"surface findings",
	); err != nil {
		return nil, err
	}

	interfaces, err := decodeRequiredArray[Interface](
		rawFindings.Interfaces,
		"interfaces",
		validateInterfaceShape,
	)
	if err != nil {
		return nil, err
	}
	integrations, err := decodeRequiredArray[Integration](
		rawFindings.Integrations,
		"integrations",
		validateIntegrationShape,
	)
	if err != nil {
		return nil, err
	}
	handlers, err := decodeRequiredArray[Handler](
		rawFindings.Handlers,
		"handlers",
		nil,
	)
	if err != nil {
		return nil, err
	}
	relationships, err := decodeRequiredArray[Relationship](
		rawFindings.Relationships,
		"relationships",
		nil,
	)
	if err != nil {
		return nil, err
	}

	return &Findings{
		Interfaces:    interfaces,
		Integrations:  integrations,
		Handlers:      handlers,
		Relationships: relationships,
	}, nil
}

func decodeRequiredArray[T any](
	data json.RawMessage,
	name string,
	validateItem func(int, json.RawMessage) error,
) ([]T, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%s array is required", name)
	}
	if err := expectJSONKind(
		"surface findings field "+name,
		data,
		"array",
	); err != nil {
		return nil, err
	}

	var rawItems []json.RawMessage
	if err := json.Unmarshal(data, &rawItems); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if rawItems == nil {
		return nil, fmt.Errorf("%s array is required", name)
	}

	values := make([]T, 0, len(rawItems))
	for i, rawItem := range rawItems {
		path := fmt.Sprintf("surface findings field %s[%d]", name, i)
		if err := expectJSONKind(path, rawItem, "object"); err != nil {
			return nil, err
		}
		if validateItem != nil {
			if err := validateItem(i, rawItem); err != nil {
				return nil, err
			}
		}

		var value T
		if err := json.Unmarshal(rawItem, &value); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		values = append(values, value)
	}

	return values, nil
}

func validateInterfaceShape(index int, data json.RawMessage) error {
	var fields struct {
		Locator          json.RawMessage `json:"locator"`
		Access           json.RawMessage `json:"access"`
		SourceComponents json.RawMessage `json:"source_components"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("parse interfaces[%d]: %w", index, err)
	}

	if err := expectJSONKind(
		fmt.Sprintf("surface findings field interfaces[%d].locator", index),
		fields.Locator,
		"object",
	); err != nil {
		return err
	}
	if len(bytes.TrimSpace(fields.Access)) > 0 {
		if err := expectJSONKind(
			fmt.Sprintf("surface findings field interfaces[%d].access", index),
			fields.Access,
			"object",
		); err != nil {
			return err
		}
	}

	return expectJSONKind(
		fmt.Sprintf(
			"surface findings field interfaces[%d].source_components",
			index,
		),
		fields.SourceComponents,
		"array",
	)
}

func validateIntegrationShape(index int, data json.RawMessage) error {
	var fields struct {
		Locator          json.RawMessage `json:"locator"`
		Authentication   json.RawMessage `json:"authentication"`
		SourceComponents json.RawMessage `json:"source_components"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("parse integrations[%d]: %w", index, err)
	}

	for _, field := range []struct {
		name string
		data json.RawMessage
		kind string
	}{
		{name: "locator", data: fields.Locator, kind: "object"},
		{
			name: "authentication",
			data: fields.Authentication,
			kind: "object",
		},
		{
			name: "source_components",
			data: fields.SourceComponents,
			kind: "array",
		},
	} {
		if err := expectJSONKind(
			fmt.Sprintf(
				"surface findings field integrations[%d].%s",
				index,
				field.name,
			),
			field.data,
			field.kind,
		); err != nil {
			return err
		}
	}

	return nil
}

func expectJSONKind(path string, data json.RawMessage, expected string) error {
	actual := investigation.JSONValueKind(data)
	if actual != expected {
		return fmt.Errorf("%s: expected %s, got %s", path, expected, actual)
	}

	return nil
}

func referencesFromFindings(
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
) priorReferences {
	references := priorReferences{
		entityIDs:     map[string]struct{}{},
		roleIDs:       map[string]struct{}{},
		permissionIDs: map[string]struct{}{},
	}

	if entityFindings != nil {
		for _, entity := range entityFindings.Entities {
			references.entityIDs[entity.ID] = struct{}{}
		}
	}
	if authorizationFindings != nil {
		for _, role := range authorizationFindings.Roles {
			references.roleIDs[role.ID] = struct{}{}
		}
		for _, permission := range authorizationFindings.Permissions {
			references.permissionIDs[permission.ID] = struct{}{}
		}
	}

	return references
}
