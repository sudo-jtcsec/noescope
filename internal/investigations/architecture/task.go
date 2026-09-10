package architecture

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
    "summary": {
      "type": "string"
    },
    "findings": {
      "type": "object",
      "properties": {
        "languages": {
          "type": "array",
          "items": {"$ref": "#/$defs/technology"}
        },
        "frameworks": {
          "type": "array",
          "items": {"$ref": "#/$defs/framework"}
        },
        "formats": {
          "type": "array",
          "items": {"$ref": "#/$defs/technology"}
        },
        "libraries": {
          "type": "array",
          "items": {"$ref": "#/$defs/technology"}
        },
        "external_interfaces": {
          "type": "array",
          "items": {"$ref": "#/$defs/technology"}
        },        
        "databases": {
          "type": "array",
          "items": {"$ref": "#/$defs/technology"}
        },
        "web_servers": {
          "type": "array",
          "items": {"$ref": "#/$defs/technology"}
        },
        "architecture_style": {
          "$ref": "#/$defs/statement"
        },
        "entrypoints": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "path": {"type": "string"},
              "type": {
                "type": "string",
                "enum": [
                  "executable",
                  "configuration",
                  "web",
                  "api",
                  "worker",
                  "script",
                  "other"
                ]
              },
              "purpose": {"type": "string"},
              "confidence": {"type": "number"},
              "evidence_ids": {
                "type": "array",
                "items": {"type": "string"}
              }
            },
            "required": ["path", "type", "purpose", "confidence", "evidence_ids"]
          }
        },
        "important_directories": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "path": {"type": "string"},
              "purpose": {"type": "string"},
              "confidence": {"type": "number"},
              "evidence_ids": {
                "type": "array",
                "items": {"type": "string"}
              }
            },
            "required": ["path", "purpose", "confidence", "evidence_ids"]
          }
        }
      },
      "required": [
        "languages",
        "frameworks",
        "databases",
        "web_servers",
        "architecture_style",
        "entrypoints",
        "important_directories"
      ]
    },
    "claims": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "subject": {"type": "string"},
          "statement": {"type": "string"},
          "confidence": {"type": "number"},
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
  "$defs": {
    "technology": {
      "type": "object",
      "properties": {
        "name": {"type": "string"},
        "role": {"type": "string"},
        "evidence_type": {
          "type": "string",
          "enum": ["direct", "inferred"]
        },
        "confidence": {"type": "number"},
        "evidence_ids": {
          "type": "array",
          "items": {"type": "string"}
        }
      },
      "required": ["name", "confidence", "evidence_ids"]
    },
    "framework": {
      "type": "object",
      "properties": {
        "name": {"type": "string"},
        "role": {"type": "string"},
        "evidence_type": {
          "type": "string",
          "enum": ["direct"]
        },
        "confidence": {"type": "number"},
        "evidence_ids": {
          "type": "array",
          "items": {"type": "string"}
        }
      },
      "required": [
        "name",
        "evidence_type",
        "confidence",
        "evidence_ids"
      ],
      "additionalProperties": false
    },
    "statement": {
      "type": "object",
      "properties": {
        "value": {"type": "string"},
        "confidence": {"type": "number"},
        "evidence_ids": {
          "type": "array",
          "items": {"type": "string"}
        }
      },
      "required": ["value", "confidence", "evidence_ids"]
    }
  },
  "required": ["status", "summary", "findings"]
}`)

func Task() investigation.Task {
	return investigation.Task{
		ID:   "architecture",
		Name: "Architecture Discovery",

		Objective: `Analyze the source repository and determine the application's technical architecture.

Identify:
- primary programming languages
- data and configuration formats
- frameworks
- important libraries
- database technologies
- web/application servers where supported by repository evidence
- external interfaces and services used by the application
- overall architectural style
- important source entrypoints
- important directories and their purposes

Classification rules:
- Programming languages belong in languages.
- JSON, YAML, XML, TOML, etc. belong in formats, not languages.
- Frameworks belong in frameworks.
- Ordinary dependencies/packages belong in libraries.
- External HTTP APIs, protocols, or remote services belong in external_interfaces, not frameworks.
- A named framework belongs in frameworks only when direct repository evidence identifies it. Directory structure or architectural resemblance alone is insufficient.
- If no framework is directly supported, leave frameworks empty and describe a generic style such as custom PHP MVC-style application under architecture_style.

Use repository evidence rather than guessing.

Do NOT investigate authentication, authorization, business features, or user workflows yet.`,

		Instructions: `Start by orienting yourself with repo_info and the repository structure.

Inspect likely manifests, dependency files, entrypoints, configuration files, and representative source files. Use search and read_file as needed.

Check dependency manifests before naming frameworks. Every framework finding must set evidence_type=direct and cite evidence that directly identifies the framework, such as an explicit manifest dependency, an import/use of its namespace, bootstrap code that instantiates it, framework configuration, or canonical framework files backed by source. Never identify a named framework from Controller/Model/Template directories, generic MVC structure, or similar naming alone.

Do not infer PSR-7 or PSR-15 merely because the application exposes HTTP endpoints or follows broadly PSR-like patterns. Verify named framework and protocol-stack claims against imports, bootstrap, configuration, or dependencies. If direct evidence is absent or ambiguous, use frameworks=[] and describe the architecture generically under architecture_style. Framework absence is a valid result.

You have a limited context budget:
- Prefer targeted inspection.
- Do not read entire source files unless necessary.
- Prefer manifests, dependency files, configuration files, entrypoints, and representative files.
- Do not repeatedly inspect files or directories once the relevant architecture is understood.
- Do not continue investigating merely to increase confidence in conclusions that already have adequate evidence.

Completion criteria:

You may submit the result once you can identify with reasonable confidence:
1. Primary programming languages.
2. Data/configuration formats.
3. Major frameworks and important libraries.
4. Database technologies, if any.
5. Web/application server technologies, if supported by repository evidence.
6. External interfaces/services, if any.
7. Overall architectural style.
8. Principal executable/application entrypoints.
9. Major source directories and their purposes.

If an item cannot be determined, report it as unresolved rather than continuing indefinitely.

Every finding with confidence greater than zero must reference evidence.

Once these criteria are satisfied, call submit_investigation_result immediately.`,

		ToolNames: []string{
			"repo_info",
			"list_files",
			"find_files",
			"file_info",
			"read_file",
			"search",
		},

		SubmitSchema: submitSchema,

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
) (*Findings, *investigation.Result, error) {
	result, err := runner.Run(ctx, Task())
	if err != nil {
		return nil, nil, err
	}

	var findings Findings
	if err := investigation.DecodeObjectFindings(
		result.Findings,
		&findings,
		"architecture findings",
	); err != nil {
		return nil, result, err
	}

	return &findings, result, nil
}

func validateResult(
	result *investigation.Result,
	evidence investigation.EvidenceLookup,
) error {
	var findings Findings

	if err := investigation.DecodeObjectFindings(
		result.Findings,
		&findings,
		"architecture findings",
	); err != nil {
		return investigation.NewSubmissionFormatError(err)
	}

	validateTech := func(category string, items []Technology) error {
		for i, item := range items {
			if item.EvidenceType != "" &&
				item.EvidenceType != "direct" &&
				item.EvidenceType != "inferred" {
				return fmt.Errorf(
					"%s[%d] %q has invalid evidence type %q",
					category,
					i,
					item.Name,
					item.EvidenceType,
				)
			}
			if err := validateEvidence(
				fmt.Sprintf("%s[%d] %q", category, i, item.Name),
				item.Confidence,
				item.EvidenceIDs,
				evidence,
			); err != nil {
				return err
			}
		}

		return nil
	}

	if err := validateTech("languages", findings.Languages); err != nil {
		return err
	}

	if err := validateTech("formats", findings.Formats); err != nil {
		return err
	}

	if err := validateTech("frameworks", findings.Frameworks); err != nil {
		return err
	}
	for i, framework := range findings.Frameworks {
		if framework.EvidenceType != "direct" {
			return fmt.Errorf(
				"frameworks[%d] %q requires direct framework evidence",
				i,
				framework.Name,
			)
		}
	}

	if err := validateTech("libraries", findings.Libraries); err != nil {
		return err
	}

	if err := validateTech("databases", findings.Databases); err != nil {
		return err
	}

	if err := validateTech("web_servers", findings.WebServers); err != nil {
		return err
	}

	if err := validateTech(
		"external_interfaces",
		findings.ExternalInterfaces,
	); err != nil {
		return err
	}

	if err := validateEvidence(
		"architecture_style",
		findings.ArchitectureStyle.Confidence,
		findings.ArchitectureStyle.EvidenceIDs,
		evidence,
	); err != nil {
		return err
	}

	for i, item := range findings.Entrypoints {
		if item.Type == "" {
			return fmt.Errorf(
				"entrypoints[%d] %q has no type",
				i,
				item.Path,
			)
		}

		if err := validateEvidence(
			fmt.Sprintf("entrypoints[%d] %q", i, item.Path),
			item.Confidence,
			item.EvidenceIDs,
			evidence,
		); err != nil {
			return err
		}
	}

	for i, item := range findings.ImportantDirectories {
		if err := validateEvidence(
			fmt.Sprintf(
				"important_directories[%d] %q",
				i,
				item.Path,
			),
			item.Confidence,
			item.EvidenceIDs,
			evidence,
		); err != nil {
			return err
		}
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
