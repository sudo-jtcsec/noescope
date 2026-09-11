package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
)

const SchemaVersion = "0.1"

type Application struct {
	SchemaVersion string                `json:"schema_version"`
	Metadata      Metadata              `json:"metadata"`
	Architecture  architecture.Findings `json:"architecture"`
	Identity      Identity              `json:"identity"`
	Entities      []entities.Entity     `json:"entities"`
	Surface       surface.Findings      `json:"surface"`
	Features      []features.Node       `json:"features"`
	Discovery     Discovery             `json:"discovery"`
}

type Metadata struct {
	ProjectName    string         `json:"project_name"`
	GeneratedAt    time.Time      `json:"generated_at"`
	RunID          string         `json:"run_id"`
	Source         SourceMetadata `json:"source"`
	ApplicationURL string         `json:"application_url"`
}

type SourceMetadata struct {
	Root      string `json:"root"`
	GitBranch string `json:"git_branch"`
	GitCommit string `json:"git_commit"`
	GitDirty  bool   `json:"git_dirty"`
}

type Identity struct {
	Authentication authentication.Findings `json:"authentication"`
	Authorization  authorization.Findings  `json:"authorization"`
}

type Discovery struct {
	EvidenceFile string          `json:"evidence_file"`
	Stages       DiscoveryStages `json:"stages"`
}

type DiscoveryStages struct {
	Architecture   StageProvenance `json:"architecture"`
	Authentication StageProvenance `json:"authentication"`
	Authorization  StageProvenance `json:"authorization"`
	Entities       StageProvenance `json:"entities"`
	Surface        StageProvenance `json:"surface"`
	Features       StageProvenance `json:"features"`
}

type StageProvenance struct {
	Status     string                             `json:"status"`
	Unresolved []investigation.UnresolvedQuestion `json:"unresolved"`
}

type Findings struct {
	Architecture   *architecture.Findings
	Authentication *authentication.Findings
	Authorization  *authorization.Findings
	Entities       *entities.Findings
	Surface        *surface.Findings
	Features       *features.Findings
}

type Results struct {
	Architecture   *investigation.Result
	Authentication *investigation.Result
	Authorization  *investigation.Result
	Entities       *investigation.Result
	Surface        *investigation.Result
	Features       *investigation.Result
}

type BuildInput struct {
	Metadata Metadata
	Findings Findings
	Results  Results
}

func Build(input BuildInput) (*Application, error) {
	if err := requireCompleteFindings(input.Findings); err != nil {
		return nil, err
	}
	application := &Application{
		SchemaVersion: SchemaVersion,
		Metadata:      input.Metadata,
		Discovery: Discovery{
			EvidenceFile: "../evidence.jsonl",
			Stages: DiscoveryStages{
				Architecture:   stageProvenance(input.Results.Architecture),
				Authentication: stageProvenance(input.Results.Authentication),
				Authorization:  stageProvenance(input.Results.Authorization),
				Entities:       stageProvenance(input.Results.Entities),
				Surface:        stageProvenance(input.Results.Surface),
				Features:       stageProvenance(input.Results.Features),
			},
		},
	}
	application.Metadata.GeneratedAt = application.Metadata.GeneratedAt.UTC()
	application.Metadata.ApplicationURL = sanitizeApplicationURL(
		application.Metadata.ApplicationURL,
	)

	// Clone through JSON so deterministic normalization never mutates the
	// validated canonical Findings retained by the coordinator.
	sections := struct {
		Architecture   *architecture.Findings   `json:"architecture"`
		Authentication *authentication.Findings `json:"authentication"`
		Authorization  *authorization.Findings  `json:"authorization"`
		Entities       *entities.Findings       `json:"entities"`
		Surface        *surface.Findings        `json:"surface"`
		Features       *features.Findings       `json:"features"`
	}{
		input.Findings.Architecture,
		input.Findings.Authentication,
		input.Findings.Authorization,
		input.Findings.Entities,
		input.Findings.Surface,
		input.Findings.Features,
	}
	raw, err := json.Marshal(sections)
	if err != nil {
		return nil, err
	}
	var cloned struct {
		Architecture   architecture.Findings   `json:"architecture"`
		Authentication authentication.Findings `json:"authentication"`
		Authorization  authorization.Findings  `json:"authorization"`
		Entities       entities.Findings       `json:"entities"`
		Surface        surface.Findings        `json:"surface"`
		Features       features.Findings       `json:"features"`
	}
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return nil, err
	}

	application.Architecture = cloned.Architecture
	application.Identity = Identity{
		Authentication: cloned.Authentication,
		Authorization:  cloned.Authorization,
	}
	application.Entities = cloned.Entities.Entities
	application.Surface = cloned.Surface
	application.Features = cloned.Features.Features
	normalize(application)
	return application, nil
}

func requireCompleteFindings(findings Findings) error {
	missing := make([]string, 0, 6)
	if findings.Architecture == nil {
		missing = append(missing, "architecture")
	}
	if findings.Authentication == nil {
		missing = append(missing, "authentication")
	}
	if findings.Authorization == nil {
		missing = append(missing, "authorization")
	}
	if findings.Entities == nil {
		missing = append(missing, "entities")
	}
	if findings.Surface == nil {
		missing = append(missing, "surface")
	}
	if findings.Features == nil {
		missing = append(missing, "features")
	}
	if len(missing) > 0 {
		return fmt.Errorf("assemble complete application: missing findings: %v", missing)
	}
	return nil
}

func stageProvenance(result *investigation.Result) StageProvenance {
	if result == nil {
		return StageProvenance{Unresolved: []investigation.UnresolvedQuestion{}}
	}
	return StageProvenance{
		Status:     result.Status,
		Unresolved: append([]investigation.UnresolvedQuestion{}, result.Unresolved...),
	}
}

func sanitizeApplicationURL(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}

func normalize(application *Application) {
	sort.Strings(application.Architecture.ArchitectureStyle.EvidenceIDs)
	sortTechnologies(application.Architecture.Languages)
	sortTechnologies(application.Architecture.Formats)
	sortTechnologies(application.Architecture.Frameworks)
	sortTechnologies(application.Architecture.Libraries)
	sortTechnologies(application.Architecture.Databases)
	sortTechnologies(application.Architecture.WebServers)
	sortTechnologies(application.Architecture.ExternalInterfaces)
	sort.Slice(application.Architecture.Entrypoints, func(i, j int) bool {
		return application.Architecture.Entrypoints[i].Path <
			application.Architecture.Entrypoints[j].Path
	})
	for i := range application.Architecture.Entrypoints {
		sort.Strings(application.Architecture.Entrypoints[i].EvidenceIDs)
	}
	sort.Slice(application.Architecture.ImportantDirectories, func(i, j int) bool {
		return application.Architecture.ImportantDirectories[i].Path <
			application.Architecture.ImportantDirectories[j].Path
	})
	for i := range application.Architecture.ImportantDirectories {
		sort.Strings(application.Architecture.ImportantDirectories[i].EvidenceIDs)
	}

	sort.Strings(application.Identity.Authentication.EvidenceIDs)
	sort.Slice(application.Identity.Authentication.Mechanisms, func(i, j int) bool {
		return application.Identity.Authentication.Mechanisms[i].ID <
			application.Identity.Authentication.Mechanisms[j].ID
	})
	for i := range application.Identity.Authentication.Mechanisms {
		mechanism := &application.Identity.Authentication.Mechanisms[i]
		sort.Strings(mechanism.LoginEntrypoints)
		sort.Strings(mechanism.CredentialFields)
		sort.Strings(mechanism.EstablishedBy)
		sort.Strings(mechanism.CheckedBy)
		sort.Strings(mechanism.SourceComponents)
		sort.Strings(mechanism.EvidenceIDs)
		if mechanism.Logout != nil {
			sort.Strings(mechanism.Logout.Entrypoints)
		}
	}
	sort.Strings(application.Identity.Authorization.EvidenceIDs)
	if application.Identity.Authorization.Model != nil {
		sort.Strings(application.Identity.Authorization.Model.EvidenceIDs)
	}
	sort.Slice(application.Identity.Authorization.Roles, func(i, j int) bool {
		return application.Identity.Authorization.Roles[i].ID <
			application.Identity.Authorization.Roles[j].ID
	})
	for i := range application.Identity.Authorization.Roles {
		role := &application.Identity.Authorization.Roles[i]
		sort.Strings(role.Inherits)
		sort.Strings(role.EvidenceIDs)
	}
	sort.Slice(application.Identity.Authorization.Permissions, func(i, j int) bool {
		return application.Identity.Authorization.Permissions[i].ID <
			application.Identity.Authorization.Permissions[j].ID
	})
	for i := range application.Identity.Authorization.Permissions {
		sort.Strings(application.Identity.Authorization.Permissions[i].EvidenceIDs)
	}
	sort.Slice(application.Identity.Authorization.RolePermissions, func(i, j int) bool {
		return application.Identity.Authorization.RolePermissions[i].RoleID <
			application.Identity.Authorization.RolePermissions[j].RoleID
	})
	for i := range application.Identity.Authorization.RolePermissions {
		mapping := &application.Identity.Authorization.RolePermissions[i]
		sort.Strings(mapping.PermissionIDs)
		sort.Strings(mapping.EvidenceIDs)
	}
	sort.Slice(application.Identity.Authorization.Enforcement, func(i, j int) bool {
		left := application.Identity.Authorization.Enforcement[i]
		right := application.Identity.Authorization.Enforcement[j]
		return left.Path+"\x00"+left.Name < right.Path+"\x00"+right.Name
	})
	for i := range application.Identity.Authorization.Enforcement {
		sort.Strings(application.Identity.Authorization.Enforcement[i].EvidenceIDs)
	}

	sort.Slice(application.Entities, func(i, j int) bool {
		return application.Entities[i].ID < application.Entities[j].ID
	})
	for i := range application.Entities {
		normalizeEntity(&application.Entities[i])
	}
	sort.Slice(application.Surface.Interfaces, func(i, j int) bool {
		return application.Surface.Interfaces[i].ID < application.Surface.Interfaces[j].ID
	})
	for i := range application.Surface.Interfaces {
		normalizeInterface(&application.Surface.Interfaces[i])
	}
	sort.Slice(application.Surface.Integrations, func(i, j int) bool {
		return application.Surface.Integrations[i].ID < application.Surface.Integrations[j].ID
	})
	for i := range application.Surface.Integrations {
		normalizeIntegration(&application.Surface.Integrations[i])
	}
	sort.Slice(application.Surface.Handlers, func(i, j int) bool {
		return application.Surface.Handlers[i].ID < application.Surface.Handlers[j].ID
	})
	for i := range application.Surface.Handlers {
		handler := &application.Surface.Handlers[i]
		sort.Strings(handler.InterfaceIDs)
		sort.Strings(handler.EvidenceIDs)
	}
	sort.Slice(application.Surface.Relationships, func(i, j int) bool {
		left := application.Surface.Relationships[i]
		right := application.Surface.Relationships[j]
		return left.Type+"\x00"+left.FromInterfaceID+"\x00"+
			left.ToInterfaceID+"\x00"+left.ToIntegrationID <
			right.Type+"\x00"+right.FromInterfaceID+"\x00"+
				right.ToInterfaceID+"\x00"+right.ToIntegrationID
	})
	for i := range application.Surface.Relationships {
		sort.Strings(application.Surface.Relationships[i].EvidenceIDs)
	}

	for i := range application.Features {
		normalizeFeatureNode(&application.Features[i])
	}
}

func sortTechnologies(values []architecture.Technology) {
	for i := range values {
		sort.Strings(values[i].EvidenceIDs)
	}
	sort.Slice(values, func(i, j int) bool {
		return values[i].Name < values[j].Name
	})
}

func normalizeEntity(entity *entities.Entity) {
	sort.Strings(entity.Aliases)
	sort.Strings(entity.EvidenceIDs)
	sort.Slice(entity.SourceComponents, func(i, j int) bool {
		left := entity.SourceComponents[i]
		right := entity.SourceComponents[j]
		return left.Path+"\x00"+left.Symbol < right.Path+"\x00"+right.Symbol
	})
	sort.Slice(entity.Persistence, func(i, j int) bool {
		left := entity.Persistence[i]
		right := entity.Persistence[j]
		return left.Type+"\x00"+left.Name < right.Type+"\x00"+right.Name
	})
	for i := range entity.Persistence {
		sort.Strings(entity.Persistence[i].EvidenceIDs)
	}
	sort.Slice(entity.Relationships, func(i, j int) bool {
		left := entity.Relationships[i]
		right := entity.Relationships[j]
		return left.Type+"\x00"+left.TargetEntityID <
			right.Type+"\x00"+right.TargetEntityID
	})
	for i := range entity.Relationships {
		sort.Strings(entity.Relationships[i].EvidenceIDs)
	}
}

func normalizeInterface(item *surface.Interface) {
	sort.Strings(item.InputNames)
	sort.Strings(item.EntityIDs)
	sort.Strings(item.EvidenceIDs)
	sortSurfaceSourceComponents(item.SourceComponents)
	if item.Access != nil {
		sort.Strings(item.Access.RoleIDs)
		sort.Strings(item.Access.PermissionIDs)
		sort.Strings(item.Access.EvidenceIDs)
	}
}

func normalizeIntegration(item *surface.Integration) {
	sort.Strings(item.EntityIDs)
	sort.Strings(item.EvidenceIDs)
	sortSurfaceSourceComponents(item.SourceComponents)
}

func sortSurfaceSourceComponents(values []surface.SourceComponent) {
	sort.Slice(values, func(i, j int) bool {
		return values[i].Path+"\x00"+values[i].Symbol <
			values[j].Path+"\x00"+values[j].Symbol
	})
}

func normalizeFeatureNode(node *features.Node) {
	sort.Strings(node.Access.RoleIDs)
	sort.Strings(node.Access.PermissionIDs)
	sort.Strings(node.EntityIDs)
	sort.Strings(node.InterfaceIDs)
	sort.Strings(node.EvidenceIDs)
	sort.Slice(node.SourceComponents, func(i, j int) bool {
		return node.SourceComponents[i].Path+"\x00"+node.SourceComponents[i].Symbol <
			node.SourceComponents[j].Path+"\x00"+node.SourceComponents[j].Symbol
	})
	for i := range node.Children {
		normalizeFeatureNode(&node.Children[i])
	}
}
