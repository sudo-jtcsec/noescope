package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
)

// Keep immutable prior-task context comfortably below the investigation
// message ceiling so the task prompt and recent investigation turns have room.
// TODO: If a deterministic projection exceeds this threshold, segment the
// stage instead of increasing context without bound. In particular, large
// feature trees should use top-level discovery followed by serial per-module
// expansion investigations.
const maxProjectedContextBytes = 30000

type contextProjection struct {
	Data           json.RawMessage
	CanonicalBytes int
	ProjectedBytes int
}

type architectureContextView struct {
	Languages         []string                `json:"languages"`
	Frameworks        []string                `json:"frameworks"`
	ArchitectureStyle string                  `json:"architecture_style"`
	Entrypoints       []entrypointContextView `json:"entrypoints"`
}

type entrypointContextView struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type authenticationContextView struct {
	AuthenticationPresent bool                   `json:"authentication_present"`
	Mechanisms            []mechanismContextView `json:"mechanisms"`
}

type mechanismContextView struct {
	ID               string   `json:"id"`
	Type             string   `json:"type"`
	LoginEntrypoints []string `json:"login_entrypoints,omitempty"`
}

type authorizationContextView struct {
	AuthorizationPresent bool                 `json:"authorization_present"`
	ModelType            string               `json:"model_type,omitempty"`
	Roles                []namedIDContextView `json:"roles"`
	Permissions          []namedIDContextView `json:"permissions"`
}

type namedIDContextView struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type entityContextView struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

type authenticationTaskContext struct {
	Architecture architectureContextView `json:"architecture"`
}

type authorizationTaskContext struct {
	Architecture   architectureContextView   `json:"architecture"`
	Authentication authenticationContextView `json:"authentication"`
}

type entitiesTaskContext struct {
	Architecture   architectureContextView `json:"architecture"`
	Authentication struct {
		AuthenticationPresent bool `json:"authentication_present"`
	} `json:"authentication"`
	Authorization authorizationContextView `json:"authorization"`
}

type surfaceTaskContext struct {
	Architecture   architectureContextView   `json:"architecture"`
	Authentication authenticationContextView `json:"authentication"`
	Authorization  authorizationContextView  `json:"authorization"`
	Entities       []entityContextView       `json:"entities"`
}

type featureArchitectureContextView struct {
	Languages         []string `json:"languages"`
	Frameworks        []string `json:"frameworks"`
	ArchitectureStyle string   `json:"architecture_style"`
}

type featureNamedIDContextView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type featureAuthorizationContextView struct {
	AuthorizationPresent bool                        `json:"authorization_present"`
	ModelType            string                      `json:"model_type,omitempty"`
	Roles                []featureNamedIDContextView `json:"roles"`
	Permissions          []featureNamedIDContextView `json:"permissions"`
}

type featureEntityContextView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type featureAccessContextView struct {
	Authentication string   `json:"auth"`
	RoleIDs        []string `json:"roles"`
	PermissionIDs  []string `json:"permissions"`
}

type featureInterfaceContextView struct {
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Name      string   `json:"name,omitempty"`
	Locator   string   `json:"locator"`
	Access    string   `json:"access,omitempty"`
	EntityIDs []string `json:"entities,omitempty"`
	Evidence  string   `json:"evidence,omitempty"`
	Root      bool     `json:"root,omitempty"`
}

type featureRelationshipContextView struct {
	Type            string `json:"type"`
	FromInterfaceID string `json:"from_interface_id"`
	ToInterfaceID   string `json:"to_interface_id,omitempty"`
	ToIntegrationID string `json:"to_integration_id,omitempty"`
}

type featureIntegrationContextView struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type featureSurfaceContextView struct {
	AccessProfiles   []featureAccessProfileContextView   `json:"access_profiles"`
	EvidenceProfiles []featureEvidenceProfileContextView `json:"evidence_profiles"`
	Interfaces       []featureInterfaceContextView       `json:"interfaces"`
	Relationships    []featureRelationshipContextView    `json:"relationships"`
	Integrations     []featureIntegrationContextView     `json:"integrations"`
}

type featureAccessProfileContextView struct {
	ID string `json:"id"`
	featureAccessContextView
}

type featureEvidenceProfileContextView struct {
	ID         string `json:"id"`
	EvidenceID string `json:"evidence_id"`
}

type featureTaskContext struct {
	Architecture   featureArchitectureContextView  `json:"architecture"`
	Authentication authenticationContextView       `json:"authentication"`
	Authorization  featureAuthorizationContextView `json:"authorization"`
	Entities       []featureEntityContextView      `json:"entities"`
	Surface        featureSurfaceContextView       `json:"surface"`
}

func buildAuthenticationContext(
	architectureFindings *architecture.Findings,
) (contextProjection, error) {
	canonical := struct {
		Architecture *architecture.Findings `json:"architecture"`
	}{Architecture: architectureFindings}
	projected := authenticationTaskContext{
		Architecture: projectArchitecture(architectureFindings),
	}
	return marshalContextProjection("authentication", canonical, projected)
}

func buildAuthorizationContext(
	architectureFindings *architecture.Findings,
	authenticationFindings *authentication.Findings,
) (contextProjection, error) {
	canonical := struct {
		Architecture   *architecture.Findings   `json:"architecture"`
		Authentication *authentication.Findings `json:"authentication"`
	}{architectureFindings, authenticationFindings}
	projected := authorizationTaskContext{
		Architecture:   projectArchitecture(architectureFindings),
		Authentication: projectAuthentication(authenticationFindings),
	}
	return marshalContextProjection("authorization", canonical, projected)
}

func buildEntitiesContext(
	architectureFindings *architecture.Findings,
	authenticationFindings *authentication.Findings,
	authorizationFindings *authorization.Findings,
) (contextProjection, error) {
	canonical := struct {
		Architecture   *architecture.Findings   `json:"architecture"`
		Authentication *authentication.Findings `json:"authentication"`
		Authorization  *authorization.Findings  `json:"authorization"`
	}{architectureFindings, authenticationFindings, authorizationFindings}
	projected := entitiesTaskContext{
		Architecture:  projectArchitecture(architectureFindings),
		Authorization: projectAuthorization(authorizationFindings),
	}
	projected.Authentication.AuthenticationPresent =
		authenticationFindings.AuthenticationPresent
	return marshalContextProjection("entities", canonical, projected)
}

func buildSurfaceContext(
	architectureFindings *architecture.Findings,
	authenticationFindings *authentication.Findings,
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
) (contextProjection, error) {
	canonical := struct {
		Architecture   *architecture.Findings   `json:"architecture"`
		Authentication *authentication.Findings `json:"authentication"`
		Authorization  *authorization.Findings  `json:"authorization"`
		Entities       *entities.Findings       `json:"entities"`
	}{
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
		entityFindings,
	}

	projectedEntities := make([]entityContextView, 0, len(entityFindings.Entities))
	for _, entity := range entityFindings.Entities {
		projectedEntities = append(projectedEntities, entityContextView{
			ID:      entity.ID,
			Name:    entity.Name,
			Aliases: append([]string(nil), entity.Aliases...),
		})
	}
	projected := surfaceTaskContext{
		Architecture:   projectArchitecture(architectureFindings),
		Authentication: projectAuthentication(authenticationFindings),
		Authorization:  projectAuthorization(authorizationFindings),
		Entities:       projectedEntities,
	}
	return marshalContextProjection("surface", canonical, projected)
}

func buildFeatureContext(
	architectureFindings *architecture.Findings,
	authenticationFindings *authentication.Findings,
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
	surfaceFindings *surface.Findings,
) (contextProjection, error) {
	canonical := struct {
		Architecture   *architecture.Findings   `json:"architecture"`
		Authentication *authentication.Findings `json:"authentication"`
		Authorization  *authorization.Findings  `json:"authorization"`
		Entities       *entities.Findings       `json:"entities"`
		Surface        *surface.Findings        `json:"surface"`
	}{
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
		entityFindings,
		surfaceFindings,
	}

	projected := featureTaskContext{
		Architecture: featureArchitectureContextView{
			Languages:         technologyNames(architectureFindings.Languages),
			Frameworks:        technologyNames(architectureFindings.Frameworks),
			ArchitectureStyle: architectureFindings.ArchitectureStyle.Value,
		},
		Authentication: projectAuthentication(authenticationFindings),
		Authorization:  projectFeatureAuthorization(authorizationFindings),
		Entities:       projectFeatureEntities(entityFindings),
		Surface:        projectFeatureSurface(surfaceFindings),
	}
	return marshalContextProjection("features", canonical, projected)
}

func projectFeatureAuthorization(
	findings *authorization.Findings,
) featureAuthorizationContextView {
	view := featureAuthorizationContextView{
		AuthorizationPresent: findings.AuthorizationPresent,
		Roles: make(
			[]featureNamedIDContextView,
			0,
			len(findings.Roles),
		),
		Permissions: make(
			[]featureNamedIDContextView,
			0,
			len(findings.Permissions),
		),
	}
	if findings.Model != nil {
		view.ModelType = findings.Model.Type
	}
	for _, role := range findings.Roles {
		view.Roles = append(view.Roles, featureNamedIDContextView{
			ID:          role.ID,
			Name:        role.Name,
			EvidenceIDs: firstEvidenceID(role.EvidenceIDs),
		})
	}
	for _, permission := range findings.Permissions {
		view.Permissions = append(view.Permissions, featureNamedIDContextView{
			ID:          permission.ID,
			Name:        permission.Name,
			EvidenceIDs: firstEvidenceID(permission.EvidenceIDs),
		})
	}
	return view
}

func projectFeatureEntities(findings *entities.Findings) []featureEntityContextView {
	view := make([]featureEntityContextView, 0, len(findings.Entities))
	for _, entity := range findings.Entities {
		view = append(view, featureEntityContextView{
			ID:          entity.ID,
			Name:        entity.Name,
			Aliases:     append([]string(nil), entity.Aliases...),
			EvidenceIDs: firstEvidenceID(entity.EvidenceIDs),
		})
	}
	return view
}

func projectFeatureSurface(findings *surface.Findings) featureSurfaceContextView {
	accessProfiles, accessProfileIDs := projectFeatureAccessProfiles(findings.Interfaces)
	evidenceProfiles, evidenceProfileIDs := projectFeatureEvidenceProfiles(findings.Interfaces)
	view := featureSurfaceContextView{
		AccessProfiles:   accessProfiles,
		EvidenceProfiles: evidenceProfiles,
		Interfaces: make(
			[]featureInterfaceContextView,
			0,
			len(findings.Interfaces),
		),
		Relationships: make(
			[]featureRelationshipContextView,
			0,
			len(findings.Relationships),
		),
		Integrations: make(
			[]featureIntegrationContextView,
			0,
			len(findings.Integrations),
		),
	}
	interfaces := append([]surface.Interface(nil), findings.Interfaces...)
	sort.Slice(interfaces, func(i, j int) bool {
		leftRoot := features.IsRootInterface(interfaces[i])
		rightRoot := features.IsRootInterface(interfaces[j])
		if leftRoot != rightRoot {
			return !leftRoot
		}
		return interfaces[i].ID < interfaces[j].ID
	})
	for _, item := range interfaces {
		projected := featureInterfaceContextView{
			ID: item.ID, Type: item.Type,
			Name:      compactInterfaceName(item),
			Locator:   compactInterfaceLocator(item),
			EntityIDs: append([]string(nil), item.EntityIDs...),
			Evidence:  evidenceProfileIDs[firstString(item.EvidenceIDs)],
			Root:      features.IsRootInterface(item),
		}
		if item.Access != nil {
			projected.Access = accessProfileIDs[featureAccessKey(item.Access)]
		}
		view.Interfaces = append(view.Interfaces, projected)
	}
	for _, relationship := range findings.Relationships {
		// Concrete invocation interfaces carry the information Feature Discovery
		// needs for semantic mapping. Retain outbound dependency edges, but omit
		// command-flow topology that would repeat those invocation points.
		if relationship.Type != "integration_call" {
			continue
		}
		view.Relationships = append(
			view.Relationships,
			featureRelationshipContextView{
				Type:            relationship.Type,
				FromInterfaceID: relationship.FromInterfaceID,
				ToInterfaceID:   relationship.ToInterfaceID,
				ToIntegrationID: relationship.ToIntegrationID,
			},
		)
	}
	for _, integration := range findings.Integrations {
		view.Integrations = append(view.Integrations, featureIntegrationContextView{
			ID: integration.ID, Type: integration.Type, Name: integration.Name,
		})
	}
	return view
}

func projectFeatureAccessProfiles(
	interfaces []surface.Interface,
) ([]featureAccessProfileContextView, map[string]string) {
	byKey := make(map[string]featureAccessContextView)
	for _, item := range interfaces {
		if item.Access == nil {
			continue
		}
		key := featureAccessKey(item.Access)
		byKey[key] = featureAccessContextView{
			Authentication: item.Access.Authentication,
			RoleIDs:        append([]string(nil), item.Access.RoleIDs...),
			PermissionIDs:  append([]string(nil), item.Access.PermissionIDs...),
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	profiles := make([]featureAccessProfileContextView, 0, len(keys))
	profileIDs := make(map[string]string, len(keys))
	for index, key := range keys {
		id := fmt.Sprintf("a%d", index+1)
		profileIDs[key] = id
		profiles = append(profiles, featureAccessProfileContextView{
			ID: id, featureAccessContextView: byKey[key],
		})
	}
	return profiles, profileIDs
}

func projectFeatureEvidenceProfiles(
	interfaces []surface.Interface,
) ([]featureEvidenceProfileContextView, map[string]string) {
	unique := make(map[string]struct{})
	for _, item := range interfaces {
		if evidenceID := firstString(item.EvidenceIDs); evidenceID != "" {
			unique[evidenceID] = struct{}{}
		}
	}
	evidenceIDs := make([]string, 0, len(unique))
	for evidenceID := range unique {
		evidenceIDs = append(evidenceIDs, evidenceID)
	}
	sort.Strings(evidenceIDs)
	profiles := make([]featureEvidenceProfileContextView, 0, len(evidenceIDs))
	profileIDs := make(map[string]string, len(evidenceIDs))
	for index, evidenceID := range evidenceIDs {
		id := fmt.Sprintf("e%d", index+1)
		profileIDs[evidenceID] = id
		profiles = append(profiles, featureEvidenceProfileContextView{
			ID: id, EvidenceID: evidenceID,
		})
	}
	return profiles, profileIDs
}

func featureAccessKey(access *surface.Access) string {
	if access == nil {
		return ""
	}
	value := featureAccessContextView{
		Authentication: access.Authentication,
		RoleIDs:        append([]string(nil), access.RoleIDs...),
		PermissionIDs:  append([]string(nil), access.PermissionIDs...),
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

func compactInterfaceName(item surface.Interface) string {
	for _, redundant := range []string{
		item.ID,
		strings.TrimPrefix(item.ID, strings.SplitN(item.ID, ".", 2)[0]+"."),
		item.Locator.MethodName,
		item.Locator.Command,
	} {
		if redundant != "" && strings.EqualFold(item.Name, redundant) {
			return ""
		}
	}
	return item.Name
}

func compactInterfaceLocator(item surface.Interface) string {
	locator := item.Locator
	if locator.MethodName != "" {
		return locator.MethodName
	}
	switch item.Type {
	case "web_page", "form_action":
		return strings.TrimSpace(locator.Method + " " + locator.Path)
	case "cli_command":
		return locator.Command
	case "scheduled_job":
		return strings.TrimSpace(locator.Schedule + " " + locator.Command)
	case "worker", "event_consumer":
		return strings.TrimSpace(locator.Event + " " + locator.Command)
	case "script":
		return strings.TrimSpace(locator.Command + " " + locator.Path)
	case "websocket":
		return strings.TrimSpace(locator.Protocol + " " + locator.Path)
	case "api_endpoint":
		return joinNonEmpty(
			locator.Protocol, locator.Method, locator.Path, locator.TransportPath,
		)
	default:
		return joinNonEmpty(
			locator.Method, locator.Path, locator.Command, locator.Schedule,
			locator.Event, locator.Protocol, locator.TransportPath,
		)
	}
}

func joinNonEmpty(values ...string) string {
	compact := values[:0]
	for _, value := range values {
		if value != "" {
			compact = append(compact, value)
		}
	}
	return strings.Join(compact, " ")
}

func technologyNames(technologies []architecture.Technology) []string {
	names := make([]string, 0, len(technologies))
	for _, technology := range technologies {
		names = append(names, technology.Name)
	}
	return names
}

func firstEvidenceID(evidenceIDs []string) []string {
	if len(evidenceIDs) == 0 {
		return nil
	}
	return []string{evidenceIDs[0]}
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func projectArchitecture(
	findings *architecture.Findings,
) architectureContextView {
	view := architectureContextView{
		Languages:         make([]string, 0, len(findings.Languages)),
		Frameworks:        make([]string, 0, len(findings.Frameworks)),
		ArchitectureStyle: findings.ArchitectureStyle.Value,
		Entrypoints:       make([]entrypointContextView, 0, len(findings.Entrypoints)),
	}
	for _, language := range findings.Languages {
		view.Languages = append(view.Languages, language.Name)
	}
	for _, framework := range findings.Frameworks {
		view.Frameworks = append(view.Frameworks, framework.Name)
	}
	for _, entrypoint := range findings.Entrypoints {
		view.Entrypoints = append(view.Entrypoints, entrypointContextView{
			Path: entrypoint.Path,
			Type: entrypoint.Type,
		})
	}
	return view
}

func projectAuthentication(
	findings *authentication.Findings,
) authenticationContextView {
	view := authenticationContextView{
		AuthenticationPresent: findings.AuthenticationPresent,
		Mechanisms: make(
			[]mechanismContextView,
			0,
			len(findings.Mechanisms),
		),
	}
	for _, mechanism := range findings.Mechanisms {
		view.Mechanisms = append(view.Mechanisms, mechanismContextView{
			ID:               mechanism.ID,
			Type:             mechanism.Type,
			LoginEntrypoints: append([]string(nil), mechanism.LoginEntrypoints...),
		})
	}
	return view
}

func projectAuthorization(
	findings *authorization.Findings,
) authorizationContextView {
	view := authorizationContextView{
		AuthorizationPresent: findings.AuthorizationPresent,
		Roles:                make([]namedIDContextView, 0, len(findings.Roles)),
		Permissions: make(
			[]namedIDContextView,
			0,
			len(findings.Permissions),
		),
	}
	if findings.Model != nil {
		view.ModelType = findings.Model.Type
	}
	for _, role := range findings.Roles {
		view.Roles = append(view.Roles, namedIDContextView{
			ID: role.ID, Name: role.Name,
		})
	}
	for _, permission := range findings.Permissions {
		view.Permissions = append(view.Permissions, namedIDContextView{
			ID: permission.ID, Name: permission.Name,
		})
	}
	return view
}

func marshalContextProjection(
	stage string,
	canonical any,
	projected any,
) (contextProjection, error) {
	canonicalData, err := json.Marshal(canonical)
	if err != nil {
		return contextProjection{}, fmt.Errorf("marshal canonical context: %w", err)
	}
	projectedData, err := json.Marshal(projected)
	if err != nil {
		return contextProjection{}, fmt.Errorf("marshal projected context: %w", err)
	}
	if len(projectedData) > maxProjectedContextBytes {
		return contextProjection{}, fmt.Errorf(
			"%s projected context is %d bytes; stage segmentation is required",
			stage,
			len(projectedData),
		)
	}
	return contextProjection{
		Data:           projectedData,
		CanonicalBytes: len(canonicalData),
		ProjectedBytes: len(projectedData),
	}, nil
}

func logContextProjection(
	out io.Writer,
	stage string,
	projection contextProjection,
) {
	fmt.Fprintf(
		out,
		"[%s] context projection: %d -> %d bytes\n",
		stage,
		projection.CanonicalBytes,
		projection.ProjectedBytes,
	)
}
