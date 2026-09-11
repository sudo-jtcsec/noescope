package features

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
)

const maxModuleContextBytes = 30000

type RunOptions struct {
	RunRoot          string
	RepositoryCommit string
	Resume           bool
	FeatureAttempt   int
}

type taskExecutor func(context.Context, investigation.Task) (*investigation.Result, error)

func RunWithOptions(
	ctx context.Context,
	runner *investigation.Runner,
	taskContext json.RawMessage,
	authenticationFindings *authentication.Findings,
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
	surfaceFindings *surface.Findings,
	options RunOptions,
) (*Findings, *investigation.Result, error) {
	return runCoordinator(
		ctx, runner.Run, runner.Evidence, runner.Logf, taskContext,
		authenticationFindings, authorizationFindings, entityFindings,
		surfaceFindings, options,
	)
}

func runCoordinator(
	ctx context.Context,
	execute taskExecutor,
	evidence investigation.EvidenceLookup,
	logf func(string, ...any),
	taskContext json.RawMessage,
	authenticationFindings *authentication.Findings,
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
	surfaceFindings *surface.Findings,
	options RunOptions,
) (*Findings, *investigation.Result, error) {
	references := referencesFromFindings(
		authorizationFindings, entityFindings, surfaceFindings,
	)
	priorHash, err := featurePriorHash(
		taskContext, authenticationFindings, authorizationFindings,
		entityFindings, surfaceFindings,
	)
	if err != nil {
		return nil, nil, err
	}
	checkpoints := newCheckpointStore(options, priorHash)
	candidateIDs := ConcreteCandidateInterfaceIDs(surfaceFindings)

	moduleTask := moduleDiscoveryTask(taskContext, references, candidateIDs)
	moduleResult, reused, err := checkpoints.load(
		moduleTask, "modules", candidateIDs,
	)
	if err != nil {
		return nil, nil, err
	}
	if reused {
		if err := moduleTask.ValidateResult(moduleResult, evidence); err != nil {
			if logf != nil {
				logf("[features.modules] checkpoint failed semantic revalidation; rerunning")
			}
			reused = false
		}
		if reused && logf != nil {
			logf("[features.modules] reused validated checkpoint")
		}
	}
	if !reused {
		moduleResult, err = execute(ctx, moduleTask)
		if err != nil {
			return nil, nil, fmt.Errorf("module discovery: %w", err)
		}
		if err := checkpoints.save(moduleTask, "modules", candidateIDs, moduleResult); err != nil {
			return nil, nil, err
		}
	}
	moduleFindings, err := decodeFindings(moduleResult.Findings)
	if err != nil {
		return nil, moduleResult, err
	}
	normalizeFindings(moduleFindings)
	assigned := assignedConcreteInterfaces(moduleFindings, surfaceFindings)
	if logf != nil {
		logf("[features] module assignment:")
		logf("  concrete candidate interfaces: %d", len(candidateIDs))
		logf("  assigned: %d", len(assigned))
		logf("  unassigned: %d", len(candidateIDs)-len(assigned))
	}

	expandedModules := make([]Node, 0, len(moduleFindings.Features))
	expansionResults := make([]*investigation.Result, 0, len(moduleFindings.Features))
	for index, module := range moduleFindings.Features {
		if logf != nil {
			logf(
				"[features] expanding module %d/%d: %s",
				index+1, len(moduleFindings.Features), module.Name,
			)
		}
		moduleContext, canonicalBytes, projectedBytes, err := buildModuleContext(
			module, authenticationFindings, authorizationFindings,
			entityFindings, surfaceFindings,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("build module %q context: %w", module.ID, err)
		}
		if logf != nil {
			logf(
				"[features.%s] context projection: %d -> %d bytes",
				module.ID, canonicalBytes, projectedBytes,
			)
		}
		expansionTask := moduleExpansionTask(module, moduleContext, references, surfaceFindings)
		inputIDs := sortedUnique(module.InterfaceIDs)
		expansionResult, checkpointReused, err := checkpoints.load(
			expansionTask, module.ID, inputIDs,
		)
		if err != nil {
			return nil, nil, err
		}
		if checkpointReused {
			if err := expansionTask.ValidateResult(expansionResult, evidence); err != nil {
				if logf != nil {
					logf("[features.%s] checkpoint failed semantic revalidation; rerunning", module.ID)
				}
				checkpointReused = false
			}
			if checkpointReused && logf != nil {
				logf("[features.%s] reused validated checkpoint", module.ID)
			}
		}
		if !checkpointReused {
			expansionResult, err = execute(ctx, expansionTask)
			if err != nil {
				return nil, nil, fmt.Errorf("expand module %q: %w", module.ID, err)
			}
			if err := checkpoints.save(
				expansionTask, module.ID, inputIDs, expansionResult,
			); err != nil {
				return nil, nil, err
			}
		}
		expansionFindings, err := decodeFindings(expansionResult.Findings)
		if err != nil {
			return nil, expansionResult, err
		}
		expanded := module
		expanded.Children = cloneNodes(expansionFindings.Features)
		normalizeNode(&expanded)
		expandedModules = append(expandedModules, expanded)
		expansionResults = append(expansionResults, expansionResult)
	}

	findings := &Findings{Features: expandedModules}
	normalizeFindings(findings)
	result := mergeResults(moduleResult, expansionResults, findings)
	if err := validateResultWithReferences(result, evidence, references); err != nil {
		return nil, result, fmt.Errorf("validate merged Feature findings: %w", err)
	}
	return findings, result, nil
}

func moduleDiscoveryTask(
	context json.RawMessage,
	references priorReferences,
	candidateIDs []string,
) investigation.Task {
	task := Task()
	task.ID = "features.modules"
	task.Name = "Feature Module Discovery"
	task.Objective = `Identify only the top-level user/client-recognizable functional modules in the validated application model. Return module nodes with children set to an empty array. Do not build features or actions yet.`
	task.Instructions = `Assign each module the canonical concrete interface IDs that belong to its functional area so a later bounded expansion can use them. Prefer concrete operations and views over roots. Every module must have at least one canonical interface ID. Use a concise semantic domain ID such as projects or administration; never prefix IDs with module., feature., or action. Do not invent interface, entity, role, permission, or evidence IDs. Keep modules broad, distinct, and product-meaningful. Repository tools are for targeted clarification only.`
	task.Context = append(json.RawMessage(nil), context...)
	candidateSet := stringSet(candidateIDs)
	task.ValidateResult = func(
		result *investigation.Result,
		evidence investigation.EvidenceLookup,
	) error {
		if err := validateResultWithReferences(result, evidence, references); err != nil {
			return err
		}
		findings, err := decodeFindings(result.Findings)
		if err != nil {
			return investigation.NewSubmissionFormatError(err)
		}
		if len(candidateIDs) > 0 && len(findings.Features) == 0 {
			return fmt.Errorf("module discovery produced no modules for %d concrete interfaces", len(candidateIDs))
		}
		for _, module := range findings.Features {
			if module.Type != "module" {
				return fmt.Errorf("module discovery returned %q with type %q", module.ID, module.Type)
			}
			if strings.HasPrefix(module.ID, "module.") ||
				strings.HasPrefix(module.ID, "feature.") ||
				strings.HasPrefix(module.ID, "action.") {
				return fmt.Errorf("module %q uses a generic type prefix instead of a semantic domain ID", module.ID)
			}
			if len(module.Children) != 0 {
				return fmt.Errorf("module %q must not contain children during module discovery", module.ID)
			}
			if len(module.InterfaceIDs) == 0 {
				return fmt.Errorf("module %q has no interfaces assigned for expansion", module.ID)
			}
			hasConcrete := false
			for _, interfaceID := range module.InterfaceIDs {
				if _, ok := candidateSet[interfaceID]; ok {
					hasConcrete = true
					break
				}
			}
			if len(candidateIDs) > 0 && !hasConcrete {
				return fmt.Errorf("module %q assigns only root or non-operation interfaces", module.ID)
			}
		}
		normalizeFindings(findings)
		result.Findings, err = json.Marshal(findings)
		return err
	}
	return task
}

func moduleExpansionTask(
	module Node,
	context json.RawMessage,
	references priorReferences,
	surfaceFindings *surface.Findings,
) investigation.Task {
	task := Task()
	task.ID = "features." + module.ID
	task.Name = "Feature Module Expansion: " + module.Name
	task.Objective = fmt.Sprintf(
		`Expand only module %q (%s) into a coherent hierarchy of user/client-meaningful feature and action children. Return only the direct children beneath the supplied immutable module scaffold in findings.features; do not return the module itself.`,
		module.ID, module.Name,
	)
	task.Instructions = fmt.Sprintf(`Use only the module-specific canonical interfaces in the supplied context. Do not rediscover unrelated application areas. Group related operations into feature nodes, then represent concrete meaningful operations as action nodes. Do not mechanically create one action per interface: multiple interfaces may support one action, and one interface may support a feature/action hierarchy. If concrete operation-capable interfaces are supplied, at least one action is required. Prefer specific interfaces over roots. Never invent a missing interface; an evidenced semantic action may remain unmapped when no canonical interface exists. The coordinator owns the module scaffold: do not repeat or modify it. Every direct child ID must begin %q followed by a dot. Every nested action ID must begin its parent feature ID followed by a dot. Never use generic module., feature., or action. prefixes.`, module.ID)
	task.Context = context
	assigned := make(map[string]struct{}, len(module.InterfaceIDs))
	concreteCount := 0
	byID := surfaceInterfacesByID(surfaceFindings)
	for _, id := range module.InterfaceIDs {
		assigned[id] = struct{}{}
		if item, ok := byID[id]; ok && IsOperationCapableInterface(item) {
			concreteCount++
		}
	}
	task.ValidateResult = func(
		result *investigation.Result,
		evidence investigation.EvidenceLookup,
	) error {
		findings, err := decodeFindings(result.Findings)
		if err != nil {
			return investigation.NewSubmissionFormatError(err)
		}
		seenIDs := map[string]struct{}{module.ID: {}}
		for i := range findings.Features {
			if err := validateNode(
				&findings.Features[i], fmt.Sprintf("features[%d]", i), module.ID,
				seenIDs, references, evidence,
			); err != nil {
				return err
			}
		}
		for i, unresolved := range result.Unresolved {
			for _, evidenceID := range unresolved.EvidenceIDs {
				if !evidence.Exists(evidenceID) {
					return fmt.Errorf("unresolved[%d] references unknown evidence ID %q", i, evidenceID)
				}
			}
		}
		if err := validateExpansionChildren(findings.Features, assigned); err != nil {
			return err
		}
		actions := countActions(findings.Features)
		if concreteCount > 0 && actions == 0 {
			return fmt.Errorf(
				"module %q has %d concrete operation interfaces but produced no action nodes",
				module.ID, concreteCount,
			)
		}
		normalizeFindings(findings)
		result.Findings, err = json.Marshal(findings)
		return err
	}
	return task
}

func validateExpansionChildren(nodes []Node, assigned map[string]struct{}) error {
	for _, node := range nodes {
		if node.Type == "module" {
			return fmt.Errorf("module expansion returned nested module %q", node.ID)
		}
		for _, interfaceID := range node.InterfaceIDs {
			if _, ok := assigned[interfaceID]; !ok {
				return fmt.Errorf(
					"module expansion references interface %q not assigned to its module",
					interfaceID,
				)
			}
		}
		if err := validateExpansionChildren(node.Children, assigned); err != nil {
			return err
		}
	}
	return nil
}

func buildModuleContext(
	module Node,
	authenticationFindings *authentication.Findings,
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
	surfaceFindings *surface.Findings,
) (json.RawMessage, int, int, error) {
	interfaceSet := stringSet(module.InterfaceIDs)
	selectedInterfaces := make([]surface.Interface, 0, len(interfaceSet))
	for _, item := range surfaceFindings.Interfaces {
		if _, ok := interfaceSet[item.ID]; ok {
			selectedInterfaces = append(selectedInterfaces, item)
		}
	}
	sort.Slice(selectedInterfaces, func(i, j int) bool {
		leftRoot, rightRoot := IsRootInterface(selectedInterfaces[i]), IsRootInterface(selectedInterfaces[j])
		if leftRoot != rightRoot {
			return !leftRoot
		}
		return selectedInterfaces[i].ID < selectedInterfaces[j].ID
	})
	entityIDs := stringSet(module.EntityIDs)
	roleIDs := stringSet(module.Access.RoleIDs)
	permissionIDs := stringSet(module.Access.PermissionIDs)
	for _, item := range selectedInterfaces {
		for _, id := range item.EntityIDs {
			entityIDs[id] = struct{}{}
		}
		if item.Access != nil {
			for _, id := range item.Access.RoleIDs {
				roleIDs[id] = struct{}{}
			}
			for _, id := range item.Access.PermissionIDs {
				permissionIDs[id] = struct{}{}
			}
		}
	}
	selectedRelationships := make([]surface.Relationship, 0)
	integrationIDs := map[string]struct{}{}
	for _, relationship := range surfaceFindings.Relationships {
		_, from := interfaceSet[relationship.FromInterfaceID]
		_, to := interfaceSet[relationship.ToInterfaceID]
		if !from && !to {
			continue
		}
		selectedRelationships = append(selectedRelationships, relationship)
		if relationship.ToIntegrationID != "" {
			integrationIDs[relationship.ToIntegrationID] = struct{}{}
		}
	}
	selectedIntegrations := make([]surface.Integration, 0, len(integrationIDs))
	for _, integration := range surfaceFindings.Integrations {
		if _, ok := integrationIDs[integration.ID]; ok {
			selectedIntegrations = append(selectedIntegrations, integration)
		}
	}
	canonical := struct {
		Module        Node                   `json:"module"`
		Interfaces    []surface.Interface    `json:"interfaces"`
		Relationships []surface.Relationship `json:"relationships"`
		Integrations  []surface.Integration  `json:"integrations"`
	}{module, selectedInterfaces, selectedRelationships, selectedIntegrations}

	projected := moduleExpansionContext{
		Module: moduleContextNode(module),
		Authentication: moduleAuthenticationContext{
			Present: authenticationFindings != nil && authenticationFindings.AuthenticationPresent,
		},
		Interfaces:    make([]moduleInterfaceContext, 0, len(selectedInterfaces)),
		Relationships: make([]moduleRelationshipContext, 0, len(selectedRelationships)),
		Integrations:  make([]moduleNamedContext, 0, len(selectedIntegrations)),
	}
	if authenticationFindings != nil {
		for _, mechanism := range authenticationFindings.Mechanisms {
			projected.Authentication.Mechanisms = append(
				projected.Authentication.Mechanisms,
				moduleMechanismContext{ID: mechanism.ID, Type: mechanism.Type},
			)
		}
	}
	if entityFindings != nil {
		for _, entity := range entityFindings.Entities {
			if _, ok := entityIDs[entity.ID]; ok {
				projected.Entities = append(projected.Entities, moduleNamedContext{
					ID: entity.ID, Name: entity.Name, EvidenceID: first(entity.EvidenceIDs),
				})
			}
		}
	}
	if authorizationFindings != nil {
		for _, role := range authorizationFindings.Roles {
			if _, ok := roleIDs[role.ID]; ok {
				projected.Roles = append(projected.Roles, moduleNamedContext{
					ID: role.ID, Name: role.Name, EvidenceID: first(role.EvidenceIDs),
				})
			}
		}
		for _, permission := range authorizationFindings.Permissions {
			if _, ok := permissionIDs[permission.ID]; ok {
				projected.Permissions = append(projected.Permissions, moduleNamedContext{
					ID: permission.ID, Name: permission.Name,
					EvidenceID: first(permission.EvidenceIDs),
				})
			}
		}
	}
	for _, item := range selectedInterfaces {
		entry := moduleInterfaceContext{
			ID: item.ID, Type: item.Type, Name: item.Name,
			Locator: compactLocator(item), EntityIDs: append([]string(nil), item.EntityIDs...),
			EvidenceID: first(item.EvidenceIDs), Root: IsRootInterface(item),
		}
		if item.Access != nil {
			entry.Access = &Access{
				Authentication: item.Access.Authentication,
				RoleIDs:        append([]string(nil), item.Access.RoleIDs...),
				PermissionIDs:  append([]string(nil), item.Access.PermissionIDs...),
			}
		}
		projected.Interfaces = append(projected.Interfaces, entry)
	}
	for _, relationship := range selectedRelationships {
		projected.Relationships = append(projected.Relationships, moduleRelationshipContext{
			Type: relationship.Type, From: relationship.FromInterfaceID,
			To: relationship.ToInterfaceID, Integration: relationship.ToIntegrationID,
		})
	}
	for _, integration := range selectedIntegrations {
		projected.Integrations = append(projected.Integrations, moduleNamedContext{
			ID: integration.ID, Name: integration.Name,
		})
	}
	canonicalData, err := json.Marshal(canonical)
	if err != nil {
		return nil, 0, 0, err
	}
	projectedData, err := json.Marshal(projected)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(projectedData) > maxModuleContextBytes {
		return nil, len(canonicalData), len(projectedData), fmt.Errorf(
			"module projection is %d bytes; subdivision is required", len(projectedData),
		)
	}
	return projectedData, len(canonicalData), len(projectedData), nil
}

type moduleExpansionContext struct {
	Module         Node                        `json:"module"`
	Authentication moduleAuthenticationContext `json:"authentication"`
	Entities       []moduleNamedContext        `json:"entities"`
	Roles          []moduleNamedContext        `json:"roles"`
	Permissions    []moduleNamedContext        `json:"permissions"`
	Interfaces     []moduleInterfaceContext    `json:"interfaces"`
	Relationships  []moduleRelationshipContext `json:"relationships"`
	Integrations   []moduleNamedContext        `json:"integrations"`
}

type moduleAuthenticationContext struct {
	Present    bool                     `json:"present"`
	Mechanisms []moduleMechanismContext `json:"mechanisms,omitempty"`
}

type moduleMechanismContext struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type moduleNamedContext struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	EvidenceID string `json:"evidence_id,omitempty"`
}

type moduleInterfaceContext struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Name       string   `json:"name"`
	Locator    string   `json:"locator"`
	Access     *Access  `json:"access,omitempty"`
	EntityIDs  []string `json:"entity_ids,omitempty"`
	EvidenceID string   `json:"evidence_id,omitempty"`
	Root       bool     `json:"root,omitempty"`
}

type moduleRelationshipContext struct {
	Type        string `json:"type"`
	From        string `json:"from"`
	To          string `json:"to,omitempty"`
	Integration string `json:"integration,omitempty"`
}

func moduleContextNode(module Node) Node {
	copy := cloneNode(module)
	copy.Children = []Node{}
	copy.SourceComponents = nil
	return copy
}

func compactLocator(item surface.Interface) string {
	locator := item.Locator
	if locator.MethodName != "" {
		return locator.MethodName
	}
	return join(
		locator.Protocol, locator.Method, locator.Path, locator.Command,
		locator.Schedule, locator.Event, locator.TransportPath,
	)
}

func join(values ...string) string {
	result := values[:0]
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return strings.Join(result, " ")
}

func mergeResults(
	moduleResult *investigation.Result,
	expansions []*investigation.Result,
	findings *Findings,
) *investigation.Result {
	result := &investigation.Result{
		Status: "completed", Summary: fmt.Sprintf(
			"Discovered and expanded %d functional modules.", len(findings.Features),
		),
		Claims:     append([]investigation.Claim(nil), moduleResult.Claims...),
		Unresolved: append([]investigation.UnresolvedQuestion(nil), moduleResult.Unresolved...),
	}
	if moduleResult.Status != "completed" {
		result.Status = "partial"
	}
	for _, expansion := range expansions {
		if expansion.Status != "completed" {
			result.Status = "partial"
		}
		result.Claims = append(result.Claims, expansion.Claims...)
		result.Unresolved = append(result.Unresolved, expansion.Unresolved...)
	}
	result.Findings, _ = json.Marshal(findings)
	return result
}

func ConcreteCandidateInterfaceIDs(findings *surface.Findings) []string {
	if findings == nil {
		return []string{}
	}
	ids := make([]string, 0, len(findings.Interfaces))
	for _, item := range findings.Interfaces {
		if IsOperationCapableInterface(item) {
			ids = append(ids, item.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func IsOperationCapableInterface(item surface.Interface) bool {
	if IsRootInterface(item) {
		return false
	}
	switch item.Type {
	case "web_page", "form_action", "api_endpoint", "websocket", "cli_command",
		"scheduled_job", "worker", "event_consumer", "script":
		return true
	default:
		return false
	}
}

func assignedConcreteInterfaces(findings *Findings, surfaceFindings *surface.Findings) []string {
	candidates := stringSet(ConcreteCandidateInterfaceIDs(surfaceFindings))
	assigned := map[string]struct{}{}
	for _, module := range findings.Features {
		for _, id := range module.InterfaceIDs {
			if _, ok := candidates[id]; ok {
				assigned[id] = struct{}{}
			}
		}
	}
	return sortedSet(assigned)
}

func surfaceInterfacesByID(findings *surface.Findings) map[string]surface.Interface {
	result := map[string]surface.Interface{}
	if findings != nil {
		for _, item := range findings.Interfaces {
			result[item.ID] = item
		}
	}
	return result
}

func countActions(nodes []Node) int {
	count := 0
	for _, node := range nodes {
		if node.Type == "action" {
			count++
		}
		count += countActions(node.Children)
	}
	return count
}

func normalizeFindings(findings *Findings) {
	if findings == nil {
		return
	}
	for i := range findings.Features {
		normalizeNode(&findings.Features[i])
	}
	sort.Slice(findings.Features, func(i, j int) bool {
		return findings.Features[i].ID < findings.Features[j].ID
	})
}

func normalizeNode(node *Node) {
	node.EntityIDs = sortedUnique(node.EntityIDs)
	node.InterfaceIDs = sortedUnique(node.InterfaceIDs)
	node.Access.RoleIDs = sortedUnique(node.Access.RoleIDs)
	node.Access.PermissionIDs = sortedUnique(node.Access.PermissionIDs)
	node.EvidenceIDs = sortedUnique(node.EvidenceIDs)
	sort.Slice(node.SourceComponents, func(i, j int) bool {
		return node.SourceComponents[i].Path+"\x00"+node.SourceComponents[i].Symbol <
			node.SourceComponents[j].Path+"\x00"+node.SourceComponents[j].Symbol
	})
	for i := range node.Children {
		normalizeNode(&node.Children[i])
	}
	sort.Slice(node.Children, func(i, j int) bool {
		return node.Children[i].ID < node.Children[j].ID
	})
}

func sortedUnique(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	if len(result) < 2 {
		return result
	}
	write := 1
	for _, value := range result[1:] {
		if value != result[write-1] {
			result[write] = value
			write++
		}
	}
	return result[:write]
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func cloneNode(value Node) Node {
	raw, _ := json.Marshal(value)
	var clone Node
	_ = json.Unmarshal(raw, &clone)
	return clone
}

func cloneNodes(values []Node) []Node {
	raw, _ := json.Marshal(values)
	var clone []Node
	_ = json.Unmarshal(raw, &clone)
	return clone
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
