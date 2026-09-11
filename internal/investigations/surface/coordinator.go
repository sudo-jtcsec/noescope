package surface

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	runpkg "github.com/sudo-jtcsec/noescope/internal/run"
)

type Category string

const (
	CategoryWeb          Category = "web"
	CategoryAPI          Category = "api"
	CategoryCLI          Category = "cli"
	CategoryBackground   Category = "background"
	CategoryIntegrations Category = "integrations"
)

var categoryOrder = []Category{
	CategoryWeb,
	CategoryAPI,
	CategoryCLI,
	CategoryBackground,
	CategoryIntegrations,
}

type categoryOutput struct {
	category Category
	findings *Findings
	result   *investigation.Result
}

type categoryTaskSpec struct {
	suffix        string
	instructions  string
	candidates    []string
	includeShared bool
	depth         int
}

const maxShardDepth = 4

type taskExecutor func(context.Context, investigation.Task) (*investigation.Result, error)

// ApplicableCategories deterministically chooses bounded Surface investigations
// from validated Architecture findings. It does not inspect free-form summaries.
func ApplicableCategories(findings *architecture.Findings) []Category {
	if findings == nil {
		return nil
	}
	signals := architectureSignals(findings)
	applicable := make(map[Category]bool, len(categoryOrder))
	for _, entrypoint := range findings.Entrypoints {
		if entrypoint.Confidence <= 0 {
			continue
		}
		typeName := strings.ToLower(strings.TrimSpace(entrypoint.Type))
		switch typeName {
		case "web":
			applicable[CategoryWeb] = true
		case "api":
			applicable[CategoryAPI] = true
		case "executable", "script":
			applicable[CategoryCLI] = true
		case "worker":
			applicable[CategoryBackground] = true
		}
		value := strings.ToLower(strings.Join(
			[]string{entrypoint.Type, entrypoint.Path, entrypoint.Purpose},
			" ",
		))
		apiSignal := containsAny(
			" "+value+" ",
			" json-rpc", " jsonrpc", " api ", " graphql", " rest ",
		)
		if typeName != "api" &&
			containsAny(value, "web", "http", "front controller", "route") &&
			!apiSignal {
			applicable[CategoryWeb] = true
		}
		if apiSignal {
			applicable[CategoryAPI] = true
		}
		if containsAny(value, "cli", "console", "command", "executable") {
			applicable[CategoryCLI] = true
		}
		if containsAny(value, "worker", "queue", "job", "cron", "schedule", "consumer") {
			applicable[CategoryBackground] = true
		}
	}
	if containsAny(signals, "jsonrpc", "json-rpc", "graphql", "rest api") {
		applicable[CategoryAPI] = true
	}
	if containsAny(signals, "queue", "worker", "cron", "scheduler", "scheduled job") {
		applicable[CategoryBackground] = true
	}
	if hasPositiveTechnology(findings.Databases) ||
		hasPositiveTechnology(findings.ExternalInterfaces) || containsAny(
		signals,
		"smtp", "mailer", "ldap", "redis", "memcache", "s3", "object storage",
		"message broker", "http client", "guzzle", "curl", "external service",
	) {
		applicable[CategoryIntegrations] = true
	}

	result := make([]Category, 0, len(categoryOrder))
	for _, category := range categoryOrder {
		if applicable[category] {
			result = append(result, category)
		}
	}
	return result
}

func hasPositiveTechnology(values []architecture.Technology) bool {
	for _, value := range values {
		if value.Confidence > 0 {
			return true
		}
	}
	return false
}

func architectureSignals(findings *architecture.Findings) string {
	values := []string{findings.ArchitectureStyle.Value}
	for _, group := range [][]architecture.Technology{
		findings.Frameworks,
		findings.Libraries,
		findings.Databases,
		findings.ExternalInterfaces,
	} {
		for _, technology := range group {
			if technology.Confidence > 0 {
				values = append(values, technology.Name, technology.Role)
			}
		}
	}
	return strings.ToLower(strings.Join(values, " "))
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func taskForCategory(category Category) investigation.Task {
	return taskForCategorySpec(category, categoryTaskSpec{})
}

func taskForCategorySpec(
	category Category,
	spec categoryTaskSpec,
) investigation.Task {
	task := Task()
	task.ID = "surface." + string(category)
	if spec.suffix != "" {
		task.ID += "." + spec.suffix
	}
	task.Name = categoryName(category)
	task.Objective = categoryObjective(category)
	task.Instructions += "\n\n" + categoryInstructions(category)
	if spec.instructions != "" {
		task.Instructions += "\n\nSUBTASK BOUNDARY:\n" + spec.instructions
	}
	task.Budget = categoryBudget(category)
	return task
}

func categoryTaskSpecs(category Category, baseContext json.RawMessage) []categoryTaskSpec {
	if category != CategoryAPI {
		return []categoryTaskSpec{{}}
	}
	targets := apiEntityTargets(baseContext)
	if len(targets) == 0 {
		return []categoryTaskSpec{{
			suffix:       "all",
			instructions: `Enumerate the complete API operation registry. Include the shared API transport/root interface. Keep output compact and inspect procedure registration before implementation details.`,
		}}
	}
	groupCount := 3
	if len(targets) < groupCount {
		groupCount = len(targets)
	}
	groups := make([][]string, groupCount)
	for i, target := range targets {
		groups[i%groupCount] = append(groups[i%groupCount], target)
	}
	specs := make([]categoryTaskSpec, 0, groupCount)
	for i, group := range groups {
		specs = append(specs, apiTaskSpec(
			fmt.Sprintf("group_%d", i+1),
			group,
			i == 0,
			0,
		))
	}
	return specs
}

func apiTaskSpec(
	suffix string,
	candidates []string,
	includeShared bool,
	depth int,
) categoryTaskSpec {
	boundary := fmt.Sprintf(
		"Enumerate only API operations centered on these canonical domain entities: %s.",
		strings.Join(candidates, ", "),
	)
	if includeShared {
		boundary += ` Also include the shared API transport/root interface and application-level API operations that do not map clearly to any canonical entity.`
	} else {
		boundary += ` Do not repeat the shared API transport/root interface or unclassified application-level operations.`
	}
	boundary += ` Locate the canonical procedure registry first, then inspect only registration entries and handler files relevant to this entity group.`
	return categoryTaskSpec{
		suffix: suffix, instructions: boundary,
		candidates:    append([]string(nil), candidates...),
		includeShared: includeShared, depth: depth,
	}
}

func splitCategoryTaskSpec(spec categoryTaskSpec) (categoryTaskSpec, categoryTaskSpec) {
	middle := (len(spec.candidates) + 1) / 2
	left := apiTaskSpec(
		spec.suffix+".1",
		spec.candidates[:middle],
		spec.includeShared,
		spec.depth+1,
	)
	right := apiTaskSpec(
		spec.suffix+".2",
		spec.candidates[middle:],
		false,
		spec.depth+1,
	)
	return left, right
}

func apiEntityTargets(baseContext json.RawMessage) []string {
	var contextView struct {
		Entities []struct {
			ID      string   `json:"id"`
			Name    string   `json:"name"`
			Aliases []string `json:"aliases"`
		} `json:"entities"`
	}
	if json.Unmarshal(baseContext, &contextView) != nil {
		return nil
	}
	targets := make([]string, 0, len(contextView.Entities))
	for _, entity := range contextView.Entities {
		if entity.ID == "" {
			continue
		}
		label := entity.ID
		if entity.Name != "" && entity.Name != entity.ID {
			label += " (" + entity.Name + ")"
		}
		if len(entity.Aliases) > 0 {
			label += " aliases=" + strings.Join(entity.Aliases, "/")
		}
		targets = append(targets, label)
	}
	sort.Strings(targets)
	return targets
}

func categoryName(category Category) string {
	switch category {
	case CategoryWeb:
		return "Web Surface Investigation"
	case CategoryAPI:
		return "API Surface Investigation"
	case CategoryCLI:
		return "CLI Surface Investigation"
	case CategoryBackground:
		return "Background Surface Investigation"
	case CategoryIntegrations:
		return "Integration Investigation"
	default:
		return "Technical Surface Investigation"
	}
}

func categoryObjective(category Category) string {
	switch category {
	case CategoryWeb:
		return `Enumerate the concrete inbound web routes, pages, and form actions exposed by this application. Inspect canonical route registration first, then connect each route to its primary controller/action, intended access, and known entities. A generic front controller such as web.root may be recorded, but it is not a substitute for concrete routes. Return no API, CLI, background, or outbound integration records.`
	case CategoryAPI:
		return `Enumerate the concrete inbound API operations exposed by this application. Represent the API transport/root separately from callable operations. For JSON-RPC, enumerate procedure method names and use protocol, method_name, and transport_path locator fields instead of inventing REST routes. Return no web-page, CLI, background, or outbound integration records.`
	case CategoryCLI:
		return `Enumerate concrete externally invokable application CLI commands from command registration and command classes. A cli.root interface may be recorded, but it is not a substitute for registered subcommands. Return no web, API, background, or outbound integration records.`
	case CategoryBackground:
		return `Enumerate concrete scheduled jobs, workers, queue consumers, background jobs, and event consumers that are operationally invokable. Do not enumerate ordinary internal helpers or synchronous domain events. Return no web, API, CLI, or outbound integration records.`
	case CategoryIntegrations:
		return `Enumerate external systems and provider dependencies that the application calls or depends upon. Internal abstractions and client libraries are not integrations: for example, a database abstraction belongs in source_components while MySQL, PostgreSQL, or SQLite are the dependency providers. Return integrations and evidence-backed integration_call relationships only; do not return application interfaces or handlers.`
	default:
		return "Inventory the requested technical surface category."
	}
}

func categoryInstructions(category Category) string {
	common := `This is one bounded category in a serial Technical Surface investigation. Stay strictly within the category objective. Enumerate concrete invocation points rather than collapsing them into a generic root. Use the supplied prior Findings only as read-only context; no earlier chat transcript is present. Stop when the category's canonical registrations and primary handlers have been covered. Return all four arrays required by the schema, using empty arrays for out-of-scope record kinds.`
	switch category {
	case CategoryWeb:
		return common + ` Web page and form-action locators must include a path. Include the HTTP method whenever canonical routing or form evidence specifies it; leave method unset only when the custom router is genuinely method-agnostic. For custom routers, prioritize route providers and route registration before controller browsing. Distinguish GET display routes from POST/PUT/DELETE actions when evidence supports that distinction, even when they share a path.`
	case CategoryAPI:
		return common + ` REST operations use method/path. JSON-RPC operations use protocol "jsonrpc", method_name, and transport_path. Do not model every JSON-RPC procedure as the same api.jsonrpc transport interface. Keep each operation description to one short sentence. Prefer one canonical source component and one sufficient evidence ID per operation. Consolidate handlers by implementation class or primary dispatch boundary and let one handler reference all interfaces it handles. Do not emit redundant per-method relationships; relationships are optional and should only capture useful transport or call structure. This compactness is required so the complete procedure inventory fits in one structured result.`
	case CategoryCLI:
		return common + ` Each concrete CLI interface must have its full invokable command in locator.command and its registered command class or callback as the primary handler.`
	case CategoryBackground:
		return common + ` Each record needs a concrete schedule, command, or delivered event locator supported by source.`
	case CategoryIntegrations:
		return common + ` A package, SDK, adapter, database abstraction, or HTTP client is implementation evidence, not the external dependency itself. Name the external provider/service generically when configuration supports multiple providers. Locator must contain a non-empty value. When an endpoint is configuration-driven, use a provider-neutral locator.name such as "configured LDAP server" or locator.base_url such as "configurable via LDAP_SERVER"; never leave every locator field empty. Use external_process only when the application actually spawns an operating-system process; LDAP and SAML providers are normally type other, while outbound webhooks are http_api. Never invent a command merely to satisfy an external_process locator. Never expose credential values.`
	default:
		return common
	}
}

func categoryBudget(category Category) investigation.Budget {
	budget := investigation.Budget{
		MaxFormatRepairs:         2,
		MaxSemanticRepairs:       2,
		FinalizeTurns:            2,
		MaxDuration:              10 * time.Minute,
		MaxStructuredResultBytes: 64 * 1024,
	}
	switch category {
	case CategoryWeb:
		budget.MaxTurns, budget.MaxToolCalls = 15, 120
	case CategoryAPI:
		budget.MaxTurns, budget.MaxToolCalls = 12, 100
	case CategoryCLI, CategoryBackground, CategoryIntegrations:
		budget.MaxTurns, budget.MaxToolCalls = 10, 80
	}
	return budget
}

func runCategoryCoordinator(
	ctx context.Context,
	execute taskExecutor,
	evidence investigation.EvidenceLookup,
	logf func(string, ...any),
	baseContext json.RawMessage,
	architectureFindings *architecture.Findings,
	references priorReferences,
	options ...RunOptions,
) (*Findings, *investigation.Result, error) {
	var runOptions RunOptions
	if len(options) > 0 {
		runOptions = options[0]
	}
	checkpoints := newCheckpointStore(runOptions)
	applicable := ApplicableCategories(architectureFindings)
	applicableSet := make(map[Category]bool, len(applicable))
	for _, category := range applicable {
		applicableSet[category] = true
	}
	coverage := skippedCoverage()
	outputs := make([]categoryOutput, 0, len(applicable))
	mergedSoFar := &Findings{
		Interfaces: []Interface{}, Integrations: []Integration{},
		Handlers: []Handler{}, Relationships: []Relationship{},
	}

	for _, category := range categoryOrder {
		if category == CategoryBackground &&
			!applicableSet[category] && backgroundSupportedBySurface(mergedSoFar) {
			applicableSet[category] = true
			if logf != nil {
				logf("[surface] category background enabled by validated CLI findings")
			}
		}
		if !applicableSet[category] {
			if logf != nil {
				logf("[surface] category %s: not applicable", category)
			}
			continue
		}
		if logf != nil {
			logf("[surface] category %s: applicable", category)
		}
		categoryCoverage := CategoryCoverage{Applicable: true, Status: "completed"}
		specs := categoryTaskSpecs(category, baseContext)
		executedShards := 0
		for index, spec := range specs {
			if logf != nil {
				logf(
					"[surface.%s] group %d/%d",
					category,
					index+1,
					len(specs),
				)
			}
			completed, err := executeCategoryShard(
				ctx,
				execute,
				evidence,
				logf,
				baseContext,
				category,
				spec,
				references,
				coverage,
				checkpoints,
				&outputs,
				&mergedSoFar,
			)
			if err != nil {
				return nil, nil, fmt.Errorf("%s surface investigation: %w", category, err)
			}
			executedShards += completed
		}
		categoryCoverage.Interfaces, categoryCoverage.Integrations =
			categoryCounts(mergedSoFar, category)
		setCategoryCoverage(&coverage, category, categoryCoverage)
		mergedSoFar.Coverage = coverage
		if logf != nil {
			logf(
				"[surface] category %s complete: %d interfaces, %d integrations; merged %d logical groups / %d completed shards",
				category,
				categoryCoverage.Interfaces,
				categoryCoverage.Integrations,
				len(specs),
				executedShards,
			)
		}
	}

	merged, err := mergeCategoryFindings(outputs, coverage)
	if err != nil {
		return nil, nil, err
	}
	result := mergedResult(outputs, merged)
	if err := validateResultWithReferences(result, evidence, references); err != nil {
		return nil, result, fmt.Errorf("validate merged surface findings: %w", err)
	}
	result.Findings, err = json.Marshal(merged)
	if err != nil {
		return nil, result, fmt.Errorf("marshal merged surface findings: %w", err)
	}
	return merged, result, nil
}

func executeCategoryShard(
	ctx context.Context,
	execute taskExecutor,
	evidence investigation.EvidenceLookup,
	logf func(string, ...any),
	baseContext json.RawMessage,
	category Category,
	spec categoryTaskSpec,
	references priorReferences,
	coverage Coverage,
	checkpoints *checkpointStore,
	outputs *[]categoryOutput,
	mergedSoFar **Findings,
) (int, error) {
	task := taskForCategorySpec(category, spec)
	if checkpoints != nil && checkpoints.resume {
		if state, ok := checkpoints.state(task.ID); ok && state.Status == "split" {
			if !reflect.DeepEqual(state.Candidates, sortedStrings(spec.candidates)) {
				return 0, fmt.Errorf(
					"saved split plan for %s has an incompatible candidate set",
					task.ID,
				)
			}
			left, right := splitCategoryTaskSpec(spec)
			completedLeft, err := executeCategoryShard(
				ctx, execute, evidence, logf, baseContext, category, left,
				references, coverage, checkpoints, outputs, mergedSoFar,
			)
			if err != nil {
				return completedLeft, err
			}
			completedRight, err := executeCategoryShard(
				ctx, execute, evidence, logf, baseContext, category, right,
				references, coverage, checkpoints, outputs, mergedSoFar,
			)
			return completedLeft + completedRight, err
		}
	}

	if len(spec.candidates) > 0 && logf != nil {
		logf("[%s] %d candidates", task.ID, len(spec.candidates))
	}
	categoryContext, err := buildCategoryContext(baseContext, category, *mergedSoFar)
	if err != nil {
		return 0, fmt.Errorf("build %s surface context: %w", category, err)
	}
	task.Context = categoryContext
	categoryReferences := references.withSurface(*mergedSoFar)
	task.ValidateResult = func(
		result *investigation.Result,
		lookup investigation.EvidenceLookup,
	) error {
		if err := validateCategoryResult(result, lookup, categoryReferences, category); err != nil {
			return err
		}
		findings, err := decodeFindings(result.Findings)
		if err != nil {
			return investigation.NewSubmissionFormatError(err)
		}
		_, err = mergeCategoryFindings([]categoryOutput{
			{findings: *mergedSoFar},
			{category: category, findings: findings, result: result},
		}, coverage)
		return err
	}

	result, reused, err := checkpoints.load(task, category, spec.candidates)
	if err != nil {
		return 0, err
	}
	if reused {
		if err := task.ValidateResult(result, evidence); err != nil {
			if logf != nil {
				logf("[%s] checkpoint failed semantic revalidation; rerunning shard", task.ID)
			}
			if stateErr := checkpoints.setState(task.ID, runpkg.SurfaceShardState{
				Status: "failed", Category: string(category),
				Candidates: append([]string(nil), spec.candidates...),
				Failure:    err.Error(),
			}); stateErr != nil {
				return 0, stateErr
			}
			reused = false
		}
		if reused && logf != nil {
			logf("[%s] reused validated checkpoint", task.ID)
		}
	}
	if !reused {
		if err := checkpoints.setState(task.ID, runpkg.SurfaceShardState{
			Status: "running", Category: string(category),
			Candidates: append([]string(nil), spec.candidates...),
		}); err != nil {
			return 0, err
		}
		result, err = execute(ctx, task)
		if err != nil {
			if investigation.IsStructuredOutputSplitRequired(err) {
				return splitFailedCategoryShard(
					ctx, execute, evidence, logf, baseContext, category, spec,
					references, coverage, checkpoints, outputs, mergedSoFar, err,
				)
			}
			_ = checkpoints.setState(task.ID, runpkg.SurfaceShardState{
				Status: "failed", Category: string(category),
				Candidates: append([]string(nil), spec.candidates...),
				Failure:    err.Error(),
			})
			return 0, err
		}
	}

	findings, err := decodeFindings(result.Findings)
	if err != nil {
		return 0, fmt.Errorf("decode %s Surface findings: %w", category, err)
	}
	prospectiveOutputs := append(
		append([]categoryOutput(nil), (*outputs)...),
		categoryOutput{category, findings, result},
	)
	prospectiveMerged, err := mergeCategoryFindings(prospectiveOutputs, coverage)
	if err != nil {
		_ = checkpoints.setState(task.ID, runpkg.SurfaceShardState{
			Status: "failed", Category: string(category),
			Candidates: append([]string(nil), spec.candidates...), Failure: err.Error(),
		})
		return 0, err
	}
	if !reused {
		if err := checkpoints.save(task, category, spec.candidates, result); err != nil {
			return 0, err
		}
	}
	*outputs = prospectiveOutputs
	*mergedSoFar = prospectiveMerged
	return 1, nil
}

func splitFailedCategoryShard(
	ctx context.Context,
	execute taskExecutor,
	evidence investigation.EvidenceLookup,
	logf func(string, ...any),
	baseContext json.RawMessage,
	category Category,
	spec categoryTaskSpec,
	references priorReferences,
	coverage Coverage,
	checkpoints *checkpointStore,
	outputs *[]categoryOutput,
	mergedSoFar **Findings,
	cause error,
) (int, error) {
	taskID := taskForCategorySpec(category, spec).ID
	if len(spec.candidates) == 0 {
		_ = checkpoints.setState(taskID, runpkg.SurfaceShardState{
			Status: "failed", Category: string(category), Failure: cause.Error(),
		})
		return 0, fmt.Errorf("%s is not candidate-shardable: %w", taskID, cause)
	}
	if len(spec.candidates) == 1 {
		_ = checkpoints.setState(taskID, runpkg.SurfaceShardState{
			Status: "failed", Category: string(category),
			Candidates: append([]string(nil), spec.candidates...), Failure: cause.Error(),
		})
		return 0, fmt.Errorf(
			"%s cannot be subdivided; candidate %q still exceeds structured output bounds: %w",
			taskID,
			spec.candidates[0],
			cause,
		)
	}
	if spec.depth >= maxShardDepth {
		_ = checkpoints.setState(taskID, runpkg.SurfaceShardState{
			Status: "failed", Category: string(category),
			Candidates: append([]string(nil), spec.candidates...), Failure: cause.Error(),
		})
		return 0, fmt.Errorf(
			"%s reached maximum shard depth %d with %d candidates: %w",
			taskID,
			maxShardDepth,
			len(spec.candidates),
			cause,
		)
	}

	left, right := splitCategoryTaskSpec(spec)
	leftID := taskForCategorySpec(category, left).ID
	rightID := taskForCategorySpec(category, right).ID
	if err := checkpoints.setState(taskID, runpkg.SurfaceShardState{
		Status: "split", Category: string(category),
		Candidates: append([]string(nil), spec.candidates...),
		Children:   []string{leftID, rightID},
		Failure:    cause.Error(),
	}); err != nil {
		return 0, err
	}
	if logf != nil {
		logf(
			"[%s] structured output too large or truncated; splitting %d candidates",
			taskID,
			len(spec.candidates),
		)
	}
	completedLeft, err := executeCategoryShard(
		ctx, execute, evidence, logf, baseContext, category, left,
		references, coverage, checkpoints, outputs, mergedSoFar,
	)
	if err != nil {
		return completedLeft, err
	}
	completedRight, err := executeCategoryShard(
		ctx, execute, evidence, logf, baseContext, category, right,
		references, coverage, checkpoints, outputs, mergedSoFar,
	)
	return completedLeft + completedRight, err
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func categoryCounts(findings *Findings, category Category) (int, int) {
	if findings == nil {
		return 0, 0
	}
	if category == CategoryIntegrations {
		return 0, len(findings.Integrations)
	}
	allowed := map[Category]map[string]struct{}{
		CategoryWeb:        {"web_page": {}, "form_action": {}},
		CategoryAPI:        {"api_endpoint": {}, "websocket": {}},
		CategoryCLI:        {"cli_command": {}, "script": {}},
		CategoryBackground: {"scheduled_job": {}, "worker": {}, "event_consumer": {}},
	}
	count := 0
	for _, item := range findings.Interfaces {
		if _, ok := allowed[category][item.Type]; ok {
			count++
		}
	}
	return count, 0
}

func backgroundSupportedBySurface(findings *Findings) bool {
	if findings == nil {
		return false
	}
	for _, item := range findings.Interfaces {
		if item.Type != "cli_command" && item.Type != "script" {
			continue
		}
		value := strings.ToLower(strings.Join(
			[]string{item.ID, item.Name, item.Locator.Command},
			" ",
		))
		if containsAny(value, "worker", "queue", "cron", "background job", " cli job") {
			return true
		}
	}
	return false
}

func buildCategoryContext(
	base json.RawMessage,
	category Category,
	prior *Findings,
) (json.RawMessage, error) {
	if category != CategoryIntegrations || prior == nil || len(prior.Interfaces) == 0 {
		return append(json.RawMessage(nil), base...), nil
	}
	interfaceIDs := make([]string, 0, len(prior.Interfaces))
	for _, item := range prior.Interfaces {
		interfaceIDs = append(interfaceIDs, item.ID)
	}
	sort.Strings(interfaceIDs)
	contextView := struct {
		PriorFindings json.RawMessage `json:"prior_findings"`
		PriorSurface  struct {
			InterfaceIDs []string `json:"interface_ids"`
		} `json:"prior_surface"`
	}{PriorFindings: append(json.RawMessage(nil), base...)}
	contextView.PriorSurface.InterfaceIDs = interfaceIDs
	return json.Marshal(contextView)
}

func skippedCoverage() Coverage {
	skipped := CategoryCoverage{Status: "skipped"}
	return Coverage{
		Web: skipped, API: skipped, CLI: skipped,
		Background: skipped, Integrations: skipped,
	}
}

func setCategoryCoverage(coverage *Coverage, category Category, value CategoryCoverage) {
	switch category {
	case CategoryWeb:
		coverage.Web = value
	case CategoryAPI:
		coverage.API = value
	case CategoryCLI:
		coverage.CLI = value
	case CategoryBackground:
		coverage.Background = value
	case CategoryIntegrations:
		coverage.Integrations = value
	}
}

func validateCategoryResult(
	result *investigation.Result,
	evidence investigation.EvidenceLookup,
	references priorReferences,
	category Category,
) error {
	decoded, err := decodeFindings(result.Findings)
	if err != nil {
		return investigation.NewSubmissionFormatError(err)
	}
	normalized, err := mergeCategoryFindings(
		[]categoryOutput{{category: category, findings: decoded, result: result}},
		Coverage{},
	)
	if err != nil {
		return err
	}
	result.Findings, err = json.Marshal(normalized)
	if err != nil {
		return investigation.NewSubmissionFormatError(
			fmt.Errorf("marshal normalized %s findings: %w", category, err),
		)
	}
	if err := validateResultWithReferences(result, evidence, references); err != nil {
		return err
	}
	findings := normalized
	allowed := map[Category]map[string]struct{}{
		CategoryWeb:        {"web_page": {}, "form_action": {}},
		CategoryAPI:        {"api_endpoint": {}, "websocket": {}},
		CategoryCLI:        {"cli_command": {}, "script": {}},
		CategoryBackground: {"scheduled_job": {}, "worker": {}, "event_consumer": {}},
	}
	if category == CategoryIntegrations {
		if len(findings.Interfaces) > 0 || len(findings.Handlers) > 0 {
			return fmt.Errorf("integrations category must not return interfaces or handlers")
		}
		for _, relationship := range findings.Relationships {
			if relationship.Type != "integration_call" {
				return fmt.Errorf("integrations category relationship must be integration_call")
			}
		}
		return nil
	}
	if len(findings.Integrations) > 0 {
		return fmt.Errorf("%s category must not return integrations", category)
	}
	for i, item := range findings.Interfaces {
		if _, ok := allowed[category][item.Type]; !ok {
			return fmt.Errorf(
				"%s category interfaces[%d] has out-of-scope type %q",
				category,
				i,
				item.Type,
			)
		}
	}
	for _, relationship := range findings.Relationships {
		if relationship.Type == "integration_call" {
			return fmt.Errorf("%s category must not return integration calls", category)
		}
	}
	return nil
}

func mergeCategoryFindings(outputs []categoryOutput, coverage Coverage) (*Findings, error) {
	merged := &Findings{
		Interfaces: []Interface{}, Integrations: []Integration{},
		Handlers: []Handler{}, Relationships: []Relationship{}, Coverage: coverage,
	}
	interfaces := map[string]Interface{}
	integrations := map[string]Integration{}
	handlers := map[string]Handler{}
	relationships := map[string]Relationship{}
	for _, output := range outputs {
		for _, item := range output.findings.Interfaces {
			normalizeInterface(&item)
			if previous, exists := interfaces[item.ID]; exists {
				combined, err := mergeInterface(previous, item)
				if err != nil {
					return nil, fmt.Errorf(
						"conflicting duplicate interface ID %q: %w",
						item.ID,
						err,
					)
				}
				interfaces[item.ID] = combined
				continue
			}
			interfaces[item.ID] = item
		}
		for _, item := range output.findings.Integrations {
			normalizeIntegration(&item)
			if previous, exists := integrations[item.ID]; exists {
				combined, err := mergeIntegration(previous, item)
				if err != nil {
					return nil, fmt.Errorf(
						"conflicting duplicate integration ID %q: %w",
						item.ID,
						err,
					)
				}
				integrations[item.ID] = combined
				continue
			}
			integrations[item.ID] = item
		}
		for _, item := range output.findings.Handlers {
			normalizeHandler(&item)
			if previous, exists := handlers[item.ID]; exists {
				combined, err := mergeHandler(previous, item)
				if err != nil {
					return nil, fmt.Errorf(
						"conflicting duplicate handler ID %q: %w",
						item.ID,
						err,
					)
				}
				handlers[item.ID] = combined
				continue
			}
			handlers[item.ID] = item
		}
		for _, item := range output.findings.Relationships {
			normalizeRelationship(&item)
			key := relationshipIdentityKey(item)
			if previous, exists := relationships[key]; exists {
				relationships[key] = mergeRelationship(previous, item)
				continue
			}
			relationships[key] = item
		}
	}
	for _, item := range interfaces {
		merged.Interfaces = append(merged.Interfaces, item)
	}
	for _, item := range integrations {
		merged.Integrations = append(merged.Integrations, item)
	}
	for _, item := range handlers {
		merged.Handlers = append(merged.Handlers, item)
	}
	for _, item := range relationships {
		merged.Relationships = append(merged.Relationships, item)
	}
	sort.Slice(merged.Interfaces, func(i, j int) bool { return merged.Interfaces[i].ID < merged.Interfaces[j].ID })
	sort.Slice(merged.Integrations, func(i, j int) bool { return merged.Integrations[i].ID < merged.Integrations[j].ID })
	sort.Slice(merged.Handlers, func(i, j int) bool { return merged.Handlers[i].ID < merged.Handlers[j].ID })
	sort.Slice(merged.Relationships, func(i, j int) bool {
		return relationshipIdentityKey(merged.Relationships[i]) <
			relationshipIdentityKey(merged.Relationships[j])
	})
	return merged, nil
}

func mergeInterface(left, right Interface) (Interface, error) {
	if left.Type != right.Type {
		return Interface{}, fmt.Errorf("types differ: %q and %q", left.Type, right.Type)
	}
	locator, err := mergeInterfaceLocator(left.Locator, right.Locator)
	if err != nil {
		return Interface{}, err
	}
	access, err := mergeAccess(left.Access, right.Access)
	if err != nil {
		return Interface{}, err
	}
	merged := Interface{
		ID:               left.ID,
		Type:             left.Type,
		Name:             preferredLabel(left.Name, right.Name),
		Description:      mergeDescriptions(left.Description, right.Description),
		Locator:          locator,
		Access:           access,
		InputNames:       unionStrings(left.InputNames, right.InputNames),
		EntityIDs:        unionStrings(left.EntityIDs, right.EntityIDs),
		SourceComponents: unionSourceComponents(left.SourceComponents, right.SourceComponents),
		Confidence:       max(left.Confidence, right.Confidence),
		EvidenceIDs:      unionStrings(left.EvidenceIDs, right.EvidenceIDs),
	}
	normalizeInterface(&merged)
	return merged, nil
}

func mergeInterfaceLocator(left, right InterfaceLocator) (InterfaceLocator, error) {
	merged := left
	fields := []struct {
		name        string
		left, right string
		target      *string
	}{
		{"path", left.Path, right.Path, &merged.Path},
		{"method", left.Method, right.Method, &merged.Method},
		{"command", left.Command, right.Command, &merged.Command},
		{"schedule", left.Schedule, right.Schedule, &merged.Schedule},
		{"event", left.Event, right.Event, &merged.Event},
		{"protocol", left.Protocol, right.Protocol, &merged.Protocol},
		{"method_name", left.MethodName, right.MethodName, &merged.MethodName},
		{"transport_path", left.TransportPath, right.TransportPath, &merged.TransportPath},
	}
	for _, field := range fields {
		value, err := mergeIdentityString("locator."+field.name, field.left, field.right)
		if err != nil {
			return InterfaceLocator{}, err
		}
		*field.target = value
	}
	return merged, nil
}

func mergeAccess(left, right *Access) (*Access, error) {
	if left == nil {
		return cloneAccess(right), nil
	}
	if right == nil {
		return cloneAccess(left), nil
	}
	authentication := left.Authentication
	switch {
	case authentication == right.Authentication:
	case authentication == "unknown":
		authentication = right.Authentication
	case right.Authentication == "unknown":
	default:
		return nil, fmt.Errorf(
			"access authentication differs: %q and %q",
			left.Authentication,
			right.Authentication,
		)
	}
	return &Access{
		Authentication: authentication,
		RoleIDs:        unionStrings(left.RoleIDs, right.RoleIDs),
		PermissionIDs:  unionStrings(left.PermissionIDs, right.PermissionIDs),
		Confidence:     max(left.Confidence, right.Confidence),
		EvidenceIDs:    unionStrings(left.EvidenceIDs, right.EvidenceIDs),
	}, nil
}

func cloneAccess(value *Access) *Access {
	if value == nil {
		return nil
	}
	copy := *value
	copy.RoleIDs = unionStrings(value.RoleIDs, nil)
	copy.PermissionIDs = unionStrings(value.PermissionIDs, nil)
	copy.EvidenceIDs = unionStrings(value.EvidenceIDs, nil)
	return &copy
}

func mergeIntegration(left, right Integration) (Integration, error) {
	if left.Type != right.Type {
		return Integration{}, fmt.Errorf("types differ: %q and %q", left.Type, right.Type)
	}
	locator, err := mergeIntegrationLocator(left.Locator, right.Locator)
	if err != nil {
		return Integration{}, err
	}
	authentication, err := mergeIntegrationAuthentication(
		left.Authentication,
		right.Authentication,
	)
	if err != nil {
		return Integration{}, err
	}
	merged := Integration{
		ID:               left.ID,
		Type:             left.Type,
		Name:             preferredLabel(left.Name, right.Name),
		Description:      mergeDescriptions(left.Description, right.Description),
		Locator:          locator,
		Authentication:   authentication,
		EntityIDs:        unionStrings(left.EntityIDs, right.EntityIDs),
		SourceComponents: unionSourceComponents(left.SourceComponents, right.SourceComponents),
		Confidence:       max(left.Confidence, right.Confidence),
		EvidenceIDs:      unionStrings(left.EvidenceIDs, right.EvidenceIDs),
	}
	normalizeIntegration(&merged)
	return merged, nil
}

func mergeIntegrationLocator(left, right IntegrationLocator) (IntegrationLocator, error) {
	merged := left
	fields := []struct {
		name        string
		left, right string
		target      *string
	}{
		{"base_url", left.BaseURL, right.BaseURL, &merged.BaseURL},
		{"path", left.Path, right.Path, &merged.Path},
		{"method", left.Method, right.Method, &merged.Method},
		{"name", left.Name, right.Name, &merged.Name},
		{"command", left.Command, right.Command, &merged.Command},
	}
	for _, field := range fields {
		value, err := mergeIdentityString("locator."+field.name, field.left, field.right)
		if err != nil {
			return IntegrationLocator{}, err
		}
		*field.target = value
	}
	return merged, nil
}

func mergeIntegrationAuthentication(
	left, right IntegrationAuthentication,
) (IntegrationAuthentication, error) {
	authenticationType := left.Type
	switch {
	case authenticationType == right.Type:
	case authenticationType == "unknown":
		authenticationType = right.Type
	case right.Type == "unknown":
	default:
		return IntegrationAuthentication{}, fmt.Errorf(
			"integration authentication differs: %q and %q",
			left.Type,
			right.Type,
		)
	}
	credentialSource, err := mergeIdentityString(
		"authentication.credential_source",
		left.CredentialSource,
		right.CredentialSource,
	)
	if err != nil {
		return IntegrationAuthentication{}, err
	}
	return IntegrationAuthentication{
		Type: authenticationType, CredentialSource: credentialSource,
	}, nil
}

func mergeHandler(left, right Handler) (Handler, error) {
	if left.Type != right.Type {
		return Handler{}, fmt.Errorf("types differ: %q and %q", left.Type, right.Type)
	}
	path, err := mergeIdentityString("path", left.Path, right.Path)
	if err != nil {
		return Handler{}, err
	}
	symbol, err := mergeHandlerSymbol(left.Symbol, right.Symbol)
	if err != nil {
		return Handler{}, err
	}
	merged := Handler{
		ID:           left.ID,
		Type:         left.Type,
		Name:         preferredLabel(left.Name, right.Name),
		Path:         path,
		Symbol:       symbol,
		InterfaceIDs: unionStrings(left.InterfaceIDs, right.InterfaceIDs),
		Confidence:   max(left.Confidence, right.Confidence),
		EvidenceIDs:  unionStrings(left.EvidenceIDs, right.EvidenceIDs),
	}
	normalizeHandler(&merged)
	return merged, nil
}

func mergeHandlerSymbol(left, right string) (string, error) {
	switch {
	case left == "":
		return right, nil
	case right == "", left == right:
		return left, nil
	case strings.HasSuffix(left, `\`+right):
		return left, nil
	case strings.HasSuffix(right, `\`+left):
		return right, nil
	default:
		return "", fmt.Errorf("symbol differs: %q and %q", left, right)
	}
}

func mergeIdentityString(field, left, right string) (string, error) {
	switch {
	case left == "":
		return right, nil
	case right == "", left == right:
		return left, nil
	default:
		return "", fmt.Errorf("%s differs: %q and %q", field, left, right)
	}
}

func preferredLabel(left, right string) string {
	if len(left) != len(right) {
		if len(left) > len(right) {
			return left
		}
		return right
	}
	if left <= right {
		return left
	}
	return right
}

func mergeDescriptions(values ...string) string {
	unique := map[string]struct{}{}
	for _, value := range values {
		for _, paragraph := range strings.Split(value, "\n\n") {
			paragraph = strings.TrimSpace(paragraph)
			if paragraph != "" {
				unique[paragraph] = struct{}{}
			}
		}
	}
	descriptions := make([]string, 0, len(unique))
	for value := range unique {
		descriptions = append(descriptions, value)
	}
	sort.Strings(descriptions)
	return strings.Join(descriptions, "\n\n")
}

func unionStrings(left, right []string) []string {
	values := append(append([]string(nil), left...), right...)
	sort.Strings(values)
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func unionSourceComponents(left, right []SourceComponent) []SourceComponent {
	byKey := make(map[string]SourceComponent, len(left)+len(right))
	for _, value := range append(append([]SourceComponent(nil), left...), right...) {
		byKey[value.Path+"\x00"+value.Symbol] = value
	}
	result := make([]SourceComponent, 0, len(byKey))
	for _, value := range byKey {
		result = append(result, value)
	}
	sortSourceComponents(result)
	return result
}

func normalizeInterface(item *Interface) {
	item.InputNames = append([]string(nil), item.InputNames...)
	item.EntityIDs = append([]string(nil), item.EntityIDs...)
	item.EvidenceIDs = append([]string(nil), item.EvidenceIDs...)
	item.SourceComponents = append([]SourceComponent(nil), item.SourceComponents...)
	sort.Strings(item.InputNames)
	sort.Strings(item.EntityIDs)
	sort.Strings(item.EvidenceIDs)
	sortSourceComponents(item.SourceComponents)
	if item.Access != nil {
		access := *item.Access
		access.RoleIDs = append([]string(nil), access.RoleIDs...)
		access.PermissionIDs = append([]string(nil), access.PermissionIDs...)
		access.EvidenceIDs = append([]string(nil), access.EvidenceIDs...)
		item.Access = &access
		sort.Strings(item.Access.RoleIDs)
		sort.Strings(item.Access.PermissionIDs)
		sort.Strings(item.Access.EvidenceIDs)
	}
}

func normalizeIntegration(item *Integration) {
	item.EntityIDs = append([]string(nil), item.EntityIDs...)
	item.EvidenceIDs = append([]string(nil), item.EvidenceIDs...)
	item.SourceComponents = append([]SourceComponent(nil), item.SourceComponents...)
	sort.Strings(item.EntityIDs)
	sort.Strings(item.EvidenceIDs)
	sortSourceComponents(item.SourceComponents)
}

func normalizeHandler(item *Handler) {
	item.InterfaceIDs = append([]string(nil), item.InterfaceIDs...)
	item.EvidenceIDs = append([]string(nil), item.EvidenceIDs...)
	sort.Strings(item.InterfaceIDs)
	sort.Strings(item.EvidenceIDs)
}

func sortSourceComponents(values []SourceComponent) {
	sort.Slice(values, func(i, j int) bool {
		return values[i].Path+"\x00"+values[i].Symbol < values[j].Path+"\x00"+values[j].Symbol
	})
}

func normalizeRelationship(value *Relationship) {
	value.EvidenceIDs = unionStrings(value.EvidenceIDs, nil)
}

func mergeRelationship(left, right Relationship) Relationship {
	return Relationship{
		Type:            left.Type,
		FromInterfaceID: left.FromInterfaceID,
		ToInterfaceID:   left.ToInterfaceID,
		ToIntegrationID: left.ToIntegrationID,
		Description:     mergeDescriptions(left.Description, right.Description),
		Confidence:      max(left.Confidence, right.Confidence),
		EvidenceIDs:     unionStrings(left.EvidenceIDs, right.EvidenceIDs),
	}
}

func relationshipIdentityKey(value Relationship) string {
	return strings.Join([]string{
		value.Type, value.FromInterfaceID, value.ToInterfaceID,
		value.ToIntegrationID,
	}, "\x00")
}

func mergedResult(outputs []categoryOutput, findings *Findings) *investigation.Result {
	status := "completed"
	claims := []investigation.Claim{}
	unresolved := []investigation.UnresolvedQuestion{}
	for _, output := range outputs {
		if output.result.Status != "completed" {
			status = "partial"
		}
		claims = append(claims, output.result.Claims...)
		for _, question := range output.result.Unresolved {
			copy := question
			copy.Question = string(output.category) + ": " + question.Question
			unresolved = append(unresolved, copy)
		}
	}
	raw, _ := json.Marshal(findings)
	return &investigation.Result{
		Status: status,
		Summary: fmt.Sprintf(
			"Completed %d applicable Technical Surface categories; discovered %d interfaces and %d integrations.",
			applicableCoverageCount(findings.Coverage), len(findings.Interfaces), len(findings.Integrations),
		),
		Findings: raw, Claims: claims, Unresolved: unresolved,
	}
}

func applicableCoverageCount(coverage Coverage) int {
	count := 0
	for _, item := range []CategoryCoverage{
		coverage.Web, coverage.API, coverage.CLI,
		coverage.Background, coverage.Integrations,
	} {
		if item.Applicable {
			count++
		}
	}
	return count
}
