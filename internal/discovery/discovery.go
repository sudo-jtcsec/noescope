package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
	runpkg "github.com/sudo-jtcsec/noescope/internal/run"
)

type Options struct {
	Resume        bool
	RerunFeatures bool
	Manifest      *runpkg.Run
}

func Run(
	ctx context.Context,
	runner *investigation.Runner,
	runRoot string,
	out io.Writer,
	metadata model.Metadata,
) error {
	return RunThrough(ctx, runner, runRoot, out, StageFeatures, metadata)
}

func RunThrough(
	ctx context.Context,
	runner *investigation.Runner,
	runRoot string,
	out io.Writer,
	through Stage,
	metadata model.Metadata,
	options ...Options,
) error {
	var runOptions Options
	if len(options) > 0 {
		runOptions = options[0]
	}
	if runOptions.Resume {
		return resumeThrough(
			ctx, runner, runRoot, out, through, metadata, runOptions.Manifest,
			runOptions.RerunFeatures,
		)
	}
	if out == nil {
		out = io.Discard
	}
	totalStages := through.Count()
	if totalStages == 0 {
		return fmt.Errorf("invalid discovery through stage %q", through)
	}

	fmt.Fprintf(out, "[1/%d] Architecture Discovery\n", totalStages)
	fmt.Fprintln(out, "[architecture] prior context: 0 bytes")

	architectureFindings, architectureResult, err := architecture.Run(
		ctx,
		runner,
	)
	if err != nil {
		return fmt.Errorf("architecture discovery: %w", err)
	}

	architecturePath := outputPath(runRoot, "architecture.json")
	if err := writeResult(
		architecturePath,
		architectureResult,
		architectureFindings,
	); err != nil {
		return err
	}
	if err := markStageCompleted(runOptions.Manifest, StageArchitecture); err != nil {
		return err
	}
	printCompletion(
		out,
		"Architecture discovery",
		architectureResult.Summary,
		architecturePath,
	)
	if through == StageArchitecture {
		return nil
	}

	authenticationContext, err := buildAuthenticationContext(
		architectureFindings,
	)
	if err != nil {
		return fmt.Errorf("marshal authentication context: %w", err)
	}

	fmt.Fprintf(out, "\n[2/%d] Authentication Discovery\n", totalStages)
	logContextProjection(out, "authentication", authenticationContext)

	authenticationFindings, authenticationResult, err := authentication.Run(
		ctx,
		runner,
		authenticationContext.Data,
	)
	if err != nil {
		return fmt.Errorf("authentication discovery: %w", err)
	}

	authenticationPath := outputPath(runRoot, "authentication.json")
	if err := writeResult(
		authenticationPath,
		authenticationResult,
		authenticationFindings,
	); err != nil {
		return err
	}
	if err := markStageCompleted(runOptions.Manifest, StageAuthentication); err != nil {
		return err
	}
	printCompletion(
		out,
		"Authentication discovery",
		authenticationResult.Summary,
		authenticationPath,
	)
	if through == StageAuthentication {
		return nil
	}

	authorizationContext, err := buildAuthorizationContext(
		architectureFindings,
		authenticationFindings,
	)
	if err != nil {
		return fmt.Errorf("marshal authorization context: %w", err)
	}

	fmt.Fprintf(out, "\n[3/%d] Authorization Discovery\n", totalStages)
	logContextProjection(out, "authorization", authorizationContext)

	authorizationFindings, authorizationResult, err := authorization.Run(
		ctx,
		runner,
		authorizationContext.Data,
	)
	if err != nil {
		return fmt.Errorf("authorization discovery: %w", err)
	}

	authorizationPath := outputPath(runRoot, "authorization.json")
	if err := writeResult(
		authorizationPath,
		authorizationResult,
		authorizationFindings,
	); err != nil {
		return err
	}
	if err := markStageCompleted(runOptions.Manifest, StageAuthorization); err != nil {
		return err
	}
	printCompletion(
		out,
		"Authorization discovery",
		authorizationResult.Summary,
		authorizationPath,
	)
	if through == StageAuthorization {
		return nil
	}

	entitiesContext, err := buildEntitiesContext(
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
	)
	if err != nil {
		return fmt.Errorf("marshal entity context: %w", err)
	}

	fmt.Fprintf(out, "\n[4/%d] Domain Entity Discovery\n", totalStages)
	logContextProjection(out, "entities", entitiesContext)

	entityFindings, entityResult, err := entities.Run(
		ctx,
		runner,
		entitiesContext.Data,
	)
	if err != nil {
		return fmt.Errorf("domain entity discovery: %w", err)
	}

	entitiesPath := outputPath(runRoot, "entities.json")
	if err := writeResult(
		entitiesPath,
		entityResult,
		entityFindings,
	); err != nil {
		return err
	}
	if err := markStageCompleted(runOptions.Manifest, StageEntities); err != nil {
		return err
	}

	fmt.Fprintf(
		out,
		"\nDomain entity discovery complete.\nDiscovered %d domain entities.\n\nWritten to:\n%s\n",
		len(entityFindings.Entities),
		entitiesPath,
	)
	if through == StageEntities {
		return nil
	}

	surfaceContext, err := buildSurfaceContext(
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
		entityFindings,
	)
	if err != nil {
		return fmt.Errorf("marshal technical surface context: %w", err)
	}

	fmt.Fprintf(out, "\n[5/%d] Technical Surface Discovery\n", totalStages)
	logContextProjection(out, "surface", surfaceContext)

	surfaceFindings, surfaceResult, err := surface.RunWithOptions(
		ctx,
		runner,
		surfaceContext.Data,
		architectureFindings,
		authorizationFindings,
		entityFindings,
		surface.RunOptions{
			RunRoot: runRoot, RepositoryCommit: metadata.Source.GitCommit,
			Manifest: runOptions.Manifest,
		},
	)
	if err != nil {
		return fmt.Errorf("technical surface discovery: %w", err)
	}

	surfacePath := outputPath(runRoot, "surface.json")
	if err := writeResult(
		surfacePath,
		surfaceResult,
		surfaceFindings,
	); err != nil {
		return err
	}
	if err := markStageCompleted(runOptions.Manifest, StageSurface); err != nil {
		return err
	}

	fmt.Fprintf(
		out,
		"\nTechnical surface discovery complete.\nDiscovered %d interfaces.\n\nWritten to:\n%s\n",
		len(surfaceFindings.Interfaces),
		surfacePath,
	)
	if through == StageSurface {
		return nil
	}

	featureContext, err := buildFeatureContext(
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
		entityFindings,
		surfaceFindings,
	)
	if err != nil {
		return fmt.Errorf("marshal feature context: %w", err)
	}

	fmt.Fprintf(out, "\n[6/%d] Feature Discovery\n", totalStages)
	logContextProjection(out, "features", featureContext)

	featureFindings, featureResult, err := features.RunWithOptions(
		ctx,
		runner,
		featureContext.Data,
		authenticationFindings,
		authorizationFindings,
		entityFindings,
		surfaceFindings,
		features.RunOptions{
			RunRoot: runRoot, RepositoryCommit: metadata.Source.GitCommit,
			FeatureAttempt: featureAttempt(runOptions.Manifest),
		},
	)
	if err != nil {
		return fmt.Errorf("feature discovery: %w", err)
	}
	logFeatureInterfaceMappings(out, featureFindings, surfaceFindings)

	featuresPath := outputPath(runRoot, "features.json")
	if err := writeResult(
		featuresPath,
		featureResult,
		featureFindings,
	); err != nil {
		return err
	}
	if err := markStageCompleted(runOptions.Manifest, StageFeatures); err != nil {
		return err
	}
	topLevelModules, totalNodes := features.Counts(featureFindings)
	fmt.Fprintf(
		out,
		"\nFeature discovery complete.\nDiscovered %d top-level modules, %d total feature nodes.\n\nWritten to:\n%s\n",
		topLevelModules,
		totalNodes,
		featuresPath,
	)

	applicationPath, markdownPath, written, err := writeApplicationArtifactsForStage(
		through,
		runRoot,
		metadata,
		completedFindings{
			architecture:   architectureFindings,
			authentication: authenticationFindings,
			authorization:  authorizationFindings,
			entities:       entityFindings,
			surface:        surfaceFindings,
			features:       featureFindings,
		},
		completedResults{
			architecture:   architectureResult,
			authentication: authenticationResult,
			authorization:  authorizationResult,
			entities:       entityResult,
			surface:        surfaceResult,
			features:       featureResult,
		},
	)
	if err != nil {
		return err
	}
	if !written {
		return nil
	}
	fmt.Fprintf(
		out,
		"\nApplication model written to:\n%s\n\nApplication documentation written to:\n%s\n",
		applicationPath,
		markdownPath,
	)

	return nil
}

func resumeThrough(
	ctx context.Context,
	runner *investigation.Runner,
	runRoot string,
	out io.Writer,
	through Stage,
	metadata model.Metadata,
	manifest *runpkg.Run,
	rerunFeatures bool,
) error {
	if out == nil {
		out = io.Discard
	}
	if manifest == nil {
		return fmt.Errorf("resume requires a run manifest")
	}
	if through.Count() < StageSurface.Count() {
		return fmt.Errorf("run %q has no resumable Surface stage", manifest.ID)
	}
	for _, stage := range []Stage{
		StageArchitecture,
		StageAuthentication,
		StageAuthorization,
		StageEntities,
	} {
		if !manifest.StageCompleted(string(stage)) {
			return fmt.Errorf(
				"run %q cannot resume Surface: prerequisite stage %s is incomplete",
				manifest.ID,
				stage,
			)
		}
	}

	architectureFindings, architectureResult, err :=
		loadStageOutput[architecture.Findings](outputPath(runRoot, "architecture.json"))
	if err != nil {
		return err
	}
	if err := architecture.Task().ValidateResult(architectureResult, runner.Evidence); err != nil {
		return fmt.Errorf("revalidate completed architecture output: %w", err)
	}
	authenticationFindings, authenticationResult, err :=
		loadStageOutput[authentication.Findings](outputPath(runRoot, "authentication.json"))
	if err != nil {
		return err
	}
	if err := authentication.Task().ValidateResult(authenticationResult, runner.Evidence); err != nil {
		return fmt.Errorf("revalidate completed authentication output: %w", err)
	}
	authorizationFindings, authorizationResult, err :=
		loadStageOutput[authorization.Findings](outputPath(runRoot, "authorization.json"))
	if err != nil {
		return err
	}
	if err := authorization.Task().ValidateResult(authorizationResult, runner.Evidence); err != nil {
		return fmt.Errorf("revalidate completed authorization output: %w", err)
	}
	entityFindings, entityResult, err :=
		loadStageOutput[entities.Findings](outputPath(runRoot, "entities.json"))
	if err != nil {
		return err
	}
	if err := entities.Task().ValidateResult(entityResult, runner.Evidence); err != nil {
		return fmt.Errorf("revalidate completed entities output: %w", err)
	}
	for _, stage := range []Stage{
		StageArchitecture,
		StageAuthentication,
		StageAuthorization,
		StageEntities,
	} {
		fmt.Fprintf(out, "[%s] reused validated canonical stage output\n", stage)
	}

	var surfaceFindings *surface.Findings
	var surfaceResult *investigation.Result
	if manifest.StageCompleted(string(StageSurface)) {
		surfaceFindings, surfaceResult, err =
			loadStageOutput[surface.Findings](outputPath(runRoot, "surface.json"))
		if err != nil {
			return err
		}
		if err := surface.ValidateCanonicalResult(
			surfaceResult,
			runner.Evidence,
			architectureFindings,
			authorizationFindings,
			entityFindings,
		); err != nil {
			return fmt.Errorf("revalidate completed canonical Surface output: %w", err)
		}
		fmt.Fprintln(out, "[surface] reused validated canonical stage output")
	} else {
		surfaceContext, err := buildSurfaceContext(
			architectureFindings,
			authenticationFindings,
			authorizationFindings,
			entityFindings,
		)
		if err != nil {
			return fmt.Errorf("marshal technical surface context: %w", err)
		}
		fmt.Fprintf(out, "\n[5/%d] Technical Surface Discovery (resume)\n", through.Count())
		logContextProjection(out, "surface", surfaceContext)
		surfaceFindings, surfaceResult, err = surface.RunWithOptions(
			ctx,
			runner,
			surfaceContext.Data,
			architectureFindings,
			authorizationFindings,
			entityFindings,
			surface.RunOptions{
				RunRoot: runRoot, RepositoryCommit: metadata.Source.GitCommit,
				Resume: true, Manifest: manifest,
			},
		)
		if err != nil {
			return fmt.Errorf("technical surface discovery: %w", err)
		}
		surfacePath := outputPath(runRoot, "surface.json")
		if err := writeResult(surfacePath, surfaceResult, surfaceFindings); err != nil {
			return err
		}
		if err := manifest.MarkStageCompleted(string(StageSurface)); err != nil {
			return err
		}
		fmt.Fprintf(
			out,
			"\nTechnical surface discovery complete.\nDiscovered %d interfaces.\n\nWritten to:\n%s\n",
			len(surfaceFindings.Interfaces),
			surfacePath,
		)
	}
	if through == StageSurface {
		return nil
	}
	if rerunFeatures && manifest.StageCompleted(string(StageFeatures)) {
		if err := manifest.BeginFeatureRerun(); err != nil {
			return err
		}
		fmt.Fprintln(out, "[features] invalidated completed terminal stage for rerun")
	}

	var featureFindings *features.Findings
	var featureResult *investigation.Result
	if manifest.StageCompleted(string(StageFeatures)) {
		featureFindings, featureResult, err =
			loadStageOutput[features.Findings](outputPath(runRoot, "features.json"))
		if err != nil {
			return err
		}
		if err := features.ValidateCanonicalResult(
			featureResult,
			runner.Evidence,
			authorizationFindings,
			entityFindings,
			surfaceFindings,
		); err != nil {
			return fmt.Errorf("revalidate completed canonical Feature output: %w", err)
		}
		fmt.Fprintln(out, "[features] reused validated canonical stage output")
	} else {
		featureContext, err := buildFeatureContext(
			architectureFindings,
			authenticationFindings,
			authorizationFindings,
			entityFindings,
			surfaceFindings,
		)
		if err != nil {
			return fmt.Errorf("marshal feature context: %w", err)
		}
		fmt.Fprintf(out, "\n[6/%d] Feature Discovery\n", through.Count())
		logContextProjection(out, "features", featureContext)
		featureFindings, featureResult, err = features.RunWithOptions(
			ctx,
			runner,
			featureContext.Data,
			authenticationFindings,
			authorizationFindings,
			entityFindings,
			surfaceFindings,
			features.RunOptions{
				RunRoot: runRoot, RepositoryCommit: metadata.Source.GitCommit,
				Resume: true, FeatureAttempt: manifest.FeatureAttempt,
			},
		)
		if err != nil {
			return fmt.Errorf("feature discovery: %w", err)
		}
		featuresPath := outputPath(runRoot, "features.json")
		if err := writeResult(featuresPath, featureResult, featureFindings); err != nil {
			return err
		}
		if err := manifest.MarkStageCompleted(string(StageFeatures)); err != nil {
			return err
		}
	}
	logFeatureInterfaceMappings(out, featureFindings, surfaceFindings)
	topLevelModules, totalNodes := features.Counts(featureFindings)
	fmt.Fprintf(
		out,
		"\nFeature discovery complete.\nDiscovered %d top-level modules, %d total feature nodes.\n\nWritten to:\n%s\n",
		topLevelModules,
		totalNodes,
		outputPath(runRoot, "features.json"),
	)

	applicationPath, markdownPath, written, err := writeApplicationArtifactsForStage(
		through,
		runRoot,
		metadata,
		completedFindings{
			architecture: architectureFindings, authentication: authenticationFindings,
			authorization: authorizationFindings, entities: entityFindings,
			surface: surfaceFindings, features: featureFindings,
		},
		completedResults{
			architecture: architectureResult, authentication: authenticationResult,
			authorization: authorizationResult, entities: entityResult,
			surface: surfaceResult, features: featureResult,
		},
	)
	if err != nil {
		return err
	}
	if written {
		fmt.Fprintf(
			out,
			"\nApplication model written to:\n%s\n\nApplication documentation written to:\n%s\n",
			applicationPath,
			markdownPath,
		)
	}
	return nil
}

func logFeatureInterfaceMappings(
	out io.Writer,
	featureFindings *features.Findings,
	surfaceFindings *surface.Findings,
) {
	counts := features.CountInterfaceMappings(featureFindings, surfaceFindings)
	coverage := features.CountConcreteInterfaceCoverage(featureFindings, surfaceFindings)
	fmt.Fprintf(
		out,
		"[features] interface mapping:\n  actions: %d\n  concrete mapped: %d\n  root-only: %d\n  unmapped: %d\n",
		counts.Actions(),
		counts.ConcreteActions,
		counts.RootOnlyActions,
		counts.UnmappedActions,
	)
	fmt.Fprintf(
		out,
		"[features] concrete interface coverage:\n  candidate interfaces: %d\n  referenced by feature tree: %d\n  unreferenced: %d\n",
		coverage.CandidateInterfaces,
		coverage.ReferencedInterfaces,
		coverage.UnreferencedInterfaces,
	)
}

func featureAttempt(manifest *runpkg.Run) int {
	if manifest == nil {
		return 0
	}
	return manifest.FeatureAttempt
}

func loadStageOutput[T any](
	path string,
) (*T, *investigation.Result, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read completed stage output %s: %w", path, err)
	}
	var envelope struct {
		Status     string                             `json:"status"`
		Summary    string                             `json:"summary"`
		Findings   json.RawMessage                    `json:"findings"`
		Claims     []investigation.Claim              `json:"claims,omitempty"`
		Unresolved []investigation.UnresolvedQuestion `json:"unresolved,omitempty"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, nil, fmt.Errorf("decode completed stage output %s: %w", path, err)
	}
	var findings T
	if err := investigation.DecodeObjectFindings(
		envelope.Findings,
		&findings,
		"completed stage findings",
	); err != nil {
		return nil, nil, fmt.Errorf("decode completed stage output %s: %w", path, err)
	}
	result := &investigation.Result{
		Status: envelope.Status, Summary: envelope.Summary,
		Findings: envelope.Findings, Claims: envelope.Claims,
		Unresolved: envelope.Unresolved,
	}
	return &findings, result, nil
}

func markStageCompleted(manifest *runpkg.Run, stage Stage) error {
	if manifest == nil {
		return nil
	}
	return manifest.MarkStageCompleted(string(stage))
}

func writeResult(
	path string,
	result *investigation.Result,
	findings any,
) error {
	output := struct {
		Status     string                             `json:"status"`
		Summary    string                             `json:"summary"`
		Findings   any                                `json:"findings"`
		Claims     []investigation.Claim              `json:"claims,omitempty"`
		Unresolved []investigation.UnresolvedQuestion `json:"unresolved,omitempty"`
	}{
		Status:     result.Status,
		Summary:    result.Summary,
		Findings:   findings,
		Claims:     result.Claims,
		Unresolved: result.Unresolved,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal output %s: %w", path, err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write output %s: %w", path, err)
	}

	return nil
}

func outputPath(runRoot, filename string) string {
	return filepath.Join(runRoot, "output", filename)
}

func printCompletion(
	out io.Writer,
	name string,
	summary string,
	path string,
) {
	fmt.Fprintf(
		out,
		"\n%s complete.\n%s\n\nWritten to:\n%s\n",
		name,
		summary,
		path,
	)
}
