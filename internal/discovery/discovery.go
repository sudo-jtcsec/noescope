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
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
)

func Run(
	ctx context.Context,
	runner *investigation.Runner,
	runRoot string,
	out io.Writer,
) error {
	return RunThrough(ctx, runner, runRoot, out, StageSurface)
}

func RunThrough(
	ctx context.Context,
	runner *investigation.Runner,
	runRoot string,
	out io.Writer,
	through Stage,
) error {
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

	surfaceFindings, surfaceResult, err := surface.Run(
		ctx,
		runner,
		surfaceContext.Data,
		authorizationFindings,
		entityFindings,
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

	fmt.Fprintf(
		out,
		"\nTechnical surface discovery complete.\nDiscovered %d interfaces.\n\nWritten to:\n%s\n",
		len(surfaceFindings.Interfaces),
		surfacePath,
	)

	return nil
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
