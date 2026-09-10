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
)

func Run(
	ctx context.Context,
	runner *investigation.Runner,
	runRoot string,
	out io.Writer,
) error {
	if out == nil {
		out = io.Discard
	}

	fmt.Fprintln(out, "[1/4] Architecture Discovery")

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

	authenticationContext, err := marshalAuthenticationContext(
		architectureFindings,
	)
	if err != nil {
		return fmt.Errorf("marshal authentication context: %w", err)
	}

	fmt.Fprintln(out, "\n[2/4] Authentication Discovery")

	authenticationFindings, authenticationResult, err := authentication.Run(
		ctx,
		runner,
		authenticationContext,
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

	authorizationContext, err := marshalAuthorizationContext(
		architectureFindings,
		authenticationFindings,
	)
	if err != nil {
		return fmt.Errorf("marshal authorization context: %w", err)
	}

	fmt.Fprintln(out, "\n[3/4] Authorization Discovery")

	authorizationFindings, authorizationResult, err := authorization.Run(
		ctx,
		runner,
		authorizationContext,
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

	entitiesContext, err := marshalEntitiesContext(
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
	)
	if err != nil {
		return fmt.Errorf("marshal entity context: %w", err)
	}

	fmt.Fprintln(out, "\n[4/4] Domain Entity Discovery")

	entityFindings, entityResult, err := entities.Run(
		ctx,
		runner,
		entitiesContext,
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

	return nil
}

// Context builders intentionally accept only validated structured findings.
// Investigation summaries are narrative-only and never become downstream
// canonical context.
func marshalAuthenticationContext(
	findings *architecture.Findings,
) (json.RawMessage, error) {
	return json.Marshal(findings)
}

func marshalAuthorizationContext(
	architectureFindings *architecture.Findings,
	authenticationFindings *authentication.Findings,
) (json.RawMessage, error) {
	return json.Marshal(struct {
		Architecture   *architecture.Findings   `json:"architecture"`
		Authentication *authentication.Findings `json:"authentication"`
	}{
		Architecture:   architectureFindings,
		Authentication: authenticationFindings,
	})
}

func marshalEntitiesContext(
	architectureFindings *architecture.Findings,
	authenticationFindings *authentication.Findings,
	authorizationFindings *authorization.Findings,
) (json.RawMessage, error) {
	return json.Marshal(struct {
		Architecture   *architecture.Findings   `json:"architecture"`
		Authentication *authentication.Findings `json:"authentication"`
		Authorization  *authorization.Findings  `json:"authorization"`
	}{
		Architecture:   architectureFindings,
		Authentication: authenticationFindings,
		Authorization:  authorizationFindings,
	})
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
