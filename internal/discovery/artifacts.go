package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
	"github.com/sudo-jtcsec/noescope/internal/investigations/features"
	"github.com/sudo-jtcsec/noescope/internal/investigations/surface"
	"github.com/sudo-jtcsec/noescope/internal/model"
	"github.com/sudo-jtcsec/noescope/internal/report"
)

type completedFindings struct {
	architecture   *architecture.Findings
	authentication *authentication.Findings
	authorization  *authorization.Findings
	entities       *entities.Findings
	surface        *surface.Findings
	features       *features.Findings
}

type completedResults struct {
	architecture   *investigation.Result
	authentication *investigation.Result
	authorization  *investigation.Result
	entities       *investigation.Result
	surface        *investigation.Result
	features       *investigation.Result
}

func writeApplicationArtifactsForStage(
	through Stage,
	runRoot string,
	metadata model.Metadata,
	findings completedFindings,
	results completedResults,
) (applicationPath string, markdownPath string, written bool, err error) {
	if through != StageFeatures {
		return "", "", false, nil
	}
	applicationPath, markdownPath, err = writeApplicationArtifacts(
		runRoot,
		metadata,
		findings,
		results,
	)
	return applicationPath, markdownPath, err == nil, err
}

func writeApplicationArtifacts(
	runRoot string,
	metadata model.Metadata,
	findings completedFindings,
	results completedResults,
) (applicationPath string, markdownPath string, err error) {
	if metadata.GeneratedAt.IsZero() {
		metadata.GeneratedAt = time.Now().UTC()
	}
	application, err := model.Build(model.BuildInput{
		Metadata: metadata,
		Findings: model.Findings{
			Architecture:   findings.architecture,
			Authentication: findings.authentication,
			Authorization:  findings.authorization,
			Entities:       findings.entities,
			Surface:        findings.surface,
			Features:       findings.features,
		},
		Results: model.Results{
			Architecture:   results.architecture,
			Authentication: results.authentication,
			Authorization:  results.authorization,
			Entities:       results.entities,
			Surface:        results.surface,
			Features:       results.features,
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("assemble application model: %w", err)
	}

	applicationJSON, err := json.MarshalIndent(application, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshal application model: %w", err)
	}
	markdown, err := report.Markdown(application)
	if err != nil {
		return "", "", fmt.Errorf("render application documentation: %w", err)
	}

	applicationPath = outputPath(runRoot, "application.json")
	markdownPath = outputPath(runRoot, "application.md")
	if err := os.WriteFile(applicationPath, applicationJSON, 0644); err != nil {
		return "", "", fmt.Errorf("write application model: %w", err)
	}
	if err := os.WriteFile(markdownPath, markdown, 0644); err != nil {
		return "", "", fmt.Errorf("write application documentation: %w", err)
	}
	return applicationPath, markdownPath, nil
}
