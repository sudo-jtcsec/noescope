package surface

import (
	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
)

func ValidateCanonicalResult(
	result *investigation.Result,
	evidence investigation.EvidenceLookup,
	architectureFindings *architecture.Findings,
	authorizationFindings *authorization.Findings,
	entityFindings *entities.Findings,
) error {
	return validateResultWithReferences(
		result,
		evidence,
		referencesFromAllFindings(
			architectureFindings,
			authorizationFindings,
			entityFindings,
		),
	)
}
