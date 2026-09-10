package discovery

import (
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
)

func TestEntityContextContainsPriorFindingsButNotSummaries(t *testing.T) {
	priorResults := []*investigation.Result{
		{Summary: "architecture summary sentinel"},
		{Summary: "authentication summary sentinel"},
		{Summary: "authorization summary sentinel"},
	}

	architectureFindings := &architecture.Findings{
		Languages: []architecture.Technology{{Name: "Go"}},
	}
	authenticationFindings := &authentication.Findings{
		AuthenticationPresent: false,
		Confidence:            0.95,
		EvidenceIDs:           []string{"ev_authentication"},
		Mechanisms:            []authentication.Mechanism{},
	}
	authorizationFindings := &authorization.Findings{
		AuthorizationPresent: false,
		Confidence:           0.95,
		EvidenceIDs:          []string{"ev_authorization"},
		Roles:                []authorization.Role{},
		Permissions:          []authorization.Permission{},
		RolePermissions:      []authorization.RolePermission{},
		Enforcement:          []authorization.Enforcement{},
	}

	contextData, err := marshalEntitiesContext(
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
	)
	if err != nil {
		t.Fatal(err)
	}

	contextText := string(contextData)
	for _, expected := range []string{
		`"architecture":{"languages":[{"name":"Go"`,
		`"authentication":{"authentication_present":false`,
		`"authorization":{"authorization_present":false`,
		`"ev_authentication"`,
		`"ev_authorization"`,
	} {
		if !strings.Contains(contextText, expected) {
			t.Fatalf("entity context does not contain %q", expected)
		}
	}

	for _, result := range priorResults {
		if strings.Contains(contextText, result.Summary) {
			t.Fatalf(
				"entity context contains narrative summary %q",
				result.Summary,
			)
		}
	}
}
