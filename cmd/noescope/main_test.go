package main

import (
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
)

func TestDownstreamContextsContainFindingsButNotSummaries(t *testing.T) {
	architectureResult := &investigation.Result{
		Summary: "summary-only incorrect module github.com/noescope/noescope",
	}
	authenticationResult := &investigation.Result{
		Summary: "summary-only unsupported authentication detail",
	}

	architectureFindings := &architecture.Findings{
		Languages: []architecture.Technology{
			{Name: "Go"},
		},
		ArchitectureStyle: architecture.Statement{
			Value: "local-first CLI",
		},
	}
	authenticationFindings := &authentication.Findings{
		AuthenticationPresent: false,
		Confidence:            0.95,
		EvidenceIDs:           []string{"ev_auth_search"},
		Mechanisms:            []authentication.Mechanism{},
	}

	authenticationContext, err := marshalAuthenticationContext(
		architectureFindings,
	)
	if err != nil {
		t.Fatal(err)
	}

	authorizationContext, err := marshalAuthorizationContext(
		architectureFindings,
		authenticationFindings,
	)
	if err != nil {
		t.Fatal(err)
	}

	for name, context := range map[string]string{
		"authentication": string(authenticationContext),
		"authorization":  string(authorizationContext),
	} {
		if !strings.Contains(context, `"languages":[{"name":"Go"`) {
			t.Fatalf("%s context does not contain architecture findings", name)
		}

		for _, summary := range []string{
			architectureResult.Summary,
			authenticationResult.Summary,
		} {
			if strings.Contains(context, summary) {
				t.Fatalf("%s context contains narrative summary %q", name, summary)
			}
		}
	}

	if !strings.Contains(
		string(authorizationContext),
		`"authentication":{"authentication_present":false,"confidence":0.95,"evidence_ids":["ev_auth_search"],"mechanisms":[]}`,
	) {
		t.Fatal("authorization context does not contain authentication findings")
	}
}
