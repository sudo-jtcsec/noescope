package discovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/sudo-jtcsec/noescope/internal/investigation"
	"github.com/sudo-jtcsec/noescope/internal/investigations/architecture"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authentication"
	"github.com/sudo-jtcsec/noescope/internal/investigations/authorization"
	"github.com/sudo-jtcsec/noescope/internal/investigations/entities"
)

func TestSurfaceContextContainsCanonicalEssentials(t *testing.T) {
	architectureFindings, authenticationFindings,
		authorizationFindings, entityFindings := contextFixtures()

	projection, err := buildSurfaceContext(
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
		entityFindings,
	)
	if err != nil {
		t.Fatal(err)
	}

	var context surfaceTaskContext
	if err := json.Unmarshal(projection.Data, &context); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(context.Architecture.Languages, []string{"PHP"}) {
		t.Fatalf("unexpected languages: %#v", context.Architecture.Languages)
	}
	if !reflect.DeepEqual(
		context.Architecture.Frameworks,
		[]string{"Symfony Console"},
	) {
		t.Fatalf("unexpected frameworks: %#v", context.Architecture.Frameworks)
	}
	if context.Architecture.ArchitectureStyle != "custom MVC" ||
		len(context.Architecture.Entrypoints) != 1 ||
		context.Architecture.Entrypoints[0].Path != "index.php" {
		t.Fatalf("architecture essentials missing: %#v", context.Architecture)
	}
	if !context.Authentication.AuthenticationPresent ||
		len(context.Authentication.Mechanisms) != 1 ||
		context.Authentication.Mechanisms[0].ID != "web-session" {
		t.Fatalf("authentication essentials missing: %#v", context.Authentication)
	}
	if !context.Authorization.AuthorizationPresent ||
		context.Authorization.ModelType != "rbac" ||
		context.Authorization.Roles[0].ID != "admin" ||
		context.Authorization.Permissions[0].ID != "project.manage" {
		t.Fatalf("authorization essentials missing: %#v", context.Authorization)
	}
	if len(context.Entities) != 1 || context.Entities[0].ID != "project" {
		t.Fatalf("canonical entity IDs missing: %#v", context.Entities)
	}
}

func TestSurfaceContextExcludesVerboseCanonicalDataAndNarrativeHistory(t *testing.T) {
	architectureFindings, authenticationFindings,
		authorizationFindings, entityFindings := contextFixtures()
	priorResults := []*investigation.Result{
		{Summary: "architecture summary sentinel"},
		{Summary: "authentication summary sentinel"},
		{Summary: "authorization summary sentinel"},
		{Summary: "entities summary sentinel"},
	}

	projection, err := buildSurfaceContext(
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
		entityFindings,
	)
	if err != nil {
		t.Fatal(err)
	}
	contextText := string(projection.Data)
	for _, excluded := range []string{
		"verbose directory purpose",
		"verbose source component",
		"verbose role description",
		"verbose permission description",
		"verbose persistence description",
		"ev_architecture",
		"ev_authentication",
		"ev_authorization",
		"ev_entity",
		"prior chat transcript sentinel",
	} {
		if strings.Contains(contextText, excluded) {
			t.Fatalf("surface context contains excluded data %q", excluded)
		}
	}
	for _, result := range priorResults {
		if strings.Contains(contextText, result.Summary) {
			t.Fatalf("surface context contains summary %q", result.Summary)
		}
	}
}

func TestContextProjectionDoesNotMutateCanonicalFindings(t *testing.T) {
	architectureFindings, authenticationFindings,
		authorizationFindings, entityFindings := contextFixtures()
	before, err := json.Marshal([]any{
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
		entityFindings,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := buildAuthenticationContext(architectureFindings); err != nil {
		t.Fatal(err)
	}
	if _, err := buildAuthorizationContext(
		architectureFindings,
		authenticationFindings,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := buildEntitiesContext(
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := buildSurfaceContext(
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
		entityFindings,
	); err != nil {
		t.Fatal(err)
	}

	after, err := json.Marshal([]any{
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
		entityFindings,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("context projection mutated canonical findings")
	}
}

func TestKanboardSizedSurfaceProjectionIsSubstantiallySmaller(t *testing.T) {
	architectureFindings, authenticationFindings,
		authorizationFindings, entityFindings := contextFixtures()
	for i := 0; i < 400; i++ {
		authorizationFindings.Permissions = append(
			authorizationFindings.Permissions,
			authorization.Permission{
				ID:          fmt.Sprintf("permission.%03d", i),
				Name:        fmt.Sprintf("Permission %03d", i),
				Description: strings.Repeat("verbose permission description ", 8),
				Confidence:  0.9,
				EvidenceIDs: []string{
					"ev_permission_1",
					"ev_permission_2",
					"ev_permission_3",
				},
			},
		)
	}

	projection, err := buildSurfaceContext(
		architectureFindings,
		authenticationFindings,
		authorizationFindings,
		entityFindings,
	)
	if err != nil {
		t.Fatal(err)
	}
	if projection.ProjectedBytes >= projection.CanonicalBytes/4 {
		t.Fatalf(
			"projection was not substantially smaller: %d -> %d",
			projection.CanonicalBytes,
			projection.ProjectedBytes,
		)
	}
	if projection.ProjectedBytes > maxProjectedContextBytes {
		t.Fatal("projection exceeds preflight threshold")
	}
}

func TestContextProjectionLoggingDoesNotRevealContents(t *testing.T) {
	var output bytes.Buffer
	logContextProjection(&output, "surface", contextProjection{
		Data:           json.RawMessage(`{"secret":"must-not-appear"}`),
		CanonicalBytes: 53000,
		ProjectedBytes: 12000,
	})
	if output.String() != "[surface] context projection: 53000 -> 12000 bytes\n" {
		t.Fatalf("unexpected telemetry: %q", output.String())
	}
	if strings.Contains(output.String(), "must-not-appear") {
		t.Fatal("context telemetry exposed context contents")
	}
}

func TestProjectedContextPreflightRequiresSegmentation(t *testing.T) {
	_, err := marshalContextProjection(
		"surface",
		map[string]string{"canonical": "small"},
		map[string]string{
			"projected": strings.Repeat("x", maxProjectedContextBytes),
		},
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"surface projected context is",
	) || !strings.Contains(err.Error(), "stage segmentation is required") {
		t.Fatalf("unexpected preflight error: %v", err)
	}
}

func contextFixtures() (
	*architecture.Findings,
	*authentication.Findings,
	*authorization.Findings,
	*entities.Findings,
) {
	architectureFindings := &architecture.Findings{
		Languages: []architecture.Technology{{
			Name: "PHP", EvidenceIDs: []string{"ev_architecture"},
		}},
		Frameworks: []architecture.Technology{{
			Name: "Symfony Console", EvidenceIDs: []string{"ev_architecture"},
		}},
		ArchitectureStyle: architecture.Statement{Value: "custom MVC"},
		Entrypoints:       []architecture.Entrypoint{{Path: "index.php", Type: "web"}},
		ImportantDirectories: []architecture.Directory{{
			Path: "app", Purpose: "verbose directory purpose",
		}},
	}
	authenticationFindings := &authentication.Findings{
		AuthenticationPresent: true,
		Confidence:            0.95,
		EvidenceIDs:           []string{"ev_authentication"},
		Mechanisms: []authentication.Mechanism{{
			ID:               "web-session",
			Type:             "form_session",
			LoginEntrypoints: []string{"/login"},
			SourceComponents: []string{"verbose source component"},
			EvidenceIDs:      []string{"ev_authentication"},
		}},
	}
	authorizationFindings := &authorization.Findings{
		AuthorizationPresent: true,
		Confidence:           0.95,
		EvidenceIDs:          []string{"ev_authorization"},
		Model:                &authorization.Model{Type: "rbac"},
		Roles: []authorization.Role{{
			ID:          "admin",
			Name:        "Administrator",
			Description: "verbose role description",
			EvidenceIDs: []string{"ev_authorization"},
		}},
		Permissions: []authorization.Permission{{
			ID:          "project.manage",
			Name:        "Manage Projects",
			Description: "verbose permission description",
			EvidenceIDs: []string{"ev_authorization"},
		}},
	}
	entityFindings := &entities.Findings{
		Entities: []entities.Entity{{
			ID:          "project",
			Name:        "Project",
			Aliases:     []string{"board"},
			Description: "verbose entity description",
			SourceComponents: []entities.SourceComponent{{
				Path: "verbose source component",
			}},
			Persistence: []entities.Persistence{{
				Type:        "database_table",
				Name:        "verbose persistence description",
				EvidenceIDs: []string{"ev_entity"},
			}},
			EvidenceIDs: []string{"ev_entity"},
		}},
	}
	return architectureFindings, authenticationFindings,
		authorizationFindings, entityFindings
}
