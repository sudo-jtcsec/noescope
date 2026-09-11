package surface

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDiscoverWebRoutesFindsLiteralRegistrationSourcesAndCandidates(t *testing.T) {
	root := t.TempDir()
	writeRouteFixture(t, root, "app/Provider.php", `<?php
$container['route']->addRoute('login', 'AuthController', 'login');
$container['route']->addRoute("project/:project_id", "ProjectController", "show");
$container['route']->addRoute('login/check', 'AuthController', 'check');
$container['route']->addRoute('login/check', 'AuthController', 'check');
$container['route']->addRoute($dynamic, 'IgnoredController', 'show');
`)
	writeRouteFixture(t, root, "vendor/DependencyRoutes.php", `<?php
$router->addRoute('vendor', 'VendorController', 'show');
`)

	discovery, err := discoverWebRoutes(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(discovery.Sources, []string{"app/Provider.php"}) {
		t.Fatalf("unexpected route sources: %v", discovery.Sources)
	}
	if len(discovery.Candidates) != 3 {
		t.Fatalf("expected three deduplicated route candidates, got %#v", discovery.Candidates)
	}
	wantPaths := []string{"/login", "/project/{project_id}", "/login/check"}
	for index, candidate := range discovery.Candidates {
		if candidate.Path != wantPaths[index] || candidate.SourcePath != "app/Provider.php" ||
			candidate.StartLine == 0 || candidate.EndLine != candidate.StartLine {
			t.Fatalf("unexpected route candidate %d: %#v", index, candidate)
		}
	}
}

func TestDiscoverWebRoutesZeroRouteRegressionIsExplicit(t *testing.T) {
	root := t.TempDir()
	writeRouteFixture(t, root, "app/Provider.php", "<?php\n// no literal route registration\n")
	discovery, err := discoverWebRoutes(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(discovery.Sources) != 0 || len(discovery.Candidates) != 0 {
		t.Fatalf("non-route source produced candidates: %#v", discovery)
	}
}

func TestWebTaskSpecsAreDeterministicBoundedShards(t *testing.T) {
	candidates := make([]webRouteCandidate, webRoutesPerGroup*2+1)
	for index := range candidates {
		candidates[index] = webRouteCandidate{
			Path: "/route/" + string(rune('a'+index)), Controller: "Controller",
			Action: "show", SourcePath: "routes.php", StartLine: index + 1, EndLine: index + 1,
		}
	}
	first := webTaskSpecs(candidates)
	second := webTaskSpecs(candidates)
	if len(first) != 3 || !reflect.DeepEqual(first, second) ||
		len(first[0].webRoutes) != webRoutesPerGroup || len(first[2].webRoutes) != 1 {
		t.Fatalf("unexpected deterministic Web sharding: %#v", first)
	}
	left, right := splitCategoryTaskSpec(CategoryWeb, first[0])
	if left.suffix != "group_1.1" || right.suffix != "group_1.2" ||
		len(left.webRoutes) != 9 || len(right.webRoutes) != 9 {
		t.Fatalf("unexpected Web half split: %#v / %#v", left, right)
	}
	if !strings.Contains(first[0].instructions, `path="/route/a"`) ||
		!strings.Contains(first[0].instructions, "do not rediscover the route table") {
		t.Fatalf("route candidates missing from bounded task: %s", first[0].instructions)
	}
}

func TestWebCandidateCoverageRequiresInterfaceAndHandlerMapping(t *testing.T) {
	candidate := webRouteCandidate{
		Path: "/login", Controller: "AuthController", Action: "login",
		SourcePath: "app/Provider.php", StartLine: 10, EndLine: 10,
	}
	if err := validateWebCandidateCoverage(&Findings{}, []webRouteCandidate{candidate}); err == nil ||
		!strings.Contains(err.Error(), "no canonical interface") {
		t.Fatalf("zero-route result was not rejected: %v", err)
	}
	findings := &Findings{
		Interfaces: []Interface{{
			ID: "web.auth.login", Type: "web_page",
			Locator:          InterfaceLocator{Method: "GET", Path: "/login"},
			Access:           &Access{Authentication: "not_required"},
			SourceComponents: []SourceComponent{{Path: "app/Provider.php"}},
		}},
	}
	if err := validateWebCandidateCoverage(findings, []webRouteCandidate{candidate}); err == nil ||
		!strings.Contains(err.Error(), "no mapped controller handler") {
		t.Fatalf("missing handler mapping was not rejected: %v", err)
	}
	findings.Handlers = []Handler{{
		ID: "handler.auth", Type: "controller", Name: "AuthController",
		Path: "app/Controller/AuthController.php", Symbol: "AuthController::login",
		InterfaceIDs: []string{"web.auth.login"},
	}}
	if err := validateWebCandidateCoverage(findings, []webRouteCandidate{candidate}); err != nil {
		t.Fatalf("valid GET web_page route was rejected: %v", err)
	}
	findings.Interfaces[0] = Interface{
		ID: "web.auth.login.submit", Type: "form_action",
		Locator:          InterfaceLocator{Method: "POST", Path: "/login"},
		Access:           &Access{Authentication: "unknown"},
		SourceComponents: []SourceComponent{{Path: "app/Provider.php"}},
	}
	findings.Handlers[0].InterfaceIDs = []string{"web.auth.login.submit"}
	if err := validateWebCandidateCoverage(findings, []webRouteCandidate{candidate}); err != nil {
		t.Fatalf("valid POST form_action route was rejected: %v", err)
	}
}

func TestWebShardCheckpointReusesSameRouteCandidateSet(t *testing.T) {
	options := testRunOptions(t, false, "commit-one")
	route := webRouteCandidate{
		Path: "/login", Controller: "AuthController", Action: "login",
		SourcePath: "routes.php", StartLine: 1, EndLine: 1,
	}
	spec := webTaskSpec("group_1", []webRouteCandidate{route}, 0)
	task := taskForCategorySpec(CategoryWeb, spec)
	result := emptySurfaceResult(t)
	if err := newCheckpointStore(options).save(task, CategoryWeb, spec.candidates, result); err != nil {
		t.Fatal(err)
	}
	options.Resume = true
	loaded, reused, err := newCheckpointStore(options).load(task, CategoryWeb, spec.candidates)
	if err != nil || !reused || loaded.Summary != result.Summary {
		t.Fatalf("compatible Web checkpoint was not reused: reused=%v result=%#v err=%v", reused, loaded, err)
	}
}

func writeRouteFixture(t *testing.T, root, relative, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
}
