package portabletests

import (
	"bytes"
	"fmt"
	"html/template"
	"path/filepath"
	"sort"
	"strings"
)

type reportTest struct {
	Test     Test
	Result   Result
	Status   string
	Label    string
	History  []reportHistory
	Evidence []Evidence
}

type reportHistory struct {
	ExecutionID string
	CompletedAt string
	Status      string
	Label       string
	DurationMS  int64
}

type reportData struct {
	Manifest       Manifest
	Summary        Summary
	Tests          []reportTest
	Latest         *Execution
	Overall        string
	OverallStatus  string
	Authentication string
}

func reportView(bundle *Bundle) reportData {
	latestResults := LatestResults(bundle)
	data := reportData{Manifest: bundle.Manifest, Tests: []reportTest{}}
	if len(bundle.History) > 0 {
		latest := bundle.History[len(bundle.History)-1]
		data.Latest = &latest
	}
	allResults := []Result{}
	for _, test := range bundle.Tests {
		result, ok := latestResults[test.ID]
		if !ok {
			result = Result{TestID: test.ID, Status: StatusNotRun, EvidenceIDs: []string{}}
		}
		allResults = append(allResults, result)
		item := reportTest{Test: test, Result: result, Status: result.Status, Label: statusLabel(result.Status)}
		evidenceIDs := map[string]struct{}{}
		for _, execution := range bundle.History {
			for _, historical := range execution.Results {
				if historical.TestID != test.ID {
					continue
				}
				item.History = append(item.History, reportHistory{ExecutionID: execution.ExecutionID,
					CompletedAt: execution.CompletedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
					Status:      historical.Status, Label: statusLabel(historical.Status), DurationMS: historical.DurationMS})
				for _, id := range historical.EvidenceIDs {
					evidenceIDs[id] = struct{}{}
				}
			}
		}
		for _, evidence := range bundle.Evidence {
			if _, ok := evidenceIDs[evidence.ID]; ok {
				item.Evidence = append(item.Evidence, evidence)
			}
		}
		data.Tests = append(data.Tests, item)
	}
	data.Summary = summarize(allResults)
	data.OverallStatus = overallStatus(data.Summary)
	data.Overall = statusLabel(data.OverallStatus)
	data.Authentication = authenticationLabel(bundle.Manifest.Identities)
	return data
}

func overallStatus(summary Summary) string {
	switch {
	case summary.CleanupFailed > 0:
		return StatusCleanupFailed
	case summary.Failed > 0:
		return StatusFailed
	case summary.Unresolved > 0:
		return StatusUnresolved
	case summary.Blocked > 0:
		return StatusBlocked
	case summary.Passed == summary.Total && summary.Total > 0:
		return StatusPassed
	default:
		return StatusNotRun
	}
}

func HTML(bundle *Bundle) ([]byte, error) {
	functions := template.FuncMap{
		"status":    statusLabel,
		"safety":    safetyLabel,
		"step":      stepDescription,
		"assertion": assertionDescription,
		"cleanup":   cleanupDescription,
		"join":      strings.Join,
	}
	tmpl, err := template.New("report").Funcs(functions).Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, reportView(bundle)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func Markdown(bundle *Bundle) []byte {
	data := reportView(bundle)
	var out bytes.Buffer
	fmt.Fprintln(&out, "# Core Test Pack")
	fmt.Fprintf(&out, "\n- Project: %s\n", markdownText(data.Manifest.Project))
	fmt.Fprintf(&out, "- Source commit: `%s`\n", markdownText(data.Manifest.SourceCommit))
	fmt.Fprintf(&out, "- Pack ID: `%s`\n", markdownText(data.Manifest.PackID))
	fmt.Fprintf(&out, "- Generated: %s\n", data.Manifest.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&out, "- Default target: `%s`\n", markdownText(data.Manifest.DefaultTarget))
	if data.Authentication != "" {
		fmt.Fprintf(&out, "- Authentication: %s\n", markdownText(data.Authentication))
	}
	if data.Latest != nil {
		fmt.Fprintf(&out, "- Most recent run: `%s`\n", markdownText(data.Latest.ExecutionID))
	}
	fmt.Fprintln(&out, "\n## Summary")
	fmt.Fprintf(&out, "\n- Total: %d\n- Passed: %d\n- Failed: %d\n- Blocked: %d\n- Cleanup failed: %d\n- Unresolved: %d\n- Not run: %d\n",
		data.Summary.Total, data.Summary.Passed, data.Summary.Failed, data.Summary.Blocked,
		data.Summary.CleanupFailed, data.Summary.Unresolved, data.Summary.NotRun)
	fmt.Fprintln(&out, "\n## Tests")
	for _, item := range data.Tests {
		fmt.Fprintf(&out, "\n### %s\n", markdownText(item.Test.Name))
		fmt.Fprintf(&out, "\n- ID: `%s`\n- Status: **%s**\n- Safety: %s\n",
			markdownText(item.Test.ID), statusLabel(item.Status), safetyLabel(item.Test.Safety))
		fmt.Fprintf(&out, "\nPurpose: %s\n", markdownText(item.Test.Description))
		if len(item.Test.FeatureIDs) > 0 || len(item.Test.InterfaceIDs) > 0 || len(item.Test.EntityIDs) > 0 {
			fmt.Fprintln(&out, "\nCovers:")
			for _, id := range item.Test.FeatureIDs {
				fmt.Fprintf(&out, "\n- Feature `%s`", markdownText(id))
			}
			for _, id := range item.Test.InterfaceIDs {
				fmt.Fprintf(&out, "\n- Interface `%s`", markdownText(id))
			}
			for _, id := range item.Test.EntityIDs {
				fmt.Fprintf(&out, "\n- Entity `%s`", markdownText(id))
			}
			fmt.Fprintln(&out)
		}
		fmt.Fprintln(&out, "\nSteps:")
		for index, step := range item.Test.Steps {
			fmt.Fprintf(&out, "\n%d. %s", index+1, markdownText(stepDescription(step)))
		}
		fmt.Fprintln(&out)
		fmt.Fprintln(&out, "\nAssertions:")
		for _, assertion := range item.Test.Assertions {
			fmt.Fprintf(&out, "\n- %s", markdownText(assertionDescription(assertion)))
		}
		if len(item.Test.Assertions) == 0 {
			fmt.Fprint(&out, "\n- None")
		}
		fmt.Fprintln(&out)
		if len(item.Test.Cleanup) > 0 {
			fmt.Fprintln(&out, "\nCleanup:")
			for _, cleanup := range item.Test.Cleanup {
				fmt.Fprintf(&out, "\n- %s", markdownText(cleanupDescription(cleanup)))
			}
			fmt.Fprintln(&out)
		}
		fmt.Fprintln(&out, "\nLatest result:")
		if item.Result.Reason != "" {
			fmt.Fprintf(&out, "\n- Failure: %s\n", markdownText(item.Result.Reason))
		}
		if item.Result.WorkflowFailure != "" {
			fmt.Fprintf(&out, "- Workflow failure: %s\n", markdownText(item.Result.WorkflowFailure))
		}
		if item.Result.CleanupFailure != "" {
			fmt.Fprintf(&out, "- Cleanup failure: %s\n- **Manual cleanup may be required.**\n", markdownText(item.Result.CleanupFailure))
		}
		if len(item.Result.EvidenceIDs) > 0 {
			fmt.Fprintf(&out, "- Evidence: `%s`\n", markdownText(strings.Join(item.Result.EvidenceIDs, "`, `")))
		}
		if len(item.Evidence) > 0 {
			fmt.Fprintln(&out, "\nEvidence details:")
			for _, evidence := range item.Evidence {
				fmt.Fprintf(&out, "\n- %s · %s", markdownText(evidence.Type), markdownText(evidence.Description))
				if evidence.InterfaceID != "" {
					fmt.Fprintf(&out, " · interface `%s`", markdownText(evidence.InterfaceID))
				}
				if evidence.URL != "" {
					fmt.Fprintf(&out, " · `%s`", markdownText(evidence.URL))
				}
			}
			fmt.Fprintln(&out)
		}
		if len(item.History) > 0 {
			fmt.Fprintln(&out, "\nRecent history:")
			for _, history := range item.History {
				fmt.Fprintf(&out, "\n- `%s` — %s — %s (%d ms)", markdownText(history.ExecutionID), history.CompletedAt, history.Label, history.DurationMS)
			}
			fmt.Fprintln(&out)
		}
	}
	return out.Bytes()
}

func WriteReports(root string, bundle *Bundle) error {
	html, err := HTML(bundle)
	if err != nil {
		return err
	}
	if err := AtomicWrite(filepath.Join(root, "report.html"), html, 0600); err != nil {
		return err
	}
	return AtomicWrite(filepath.Join(root, "report.md"), Markdown(bundle), 0600)
}

func WriteBundleReports(root string, bundle *Bundle) error {
	if err := WriteReports(root, bundle); err != nil {
		return err
	}
	return nil
}

func statusLabel(status string) string {
	switch status {
	case StatusPassed:
		return "PASS"
	case StatusFailed:
		return "FAIL"
	case StatusBlocked:
		return "BLOCKED"
	case StatusCleanupFailed:
		return "CLEANUP FAILED"
	case StatusUnresolved:
		return "UNRESOLVED"
	default:
		return "NOT RUN"
	}
}

func safetyLabel(safety Safety) string {
	if safety.Mutating {
		return "Mutating"
	}
	return "Read-only"
}

func authenticationLabel(identities []IdentityReference) string {
	if len(identities) == 0 {
		return ""
	}
	for _, identity := range identities {
		if identity.TOTP != nil {
			return "Username/password + TOTP"
		}
	}
	return "Username/password"
}

func stepDescription(step Step) string {
	switch step.Type {
	case "navigate":
		return "Navigate via interface " + step.InterfaceID
	case "fill":
		return "Fill semantic field " + step.Field + " from " + valueReference(step.Value)
	case "submit":
		return "Submit native form for interface " + step.InterfaceID
	case "wait_for":
		return "Wait for and bind " + step.Target
	case "observe":
		if step.InterfaceID != "" {
			return "Observe interface " + step.InterfaceID
		}
		return "Observe current page"
	default:
		return strings.Title(strings.ReplaceAll(step.Type, "_", " "))
	}
}

func assertionDescription(assertion Assertion) string {
	switch assertion.Type {
	case "http_status":
		return fmt.Sprintf("HTTP status equals %d", assertion.HTTPStatus)
	case "page_title":
		match := assertion.Match
		if match == "" {
			match = "exact"
		}
		return fmt.Sprintf("Page title %s %q", match, assertion.Expected)
	case "url_matches":
		return "Final URL matches " + assertion.Expected
	case "authenticated":
		return "Authenticated session is present"
	case "not_authenticated":
		return "Login surface is present"
	case "entity_visible":
		return "Entity value " + assertion.Expected + " is visible"
	default:
		return strings.ReplaceAll(assertion.Type, "_", " ") + " " + assertion.Expected
	}
}

func cleanupDescription(cleanup CleanupStep) string {
	return "Delete proven-owned object " + cleanup.OwnedReference + " via " + cleanup.InterfaceID
}

func valueReference(value *ValueReference) string {
	if value == nil {
		return "an unresolved value"
	}
	return value.Reference
}

func markdownText(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "`", "\\`")
	value = strings.ReplaceAll(value, "<", "&lt;")
	return value
}

func sortedTests(values []Test) []Test {
	result := append([]Test(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

const htmlTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Core Test Pack</title><style>
:root{font-family:system-ui,sans-serif;color:#172033;background:#f5f7fb}body{margin:0}.wrap{max-width:1180px;margin:auto;padding:28px}h1,h2{color:#101828}.meta,.summary,.test{background:#fff;border:1px solid #dfe4ec;border-radius:10px;padding:18px;margin:14px 0}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}.card{padding:12px;border-radius:8px;background:#eef2f7}.count{font-size:1.6rem;font-weight:700}.badge{display:inline-block;padding:4px 9px;border-radius:999px;font-weight:700;font-size:.78rem}.passed{background:#d1fadf;color:#05603a}.failed{background:#fee4e2;color:#b42318}.blocked{background:#fef0c7;color:#93370d}.cleanup_failed{background:#fecdca;color:#7a271a}.unresolved,.not_run{background:#eaecf0;color:#344054}.mutating{background:#ffe0b2;color:#8a3b00}.readonly{background:#dbeafe;color:#1e40af}.warning{border:2px solid #d92d20;background:#fff4f2;padding:12px;font-weight:700}code{overflow-wrap:anywhere}ol,ul{line-height:1.55}summary{cursor:pointer}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:9px;border-bottom:1px solid #e4e7ec}
</style></head><body><main class="wrap"><h1>Core Test Pack</h1>
<section class="meta"><strong>{{.Manifest.Project}}</strong> · <span class="badge {{.OverallStatus}}">{{.Overall}}</span><br>Source <code>{{.Manifest.SourceCommit}}</code> · Pack <code>{{.Manifest.PackID}}</code><br>Generated {{.Manifest.CreatedAt}} · Default target <code>{{.Manifest.DefaultTarget}}</code>{{if .Authentication}}<br>Authentication: {{.Authentication}}{{end}}{{if .Latest}}<br>Most recent run <code>{{.Latest.ExecutionID}}</code>{{end}}</section>
<section class="summary"><div class="card"><div class="count">{{.Summary.Total}}</div>Total</div><div class="card"><div class="count">{{.Summary.Passed}}</div>Passed</div><div class="card"><div class="count">{{.Summary.Failed}}</div>Failed</div><div class="card"><div class="count">{{.Summary.Blocked}}</div>Blocked</div><div class="card"><div class="count">{{.Summary.CleanupFailed}}</div>Cleanup failed</div><div class="card"><div class="count">{{.Summary.Unresolved}}</div>Unresolved</div></section>
<h2>Tests</h2><table><thead><tr><th>Status</th><th>Name</th><th>ID</th><th>Safety</th><th>Duration</th></tr></thead><tbody>{{range .Tests}}<tr><td><span class="badge {{.Status}}">{{.Label}}</span></td><td>{{.Test.Name}}</td><td><code>{{.Test.ID}}</code></td><td>{{if .Test.Safety.Mutating}}<span class="badge mutating">MUTATING</span>{{else}}<span class="badge readonly">READ-ONLY</span>{{end}}</td><td>{{.Result.DurationMS}} ms</td></tr>{{end}}</tbody></table>
{{range .Tests}}<details class="test" id="{{.Test.ID}}"><summary><strong>{{.Test.Name}}</strong> · <span class="badge {{.Status}}">{{.Label}}</span></summary><p>{{.Test.Description}}</p>
<p><strong>Safety:</strong> {{safety .Test.Safety}} · <strong>Identity:</strong> {{.Test.Identity}}</p>
<p><strong>Features:</strong> {{join .Test.FeatureIDs ", "}}<br><strong>Interfaces:</strong> {{join .Test.InterfaceIDs ", "}}<br><strong>Entities:</strong> {{join .Test.EntityIDs ", "}}</p>
<h3>Steps</h3><ol>{{range .Test.Steps}}<li>{{step .}}</li>{{end}}</ol><h3>Assertions</h3><ul>{{range .Test.Assertions}}<li>{{assertion .}}</li>{{else}}<li>None</li>{{end}}</ul>
{{if .Test.Cleanup}}<h3>Cleanup</h3><ul>{{range .Test.Cleanup}}<li>{{cleanup .}}</li>{{end}}</ul>{{end}}
<h3>Latest result</h3>{{if .Result.Reason}}<p><strong>Failure:</strong> {{.Result.Reason}}</p>{{end}}{{if .Result.WorkflowFailure}}<p><strong>Workflow failure:</strong> {{.Result.WorkflowFailure}}</p>{{end}}{{if .Result.CleanupFailure}}<div class="warning">Cleanup failure: {{.Result.CleanupFailure}}<br>Manual cleanup may be required.</div>{{end}}{{if .Result.EvidenceIDs}}<p><strong>Evidence:</strong> <code>{{join .Result.EvidenceIDs ", "}}</code></p>{{end}}
{{if .Evidence}}<h3>Evidence details</h3><ul>{{range .Evidence}}<li><strong>{{.Type}}</strong> · {{.Description}}{{if .InterfaceID}} · interface <code>{{.InterfaceID}}</code>{{end}}{{if .URL}} · <code>{{.URL}}</code>{{end}} · {{.CreatedAt}}</li>{{end}}</ul>{{end}}
{{if .History}}<h3>Recent history</h3><table><thead><tr><th>Execution</th><th>Completed</th><th>Status</th><th>Duration</th></tr></thead><tbody>{{range .History}}<tr><td><code>{{.ExecutionID}}</code></td><td>{{.CompletedAt}}</td><td><span class="badge {{.Status}}">{{.Label}}</span></td><td>{{.DurationMS}} ms</td></tr>{{end}}</tbody></table>{{end}}</details>{{end}}
</main></body></html>`
