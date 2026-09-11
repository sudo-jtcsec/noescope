package runtimeverify

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

func Markdown(runtime *Runtime) []byte {
	var out bytes.Buffer
	summary := Summarize(runtime)
	fmt.Fprintln(&out, "# Runtime Verification")
	fmt.Fprintf(&out, "\n- Source run: `%s`\n", inline(runtime.SourceRunID))
	fmt.Fprintf(&out, "- Git commit: `%s`\n", inline(runtime.SourceGitCommit))
	fmt.Fprintf(&out, "- Runtime run: `%s`\n", inline(runtime.RuntimeID))
	fmt.Fprintf(&out, "- Target: `%s`\n", inline(runtime.BaseURL))
	fmt.Fprintln(&out, "\n## Summary")
	fmt.Fprintf(&out, "\n- Runtime status: `%s`\n", runtime.Status)
	fmt.Fprintf(&out, "\n- Application reachable: %s\n", yesNo(runtime.Application.Reachable))
	fmt.Fprintf(&out, "- Authentication: `%s`\n", runtime.Authentication.Status)
	fmt.Fprintf(&out, "- Unique source interfaces selected: %d\n", summary.SelectedInterfaces)
	fmt.Fprintf(&out, "- State-scoped observations: %d\n", summary.Observations)
	fmt.Fprintf(&out, "- Verified observations: %d\n", summary.Verified)
	fmt.Fprintf(&out, "- Authentication required observations: %d\n", summary.AuthRequired)
	fmt.Fprintf(&out, "- Redirected observations: %d\n", summary.Redirected)
	fmt.Fprintf(&out, "- Contradicted observations: %d\n", summary.Contradicted)
	fmt.Fprintf(&out, "- Failed observations: %d\n", summary.Failed)
	fmt.Fprintf(&out, "- Mutating interfaces skipped: %d\n", summary.SkippedMutating)
	fmt.Fprintf(&out, "- Unknown interfaces skipped: %d\n", summary.SkippedUnknown)
	fmt.Fprintf(&out, "- Routes requiring runtime binding: %d\n", summary.RequiresBinding)

	interfaces := append([]InterfaceObservation(nil), runtime.Interfaces...)
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].InterfaceID+"\x00"+interfaces[i].State <
			interfaces[j].InterfaceID+"\x00"+interfaces[j].State
	})
	fmt.Fprintln(&out, "\n## Interface Verification")
	fmt.Fprintln(&out, "\n| Interface | State | Safety | Status | HTTP | Final URL | Reason |")
	fmt.Fprintln(&out, "|---|---|---|---|---:|---|---|")
	for _, item := range interfaces {
		fmt.Fprintf(&out, "| `%s` | %s | %s | `%s` | %s | `%s` | %s |\n",
			inline(item.InterfaceID), inline(item.State), item.Safety, item.Status,
			httpStatus(item.HTTPStatus), inline(item.FinalURL), inline(item.Reason),
		)
	}

	fmt.Fprintln(&out, "\n## Feature Verification")
	fmt.Fprintln(&out, "\n| Feature | Status | Verified interfaces | Source interfaces |")
	fmt.Fprintln(&out, "|---|---|---|---|")
	for _, item := range runtime.Features {
		fmt.Fprintf(&out, "| `%s` | `%s` | %s | %s |\n",
			inline(item.FeatureID), item.Status, codeList(item.VerifiedInterfaceIDs),
			codeList(item.InterfaceIDs),
		)
	}

	fmt.Fprintln(&out, "\n## Console / Runtime Errors")
	if runtime.Failure == nil && len(runtime.ObservationErrors) == 0 && len(runtime.ConsoleErrors) == 0 {
		fmt.Fprintln(&out, "\nNone observed.")
	} else {
		if runtime.Failure != nil {
			fmt.Fprintf(&out, "\n- runtime `%s/%s`: %s\n",
				inline(runtime.Failure.Phase), inline(runtime.Failure.Operation), inline(runtime.Failure.Message),
			)
		}
		for _, issue := range runtime.ObservationErrors {
			fmt.Fprintf(&out, "\n- observation `%s/%s` `%s` (%s): %s\n",
				inline(issue.Phase), inline(issue.Operation), inline(issue.InterfaceID),
				inline(issue.State), inline(issue.Message),
			)
		}
		for _, issue := range runtime.ConsoleErrors {
			fmt.Fprintf(&out, "\n- `%s` (%s): %s\n",
				inline(issue.InterfaceID), inline(issue.State), inline(issue.Message),
			)
		}
	}
	return out.Bytes()
}

func inline(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func yesNo(value bool) string {
	if value {
		return "Yes"
	}
	return "No"
}

func httpStatus(value int) string {
	if value == 0 {
		return ""
	}
	return fmt.Sprintf("%d", value)
}

func codeList(values []string) string {
	if len(values) == 0 {
		return "—"
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, "`"+inline(value)+"`")
	}
	return strings.Join(quoted, ", ")
}
