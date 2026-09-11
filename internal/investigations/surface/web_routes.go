package surface

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

const webRoutesPerGroup = 18

type webRouteCandidate struct {
	Path       string `json:"path"`
	Controller string `json:"controller"`
	Action     string `json:"action"`
	RouteName  string `json:"route_name,omitempty"`
	Method     string `json:"method,omitempty"`
	SourcePath string `json:"source_path"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
}

type webRouteDiscovery struct {
	Sources    []string
	Candidates []webRouteCandidate
}

func discoverWebRoutes(repositoryRoot string) (webRouteDiscovery, error) {
	result := webRouteDiscovery{Sources: []string{}, Candidates: []webRouteCandidate{}}
	if repositoryRoot == "" {
		return result, nil
	}
	byKey := map[string]webRouteCandidate{}
	sources := map[string]struct{}{}
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != repositoryRoot && ignoredRouteDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".php") {
			return nil
		}
		relative, err := filepath.Rel(repositoryRoot, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		candidates, err := extractAddRouteCandidates(path, relative)
		if err != nil {
			return err
		}
		if len(candidates) > 0 {
			sources[relative] = struct{}{}
		}
		for _, candidate := range candidates {
			key := webRouteCandidateIdentity(candidate)
			if previous, ok := byKey[key]; !ok || webRouteCandidateLess(candidate, previous) {
				byKey[key] = candidate
			}
		}
		return nil
	})
	if err != nil {
		return result, fmt.Errorf("scan web route registrations: %w", err)
	}
	for source := range sources {
		result.Sources = append(result.Sources, source)
	}
	for _, candidate := range byKey {
		result.Candidates = append(result.Candidates, candidate)
	}
	sort.Strings(result.Sources)
	sort.Slice(result.Candidates, func(i, j int) bool {
		return webRouteCandidateLess(result.Candidates[i], result.Candidates[j])
	})
	return result, nil
}

func ignoredRouteDirectory(name string) bool {
	switch name {
	case ".git", ".noescope", "node_modules", "vendor", "dist", "build",
		"test", "tests", "testdata", "spec", "specs", "fixtures":
		return true
	default:
		return false
	}
}

func extractAddRouteCandidates(path, relativePath string) ([]webRouteCandidate, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := []webRouteCandidate{}
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		for offset := 0; ; {
			index := strings.Index(line[offset:], "addRoute")
			if index < 0 {
				break
			}
			index += offset
			if !methodCallAt(line, index) {
				offset = index + len("addRoute")
				continue
			}
			arguments, end, ok := literalCallArguments(line, index+len("addRoute"))
			if ok && len(arguments) >= 3 {
				result = append(result, webRouteCandidate{
					Path:       normalizeRegisteredRoutePath(arguments[0]),
					Controller: arguments[1], Action: arguments[2],
					SourcePath: relativePath, StartLine: lineNumber, EndLine: lineNumber,
				})
			}
			if end <= index {
				offset = index + len("addRoute")
			} else {
				offset = end
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func methodCallAt(line string, index int) bool {
	if index > 0 && (unicode.IsLetter(rune(line[index-1])) || unicode.IsDigit(rune(line[index-1])) || line[index-1] == '_') {
		return false
	}
	before := strings.TrimSpace(line[:index])
	if !strings.HasSuffix(before, "->") {
		return false
	}
	after := strings.TrimSpace(line[index+len("addRoute"):])
	return strings.HasPrefix(after, "(")
}

func literalCallArguments(line string, afterName int) ([]string, int, bool) {
	index := afterName
	for index < len(line) && unicode.IsSpace(rune(line[index])) {
		index++
	}
	if index >= len(line) || line[index] != '(' {
		return nil, index, false
	}
	index++
	arguments := []string{}
	for index < len(line) {
		for index < len(line) && (unicode.IsSpace(rune(line[index])) || line[index] == ',') {
			index++
		}
		if index >= len(line) || (line[index] != '\'' && line[index] != '"') {
			return arguments, index, false
		}
		quote := line[index]
		index++
		var value strings.Builder
		closed := false
		for index < len(line) {
			character := line[index]
			index++
			if character == '\\' && index < len(line) {
				value.WriteByte(line[index])
				index++
				continue
			}
			if character == quote {
				closed = true
				break
			}
			value.WriteByte(character)
		}
		if !closed {
			return arguments, index, false
		}
		arguments = append(arguments, value.String())
		for index < len(line) && unicode.IsSpace(rune(line[index])) {
			index++
		}
		if index < len(line) && line[index] == ')' {
			return arguments, index + 1, true
		}
		if index >= len(line) || line[index] != ',' {
			return arguments, index, false
		}
	}
	return arguments, index, false
}

func normalizeRegisteredRoutePath(path string) string {
	path = "/" + strings.TrimLeft(strings.TrimSpace(path), "/")
	parts := strings.Split(path, "/")
	for index, part := range parts {
		if len(part) > 1 && part[0] == ':' {
			name := part[1:]
			valid := true
			for _, character := range name {
				if !unicode.IsLetter(character) && !unicode.IsDigit(character) && character != '_' {
					valid = false
					break
				}
			}
			if valid {
				parts[index] = "{" + name + "}"
			}
		}
	}
	return strings.Join(parts, "/")
}

func webRouteCandidateIdentity(candidate webRouteCandidate) string {
	return strings.Join([]string{
		candidate.Path, candidate.Method, candidate.Controller,
		candidate.Action, candidate.RouteName,
	}, "\x00")
}

func webRouteCandidateLess(left, right webRouteCandidate) bool {
	leftKey := strings.Join([]string{
		left.SourcePath, fmt.Sprintf("%09d", left.StartLine), webRouteCandidateIdentity(left),
	}, "\x00")
	rightKey := strings.Join([]string{
		right.SourcePath, fmt.Sprintf("%09d", right.StartLine), webRouteCandidateIdentity(right),
	}, "\x00")
	return leftKey < rightKey
}

func webRouteCandidateKey(candidate webRouteCandidate) string {
	raw, _ := json.Marshal(candidate)
	return string(raw)
}

func webTaskSpecs(candidates []webRouteCandidate) []categoryTaskSpec {
	if len(candidates) == 0 {
		return []categoryTaskSpec{{}}
	}
	result := make([]categoryTaskSpec, 0, (len(candidates)+webRoutesPerGroup-1)/webRoutesPerGroup)
	for start := 0; start < len(candidates); start += webRoutesPerGroup {
		end := start + webRoutesPerGroup
		if end > len(candidates) {
			end = len(candidates)
		}
		result = append(result, webTaskSpec(
			fmt.Sprintf("group_%d", len(result)+1), candidates[start:end], 0,
		))
	}
	return result
}

func webTaskSpec(suffix string, routes []webRouteCandidate, depth int) categoryTaskSpec {
	candidateKeys := make([]string, 0, len(routes))
	rows := make([]string, 0, len(routes))
	for _, candidate := range routes {
		candidateKeys = append(candidateKeys, webRouteCandidateKey(candidate))
		rows = append(rows, fmt.Sprintf(
			"- path=%q controller=%q action=%q method=%q route_name=%q source=%s:%d",
			candidate.Path, candidate.Controller, candidate.Action, candidate.Method,
			candidate.RouteName, candidate.SourcePath, candidate.StartLine,
		))
	}
	instructions := `Enumerate and enrich every route candidate below. The candidates were extracted deterministically from literal route registrations; do not rediscover the route table. Preserve each exact path and placeholder. Every returned interface must include the candidate route-registration file in source_components, and every candidate must map through handler.interface_ids to its controller/action handler. Cite source evidence for both registration and handler. Inspect targeted handler or form evidence to distinguish web_page from form_action and to establish an HTTP method. When the registration and handler evidence do not establish a method, leave locator.method unset; do not infer it solely from an action name. A route supporting distinct display and submission behavior may yield both a web_page and form_action when source evidence supports both. Do not omit a candidate merely because access or method is uncertain; represent uncertainty in access/method rather than inventing it.`
	instructions += "\n\nROUTE CANDIDATES:\n" + strings.Join(rows, "\n")
	return categoryTaskSpec{
		suffix: suffix, instructions: instructions,
		candidates: candidateKeys, webRoutes: append([]webRouteCandidate(nil), routes...), depth: depth,
	}
}

func validateWebCandidateCoverage(findings *Findings, candidates []webRouteCandidate) error {
	if len(candidates) == 0 {
		return nil
	}
	for _, candidate := range candidates {
		covered := false
		handled := false
		for _, item := range findings.Interfaces {
			if item.Locator.Path != candidate.Path {
				continue
			}
			for _, component := range item.SourceComponents {
				if component.Path == candidate.SourcePath {
					covered = true
					break
				}
			}
			if covered {
				for _, handler := range findings.Handlers {
					if !containsString(handler.InterfaceIDs, item.ID) {
						continue
					}
					handlerIdentity := strings.ToLower(handler.Name + " " + handler.Symbol)
					if strings.Contains(handlerIdentity, strings.ToLower(candidate.Controller)) {
						handled = true
						break
					}
				}
				if handled {
					break
				}
			}
		}
		if !covered {
			return fmt.Errorf(
				"web route candidate %q (%s::%s at %s:%d) has no canonical interface",
				candidate.Path, candidate.Controller, candidate.Action,
				candidate.SourcePath, candidate.StartLine,
			)
		}
		if !handled {
			return fmt.Errorf(
				"web route candidate %q (%s::%s) has no mapped controller handler",
				candidate.Path, candidate.Controller, candidate.Action,
			)
		}
	}
	return nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
