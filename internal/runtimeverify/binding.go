package runtimeverify

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/sudo-jtcsec/noescope/internal/runtimeverify/browser"
)

type ObservedLink struct {
	URL        string
	EvidenceID string
}

type DiscoveryState struct {
	ObservedURLs  []string
	Links         []ObservedLink
	Authenticated bool
}

type RouteResolution struct {
	URL             string
	Bindings        map[string]string
	EvidenceIDs     []string
	RequiresBinding bool
}

func (s *DiscoveryState) Observe(page browser.Page, evidenceID string, redactor *Redactor) {
	s.ObservedURLs = appendUniqueSorted(s.ObservedURLs, redactor.URL(page.FinalURL))
	for _, link := range page.Links {
		s.Links = append(s.Links, ObservedLink{URL: redactor.URL(link.URL), EvidenceID: evidenceID})
	}
	sort.Slice(s.Links, func(i, j int) bool {
		if s.Links[i].URL == s.Links[j].URL {
			return s.Links[i].EvidenceID < s.Links[j].EvidenceID
		}
		return s.Links[i].URL < s.Links[j].URL
	})
	s.Links = uniqueLinks(s.Links)
}

func ResolveRoute(baseURL, route string, state *DiscoveryState) (RouteResolution, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return RouteResolution{}, fmt.Errorf("invalid runtime base URL")
	}
	if route == "" {
		return RouteResolution{}, fmt.Errorf("interface has no URL path")
	}
	names := routeParameterNames(route)
	if len(names) > 0 {
		if state == nil {
			return RouteResolution{RequiresBinding: true}, nil
		}
		templateReference, err := url.Parse(route)
		if err != nil {
			return RouteResolution{}, fmt.Errorf("invalid parameterized interface path: %w", err)
		}
		templatePath := base.ResolveReference(templateReference).Path
		pattern, err := routePattern(templatePath, names)
		if err != nil {
			return RouteResolution{}, err
		}
		for _, link := range state.Links {
			candidate, err := url.Parse(link.URL)
			if err != nil || !sameOrigin(base, candidate) {
				continue
			}
			matches := pattern.FindStringSubmatch(candidate.Path)
			if len(matches) != len(names)+1 {
				continue
			}
			bindings := map[string]string{}
			for index, name := range names {
				value, err := url.PathUnescape(matches[index+1])
				if err != nil || value == "" {
					bindings = nil
					break
				}
				bindings[name] = value
			}
			if bindings != nil {
				return RouteResolution{
					URL: candidate.String(), Bindings: bindings,
					EvidenceIDs: []string{link.EvidenceID},
				}, nil
			}
		}
		return RouteResolution{RequiresBinding: true}, nil
	}
	reference, err := url.Parse(route)
	if err != nil {
		return RouteResolution{}, fmt.Errorf("invalid interface path: %w", err)
	}
	resolved := base.ResolveReference(reference)
	if !sameOrigin(base, resolved) {
		return RouteResolution{}, fmt.Errorf("interface resolves outside runtime origin")
	}
	return RouteResolution{URL: resolved.String(), Bindings: map[string]string{}}, nil
}

func routeParameterNames(route string) []string {
	pattern := regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	matches := pattern.FindAllStringSubmatch(route, -1)
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		result = append(result, match[1])
	}
	return result
}

func routePattern(route string, names []string) (*regexp.Regexp, error) {
	path := route
	if parsed, err := url.Parse(route); err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	var pattern strings.Builder
	pattern.WriteString("^")
	remaining := path
	for _, name := range names {
		marker := "{" + name + "}"
		index := strings.Index(remaining, marker)
		if index < 0 {
			return nil, fmt.Errorf("invalid route parameter %q", name)
		}
		pattern.WriteString(regexp.QuoteMeta(remaining[:index]))
		pattern.WriteString("([^/]+)")
		remaining = remaining[index+len(marker):]
	}
	pattern.WriteString(regexp.QuoteMeta(remaining))
	pattern.WriteString("$")
	return regexp.Compile(pattern.String())
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func appendUniqueSorted(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	values = append(values, value)
	sort.Strings(values)
	return values
}

func uniqueLinks(values []ObservedLink) []ObservedLink {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		last := result[len(result)-1]
		if value.URL != last.URL || value.EvidenceID != last.EvidenceID {
			result = append(result, value)
		}
	}
	return result
}
