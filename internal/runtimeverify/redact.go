package runtimeverify

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const redacted = "[REDACTED]"

var (
	headerSecretPattern = regexp.MustCompile(`(?i)(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*[^\r\n]+`)
	bearerPattern       = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/-]+=*`)
)

type Redactor struct {
	secrets []string
}

func NewRedactor(secrets ...string) *Redactor {
	filtered := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret != "" {
			filtered = append(filtered, secret)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return len(filtered[i]) > len(filtered[j]) })
	return &Redactor{secrets: filtered}
}

func (r *Redactor) String(value string) string {
	value = headerSecretPattern.ReplaceAllString(value, "$1: "+redacted)
	value = bearerPattern.ReplaceAllString(value, "Bearer "+redacted)
	for _, secret := range r.secrets {
		value = strings.ReplaceAll(value, secret, redacted)
	}
	return value
}

func (r *Redactor) URL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return r.String(value)
	}
	parsed.User = nil
	parsed.Fragment = ""
	query := parsed.Query()
	for key := range query {
		if sensitiveName(key) {
			query.Set(key, redacted)
		}
	}
	parsed.RawQuery = query.Encode()
	return r.String(parsed.String())
}

func sensitiveName(name string) bool {
	name = strings.ToLower(name)
	for _, token := range []string{"password", "passwd", "token", "secret", "api_key", "apikey", "authorization", "cookie"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}
