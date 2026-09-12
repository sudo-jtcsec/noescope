package runtimeverify

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const redacted = "[REDACTED]"

var (
	headerSecretPattern = regexp.MustCompile(`(?i)(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*[^\r\n]+`)
	bearerPattern       = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/-]+=*`)
	otpauthPattern      = regexp.MustCompile(`(?i)otpauth://[^\s"'<>]+`)
)

type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

func NewRedactor(secrets ...string) *Redactor {
	result := &Redactor{}
	result.AddSecrets(secrets...)
	return result
}

// AddSecrets registers short-lived values such as a generated TOTP code before
// they can reach diagnostic or persistence boundaries.
func (r *Redactor) AddSecrets(secrets ...string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		found := false
		for _, existing := range r.secrets {
			if existing == secret {
				found = true
				break
			}
		}
		if !found {
			r.secrets = append(r.secrets, secret)
		}
	}
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
}

func (r *Redactor) String(value string) string {
	value = headerSecretPattern.ReplaceAllString(value, "$1: "+redacted)
	value = bearerPattern.ReplaceAllString(value, "Bearer "+redacted)
	value = otpauthPattern.ReplaceAllString(value, redacted)
	r.mu.RLock()
	secrets := append([]string(nil), r.secrets...)
	r.mu.RUnlock()
	for _, secret := range secrets {
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
	for _, token := range []string{"password", "passwd", "token", "secret", "api_key", "apikey", "authorization", "cookie", "otp", "totp", "one_time", "one-time", "authentication_code", "verification_code"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}
