package coretests

import (
	"strings"
	"unicode"
)

const redactionMarker = "[REDACTED]"

type SafeStringGrounding struct {
	Match  string
	Value  string
	Usable bool
}

// GroundSafeString converts a persisted runtime string into assertion-safe
// semantics. Redaction placeholders are never treated as literal application
// text and no attempt is made to reconstruct the removed value.
func GroundSafeString(value string) SafeStringGrounding {
	if !strings.Contains(value, redactionMarker) {
		return SafeStringGrounding{Match: "exact", Value: value, Usable: meaningfulFragment(value)}
	}
	fragments := strings.Split(value, redactionMarker)
	if len(fragments) > 0 && meaningfulFragment(fragments[0]) {
		return SafeStringGrounding{Match: "prefix", Value: fragments[0], Usable: true}
	}
	best := ""
	for _, fragment := range fragments {
		if meaningfulFragment(fragment) && len(fragment) > len(best) {
			best = fragment
		}
	}
	if best == "" {
		return SafeStringGrounding{}
	}
	return SafeStringGrounding{Match: "contains", Value: best, Usable: true}
}

func meaningfulFragment(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 2 {
		return false
	}
	for _, character := range trimmed {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			return true
		}
	}
	return false
}
