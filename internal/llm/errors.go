package llm

import (
	"errors"
	"fmt"
	"strings"
)

type RequestError struct {
	StatusCode int
	Status     string
	Message    string
	Type       string
	Code       string
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("LLM API returned %s: %s", e.Status, e.Message)
}

func IsResponseFormatUnsupported(err error) bool {
	var requestErr *RequestError
	if !errors.As(err, &requestErr) {
		return false
	}
	if requestErr.StatusCode != 400 &&
		requestErr.StatusCode != 404 &&
		requestErr.StatusCode != 422 {
		return false
	}

	detail := strings.ToLower(
		requestErr.Code + " " + requestErr.Type + " " + requestErr.Message,
	)
	mentionsFormat := strings.Contains(detail, "response_format") ||
		strings.Contains(detail, "json_schema") ||
		strings.Contains(detail, "json schema")
	explicitlyUnsupported := strings.Contains(detail, "not supported") ||
		strings.Contains(detail, "unsupported") ||
		strings.Contains(detail, "not implemented") ||
		strings.Contains(detail, "unrecognized") ||
		strings.Contains(detail, "unknown") ||
		strings.Contains(detail, "unexpected parameter") ||
		strings.Contains(detail, "extra inputs are not permitted")

	return mentionsFormat && explicitlyUnsupported
}
