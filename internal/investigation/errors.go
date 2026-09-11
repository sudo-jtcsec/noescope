package investigation

import (
	"errors"
	"fmt"
)

type StructuredOutputMetadata struct {
	Bytes            int
	FinishReason     string
	CompletionTokens *int
	JSONValid        bool
	TopLevelType     string
	AppearsTruncated bool
}

type StructuredOutputInvalid struct {
	Metadata StructuredOutputMetadata
	Err      error
}

func (e *StructuredOutputInvalid) Error() string {
	return e.Err.Error()
}

func (e *StructuredOutputInvalid) Unwrap() error { return e.Err }

type StructuredOutputTruncated struct {
	Metadata StructuredOutputMetadata
}

func (e *StructuredOutputTruncated) Error() string {
	return fmt.Sprintf(
		"structured output was truncated (bytes=%d finish_reason=%q)",
		e.Metadata.Bytes,
		e.Metadata.FinishReason,
	)
}

type StructuredOutputTooLarge struct {
	Metadata StructuredOutputMetadata
	Limit    int
}

func (e *StructuredOutputTooLarge) Error() string {
	return fmt.Sprintf(
		"structured output exceeds %d-byte limit (bytes=%d)",
		e.Limit,
		e.Metadata.Bytes,
	)
}

func IsStructuredOutputSplitRequired(err error) bool {
	var truncated *StructuredOutputTruncated
	var tooLarge *StructuredOutputTooLarge
	return errors.As(err, &truncated) || errors.As(err, &tooLarge)
}

type SubmissionFormatError struct {
	Err error
}

func (e *SubmissionFormatError) Error() string {
	return e.Err.Error()
}

func (e *SubmissionFormatError) Unwrap() error {
	return e.Err
}

type SubmissionValidationError struct {
	Err error
}

func (e *SubmissionValidationError) Error() string {
	return e.Err.Error()
}

func (e *SubmissionValidationError) Unwrap() error {
	return e.Err
}

func NewSubmissionFormatError(err error) error {
	if err == nil {
		return nil
	}
	var existing *SubmissionFormatError
	if errors.As(err, &existing) {
		return err
	}
	return &SubmissionFormatError{Err: err}
}

func NewSubmissionValidationError(err error) error {
	if err == nil {
		return nil
	}
	var existing *SubmissionValidationError
	if errors.As(err, &existing) {
		return err
	}
	return &SubmissionValidationError{Err: err}
}

func IsSubmissionFormatError(err error) bool {
	var target *SubmissionFormatError
	return errors.As(err, &target)
}
