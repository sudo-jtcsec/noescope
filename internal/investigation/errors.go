package investigation

import "errors"

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
