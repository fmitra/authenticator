package auth

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
)

const (
	// ErrInternal represents an internal error.
	ErrInternal = "internal"
	// ErrTokenInvalid represents an invalid JWT token error.
	ErrTokenInvalid = "token_invalid"
)

// Error represents an error within the authenticator's domain.
type Error struct {
	// Code is a machine-readable code.
	Code string
	// Message is a human-readable message for a public API.
	Message string
	// Err is a nested error.
	Err error
}

// Error returns an error message for internal consumption.
func (e *Error) Error() string {
	var buf bytes.Buffer

	if e.Code != "" {
		fmt.Fprintf(&buf, "[%s] ", e.Code)
	}

	if e.Message != "" {
		fmt.Fprintf(&buf, "(%s) ", e.Message)
	}

	if e.Err != nil {
		fmt.Fprintf(&buf, "%v", e.Err)
	}

	return buf.String()
}

// ErrorStack returns the error stack if available.
func ErrorStack(err error) string {
	if err == nil {
		return ""
	}

	if e, ok := err.(*Error); ok && e.Err != nil {
		return fmt.Sprintf("%+v", e.Err)
	}

	return fmt.Sprintf("%+v", err)
}

// ErrorCode recursively finds the first code available.
// If no code is available, it returns ErrInternal.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	if e, ok := err.(*Error); ok && e.Code != "" {
		return e.Code
	} else if ok && e.Err != nil {
		return ErrorCode(e.Err)
	}
	return ErrInternal
}

// ErrorMessage recursively finds the first message available.
// If no message is available, it returns a generic error message.
func ErrorMessage(err error) string {
	if err == nil {
		return ""
	} else if e, ok := err.(*Error); ok && e.Message != "" {
		return e.Message
	} else if ok && e.Err != nil {
		return ErrorMessage(e.Err)
	}
	return "An internal error has occured"
}

// DomainError returns a domain error if availabile.
func DomainError(err error) *Error {
	if e, ok := err.(*Error); ok {
		return e
	}

	if e, ok := errors.Cause(err).(*Error); ok {
		return e
	}

	return nil
}
