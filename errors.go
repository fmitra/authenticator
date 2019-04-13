package auth

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
)

const (
	// ECInternal represents an internal error.
	ECInternal = "internal"
	// ECTokenRevoked represents a token revocation error.
	ECTokenRevoked = "token_revoked"
	// ECTokenInvalid represents an invalid JWT token error.
	ECTokenInvalid = "token_invalid"
)

var (
	// ErrTokenInvalid is returned when an invalid JWT token
	// is submitted for validation. Invalid tokens may be
	// improperly signed or expired.
	ErrTokenInvalid = &Error{
		Code:    ECTokenInvalid,
		Message: "Token is invalid",
	}
	// ErrTokenRevoked is a returned when a JWT token validation
	// fails due to revocation.
	ErrTokenRevoked = &Error{
		Code:    ECTokenRevoked,
		Message: "Token has been revoked",
	}
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

// WithError sets error context to a domain error.
func (e *Error) WithError(err error) *Error {
	if err == nil {
		return e
	}

	newErr := *e
	if newErr.Err == nil {
		newErr.Err = err
	} else {
		newErr.Err = errors.Wrap(newErr.Err, err.Error())
	}
	return &newErr
}

// WithMessage sets a human-readable message to a domain error.
// Messages are safe to be consumed by a public API.
func (e *Error) WithMessage(msg string) *Error {
	newErr := *e
	newErr.Message = msg
	return &newErr
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
	return ECInternal
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
