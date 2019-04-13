package authenticator

import (
	"fmt"

	"github.com/pkg/errors"
)

const (
	// EInvalidToken represents an invalid JWT token error.
	EInvalidToken ErrCode = "invalid_token"
	// EInvalidField represents an entity field error in a repository.
	EInvalidField ErrCode = "invalid_field"
	// EInternal represents an internal error outside of our domain.
	EInternal ErrCode = "internal"
)

// Error represents an error within the authenticator domain.
type Error interface {
	Error() string
	Code() ErrCode
}

// ErrCode is a machine readable code representing
// an error within the authenticator domain.
type ErrCode string

// ErrInvalidToken represents an error related to JWT token invalidation
// such as expiry, revocation, or signing errors.
type ErrInvalidToken string

func (e ErrInvalidToken) Code() ErrCode { return EInvalidToken }
func (e ErrInvalidToken) Error() string { return fmt.Sprintf("[%s] %s", e.Code(), string(e)) }

// ErrInvalidField represents an error related to missing or invalid entity fields
// in a supplied to repository.
type ErrInvalidField string

func (e ErrInvalidField) Code() ErrCode { return EInvalidField }
func (e ErrInvalidField) Error() string { return fmt.Sprintf("[%s] %s", e.Code(), string(e)) }

// DomainError returns a domain error if available.
func DomainError(err error) Error {
	if err == nil {
		return nil
	}

	if e, ok := err.(Error); ok {
		return e
	}

	if e, ok := errors.Cause(err).(Error); ok {
		return e
	}

	return nil
}

// ErrorCode returns the code associated with a domain error.
// If an error is not part of the authenticator domain, it
// returns Internal.
func ErrorCode(err error) ErrCode {
	if err == nil {
		return ErrCode("")
	}

	e := DomainError(err)
	if e == nil {
		return EInternal
	}

	return e.Code()
}
