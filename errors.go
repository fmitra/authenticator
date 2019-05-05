package authenticator

import (
	"fmt"

	"github.com/pkg/errors"
)

const (
	// EInvalidToken represents an invalid JWT token error.
	EInvalidToken ErrCode = "invalid_token"
	// EInvalidCode represents an invalid OTP code.
	EInvalidCode ErrCode = "invalid_code"
	// EInvalidField represents an entity field error in a repository.
	EInvalidField ErrCode = "invalid_field"
	// EInternal represents an internal error outside of our domain.
	EInternal ErrCode = "internal"
	// EBadRequest represents a bad JSON request body.
	EBadRequest ErrCode = "bad_request"
	// ENotFound represents a non existent entity.
	ENotFound ErrCode = "not_found"
	// EWebAuthn represents a webauthn authentication error.
	EWebAuthn ErrCode = "webauthn"
)

// Error represents an error within the authenticator domain.
type Error interface {
	Error() string
	Message() string
	Code() ErrCode
}

// ErrCode is a machine readable code representing
// an error within the authenticator domain.
type ErrCode string

// ErrInvalidCode represents an error related to an invalid TOTP/OTP code.
type ErrInvalidCode string

func (e ErrInvalidCode) Code() ErrCode   { return EInvalidCode }
func (e ErrInvalidCode) Error() string   { return fmt.Sprintf("[%s] %s", e.Code(), string(e)) }
func (e ErrInvalidCode) Message() string { return string(e) }

// ErrInvalidToken represents an error related to JWT token invalidation
// such as expiry, revocation, or signing errors.
type ErrInvalidToken string

func (e ErrInvalidToken) Code() ErrCode   { return EInvalidToken }
func (e ErrInvalidToken) Error() string   { return fmt.Sprintf("[%s] %s", e.Code(), string(e)) }
func (e ErrInvalidToken) Message() string { return string(e) }

// ErrInvalidField represents an error related to missing or invalid entity fields.
type ErrInvalidField string

func (e ErrInvalidField) Code() ErrCode   { return EInvalidField }
func (e ErrInvalidField) Error() string   { return fmt.Sprintf("[%s] %s", e.Code(), string(e)) }
func (e ErrInvalidField) Message() string { return string(e) }

// ErrBadRequest represents an error where we fail to read a JSON requst body.
type ErrBadRequest string

func (e ErrBadRequest) Code() ErrCode   { return EBadRequest }
func (e ErrBadRequest) Error() string   { return fmt.Sprintf("[%s] %s", e.Code(), string(e)) }
func (e ErrBadRequest) Message() string { return string(e) }

// ErrNotFound represents an error where we fail to read a JSON requst body.
type ErrNotFound string

func (e ErrNotFound) Code() ErrCode   { return ENotFound }
func (e ErrNotFound) Error() string   { return fmt.Sprintf("[%s] %s", e.Code(), string(e)) }
func (e ErrNotFound) Message() string { return string(e) }

// ErrWebAuthn represents an error related to webauthn authentication.
type ErrWebAuthn string

func (e ErrWebAuthn) Code() ErrCode   { return EWebAuthn }
func (e ErrWebAuthn) Error() string   { return fmt.Sprintf("[%s] %s", e.Code(), string(e)) }
func (e ErrWebAuthn) Message() string { return string(e) }

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
