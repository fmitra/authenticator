package password

import (
	"golang.org/x/crypto/bcrypt"

	auth "github.com/fmitra/authenticator"
)

const (
	defaultCost      = bcrypt.DefaultCost
	defaultMinLength = 8
	defaultMaxLength = 1000
)

// NewPassword returns a new password validator.
func NewPassword(options ...ConfigOption) auth.PasswordService {
	s := Password{
		cost:      defaultCost,
		minLength: defaultMinLength,
		maxLength: defaultMaxLength,
	}

	for _, opt := range options {
		opt(&s)
	}

	return &s
}

// ConfigOption configures the validator.
type ConfigOption func(*Password)

// WithCost configures the service with a cost.
func WithCost(cost int) ConfigOption {
	return func(s *Password) {
		s.cost = cost
	}
}

// WithMinLength sets a minimum password length.
func WithMinLength(length int) ConfigOption {
	return func(s *Password) {
		s.minLength = length
	}
}

// WithMaxLength sets a maximum password length.
func WithMaxLength(length int) ConfigOption {
	return func(s *Password) {
		s.maxLength = length
	}
}
