package otp

import (
	auth "github.com/fmitra/authenticator"
)

const (
	defaultLength = 6
)

// NewOTP returns a new OTP validator.
func NewOTP(options ...ConfigOption) auth.OTPService {
	s := OTP{
		codeLength: defaultLength,
	}

	for _, opt := range options {
		opt(&s)
	}

	return &s
}

// ConfigOption configures the validator
type ConfigOption func(*OTP)

// WithCodeLength configures th service with a length
// for random code generation.
func WithCodeLength(length int) ConfigOption {
	return func(s *OTP) {
		s.codeLength = length
	}
}
