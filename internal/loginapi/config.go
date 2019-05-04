package loginapi

import (
	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// NewService returns a new implementation of auth.LoginAPI.
func NewService(options ...ConfigOption) auth.LoginAPI {
	s := service{
		logger: log.NewNopLogger(),
	}

	for _, opt := range options {
		opt(&s)
	}

	return &s
}

// ConfigOption configures the service.
type ConfigOption func(*service)

// WithLogger configures the service with a logger.
func WithLogger(l log.Logger) ConfigOption {
	return func(s *service) {
		s.logger = l
	}
}

// WithTokenService configures the service with a new TokenService.
func WithTokenService(tokenSvc auth.TokenService) ConfigOption {
	return func(s *service) {
		s.token = tokenSvc
	}
}

// WithRepoManager configures the service with a new RepositoryManager.
func WithRepoManager(repoMngr auth.RepositoryManager) ConfigOption {
	return func(s *service) {
		s.repoMngr = repoMngr
	}
}

// WithWebAuthn configures the service with a WebAuthn library.
func WithWebAuthn(w auth.WebAuthnService) ConfigOption {
	return func(s *service) {
		s.webauthn = w
	}
}

// WithOTP configures the service with an OTP validator.
func WithOTP(o auth.OTPService) ConfigOption {
	return func(s *service) {
		s.otp = o
	}
}

// WithMessaging configures the service with a MessagingService.
func WithMessaging(m auth.MessagingService) ConfigOption {
	return func(s *service) {
		s.message = m
	}
}

// WithPassword configures the servicewith a PasswordService.
func WithPassword(p auth.PasswordService) ConfigOption {
	return func(s *service) {
		s.password = p
	}
}
