package contactapi

import (
	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// NewService returns a new implementation of auth.ContactAPI
func NewService(options ...ConfigOption) auth.ContactAPI {
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

// WithOTP configures the service with an OTP management service.
func WithOTP(o auth.OTPService) ConfigOption {
	return func(s *service) {
		s.otp = o
	}
}

// WithRepoManager configures the service with a new RepositoryManager.
func WithRepoManager(repoMngr auth.RepositoryManager) ConfigOption {
	return func(s *service) {
		s.repoMngr = repoMngr
	}
}

// WithMessaging configures the service with a MessagingService.
func WithMessaging(m auth.MessagingService) ConfigOption {
	return func(s *service) {
		s.message = m
	}
}

// WithToken configures the service with a TokenService.
func WithToken(t auth.TokenService) ConfigOption {
	return func(s *service) {
		s.token = t
	}
}
