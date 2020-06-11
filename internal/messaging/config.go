package messaging

import (
	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// NewService returns a new implementation of auth.MessagingService.
func NewService(options ...ConfigOption) auth.MessagingService {
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

// WithSMSLib configures the service with a SMS sending library.
func WithSMSLib(lib SMSer) ConfigOption {
	return func(s *service) {
		s.smsLib = lib
	}
}

// WithEmailLib configures the service with an email sending library.
func WithEmailLib(lib Emailer) ConfigOption {
	return func(s *service) {
		s.emailLib = lib
	}
}
