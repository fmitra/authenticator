package msgrepo

import (
	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// NewService returns a new MessageRepository
func NewService(options ...ConfigOption) auth.MessageRepository {
	s := service{
		logger:       log.NewNopLogger(),
		messageQueue: make(chan *auth.Message),
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
