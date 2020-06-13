package msgpublisher

import (
	"time"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// defaultExpiry is the default expiry time for a message to be published.
const defaultExpiry = time.Minute * 10

// NewService returns a new implementation of auth.MessagingService.
func NewService(r auth.MessageRepository, options ...ConfigOption) auth.MessagingService {
	s := service{
		messageRepo: r,
		expireAfter: defaultExpiry,
		logger:      log.NewNopLogger(),
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

// WithExpiry sets an expiry time for a message to complete sending.
func WithExpiry(t time.Duration) ConfigOption {
	return func(s *service) {
		s.expireAfter = t
	}
}
