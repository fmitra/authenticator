package msgconsumer

import (
	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// defaultWorkers represents the default number of workers to process a queue.
const defaultWorkers = 4

// NewService returns a new Consumer
func NewService(r auth.MessageRepository, smsLib auth.SMSer, emailLib auth.Emailer, options ...ConfigOption) Consumer {
	s := service{
		logger:       log.NewNopLogger(),
		totalWorkers: defaultWorkers,
		messageRepo:  r,
		smsLib:       smsLib,
		emailLib:     emailLib,
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

// WithWorkers determines the total number of workers to process
// a message queue.
func WithWorkers(w int) ConfigOption {
	return func(s *service) {
		s.totalWorkers = w
	}
}
