package messaging

import (
	"context"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

const (
	// defaultWorkers represents the default number of workers to process a queue.
	defaultWorkers = 4
	// defaultEmailLimit the max amount of email messages we may send at a time.
	defaultEmailLimit = "5/s"
	// defaultSMSLimit is the max amount of SMS messages we may send at a time.
	defaultSMSLimit = "1/s"
)

// NewService returns a new implementation of auth.MessagingService.
func NewService(ctx context.Context, smsLib SMSer, emailLib Emailer, options ...ConfigOption) auth.MessagingService {
	s := service{
		smsLib:       smsLib,
		emailLib:     emailLib,
		totalWorkers: defaultWorkers,
		emailLimit:   defaultEmailLimit,
		smsLimit:     defaultSMSLimit,
		messageQueue: make(chan func()),
		logger:       log.NewNopLogger(),
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

// WithSMSLimit sets a limit for the max amount of SMS messages we may send
// at a time.
func WithSMSLimit(limit string) ConfigOption {
	// TODO Add validation and return an error if the format is invalid
	return func(s *service) {
		s.smsLimit = limit
	}
}

// WithEmailLimit sets a limit for the max amount of email messages we may send
// at a time.
func WithEmailLimit(limit string) ConfigOption {
	// TODO Add validation and return an error if the format is invalid
	return func(s *service) {
		s.emailLimit = limit
	}
}
