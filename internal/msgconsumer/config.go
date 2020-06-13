package msgconsumer

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

// New returns a new Consumer
func New(ctx context.Context, smsLib SMSer, emailLib Emailer, options ...ConfigOption) (Consumer, error) {
	s := service{
		logger:       log.NewNopLogger(),
		totalWorkers: defaultWorkers,
		emailLimit:   defaultEmailLimit,
		smsLimit:     defaultSMSLimit,
		messageQueue: make(chan *auth.Message),
		smsLib:       smsLib,
		emailLib:     emailLib,
	}

	for _, opt := range options {
		if err := opt(&s); err != nil {
			return nil, err
		}
	}

	return &s, nil
}

// ConfigOption configures the service.
type ConfigOption func(*service) error

// WithLogger configures the service with a logger.
func WithLogger(l log.Logger) ConfigOption {
	return func(s *service) error {
		s.logger = l
		return nil
	}
}

// WithWorkers determines the total number of workers to process
// a message queue.
func WithWorkers(w int) ConfigOption {
	return func(s *service) error {
		s.totalWorkers = w
		return nil
	}
}

// WithSMSLimit sets a limit for the max amount of SMS messages we may send
// at a time.
func WithSMSLimit(limit string) ConfigOption {
	return func(s *service) error {
		if _, _, err := parseThrottle(limit); err != nil {
			return err
		}

		s.smsLimit = limit
		return nil
	}
}

// WithEmailLimit sets a limit for the max amount of email messages we may send
// at a time.
func WithEmailLimit(limit string) ConfigOption {
	return func(s *service) error {
		if _, _, err := parseThrottle(limit); err != nil {
			return err
		}

		s.emailLimit = limit
		return nil
	}
}
