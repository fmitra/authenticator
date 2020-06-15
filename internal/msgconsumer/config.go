package msgconsumer

import (
	"context"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// defaultWorkers represents the default number of workers to process a queue.
const defaultWorkers = 4

// New returns a new Consumer
func New(ctx context.Context, r auth.MessageRepository, smsLib SMSer, emailLib Emailer, options ...ConfigOption) (Consumer, error) {
	s := service{
		logger:       log.NewNopLogger(),
		totalWorkers: defaultWorkers,
		messageQueue: make(chan *auth.Message),
		messageRepo:  r,
		smsLib:       smsLib,
		emailLib:     emailLib,
	}

	for _, opt := range options {
		if err := opt(&s); err != nil {
			return nil, err
		}
	}

	s.startWorkers(ctx)

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
