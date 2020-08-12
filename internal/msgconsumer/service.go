// Package msgconsumer reads and sends SMS/Email messages from a repository.
package msgconsumer

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	auth "github.com/fmitra/authenticator"
)

// Consumer reads a message stream from a repository.
type Consumer interface {
	Run(ctx context.Context) error
}

// Service consumes messages to be delivered in a parallel through
// goroutines.
type service struct {
	logger       log.Logger
	smsLib       auth.SMSer
	emailLib     auth.Emailer
	totalWorkers int
	messageRepo  auth.MessageRepository
}

// Run retrieves recent messages from the repository and passes
// them into a channel to be consumed by goroutines.
func (s *service) Run(ctx context.Context) error {
	msgc, errc := s.messageRepo.Recent(ctx)

	s.startWorkers(ctx, msgc)

	for {
		select {
		case err := <-errc:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// startWorkers starts a finite number of workers to deliver messages found
// in the message queue.
func (s *service) startWorkers(ctx context.Context, msgc <-chan *auth.Message) {
	for i := 0; i < s.totalWorkers; i++ {
		go func() {
			for msg := range msgc {
				s.processMessage(ctx, msg)
			}
		}()
	}
}

// processMessage delivers a message through email or SMS.
func (s *service) processMessage(ctx context.Context, msg *auth.Message) {
	logger := log.With(
		s.logger,
		"source", "msgconsumer.processMessage",
		"address", msg.Address,
		"delivery", msg.Delivery,
		"type", msg.Type,
		"delivery_attempts", msg.DeliveryAttempts,
		"expires_at", msg.ExpiresAt,
	)
	isExpired := time.Now().After(msg.ExpiresAt)

	if isExpired {
		level.Info(logger).Log("message", "dropping expired message")
		return
	}

	var err error
	if msg.Delivery == auth.Phone {
		err = s.smsLib.SMS(ctx, msg.Address, msg.Content)
	} else if msg.Delivery == auth.Email {
		err = s.emailLib.Email(ctx, msg.Address, msg.Content)
	}

	if err == nil {
		level.Info(logger).Log("message", "message sent")
		// Enable in config.json: api.debug
		level.Debug(logger).Log(
			"content", msg.Content,
			"message", "message contents",
		)
		return
	}

	// Continue to retry the message until expiry.
	level.Info(logger).Log("message", "retrying message", "error", err)

	if err := s.messageRepo.Publish(ctx, msg); err != nil {
		level.Info(logger).Log(
			"message",
			"failed to retry message",
			"error",
			err,
		)
	} else {
		level.Info(logger).Log(
			"message", "message sent back to queue",
		)
	}
}
