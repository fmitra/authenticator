// Package msgconsumer reads SMS/Email messages from Kafka.
package msgconsumer

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// Consumer reads a message stream from Kafka.
type Consumer interface {
	Run(ctx context.Context) error
}

// SMSer exposes an API to send SMS messages.
type SMSer interface {
	SMS(ctx context.Context, phoneNumber string, message string) error
}

// Emailer exposes an API to send email messages.
type Emailer interface {
	Email(ctx context.Context, email string, message string) error
}

// Service consumes messages from a Kafka topic into a channel
// to be delivered in parallel through goroutines.
type service struct {
	logger       log.Logger
	smsLib       SMSer
	emailLib     Emailer
	totalWorkers int
	messageQueue chan *auth.Message
	messageRepo  auth.MessageRepository
}

// Run retrieves recent messages from the repository and passes
// them into a channel to be consumed by goroutines.
func (s *service) Run(ctx context.Context) error {
	msgc, errc := s.messageRepo.Recent(ctx)

	for {
		select {
		case msg, ok := <-msgc:
			if !ok {
				msgc = nil
				continue
			}
			s.messageQueue <- msg
		case err := <-errc:
			if err != nil {
				return err
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// startWorkers starts a finite number of workers to deliver messages found
// in the message queue.
func (s *service) startWorkers(ctx context.Context) {
	for i := 0; i < s.totalWorkers; i++ {
		go func() {
			for msg := range s.messageQueue {
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
	)
	isExpired := time.Now().After(msg.ExpiresAt)

	if isExpired {
		logger.Log("message", "dropping expired message")
		return
	}

	var err error
	if msg.Delivery == auth.Phone {
		err = s.smsLib.SMS(ctx, msg.Address, msg.Content)
	} else if msg.Delivery == auth.Email {
		err = s.emailLib.Email(ctx, msg.Address, msg.Content)
	}

	if err == nil {
		return
	}

	// Continue to retry the message until expiry.
	logger.Log("message", "retrying message", "error", err)

	if err := s.messageRepo.Publish(ctx, msg); err != nil {
		logger.Log("message", "failed to retry message", "error", err)
	}
}
