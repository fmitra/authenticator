// Package msgrepo provides message storage for consumers and publishers.
package msgrepo

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// service is an implementation of auth.MessageRepository
type service struct {
	logger       log.Logger
	messageQueue chan *auth.Message
}

// Publish writes an unsent message to a channel.
func (s *service) Publish(ctx context.Context, msg *auth.Message) error {
	isExpired := time.Now().After(msg.ExpiresAt)
	if isExpired {
		return fmt.Errorf("cannot publish expired message")
	}

	go func() {
		countdown := time.Duration(msg.DeliveryAttempts) * time.Second
		msg.DeliveryAttempts++

		time.Sleep(countdown)
		s.messageQueue <- msg
	}()

	return nil
}

// Recent retrieves recently published unsent messages.
func (s *service) Recent(ctx context.Context) (<-chan *auth.Message, <-chan error) {
	errc := make(chan error, 1)

	go func() {
		defer close(errc)
		defer close(s.messageQueue)
		<-ctx.Done()
		errc <- ctx.Err()
	}()

	return s.messageQueue, errc
}
