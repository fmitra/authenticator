// Package msgrepo provides message storage for consumers and publishers.
package msgrepo

import (
	"context"
	"fmt"
	"math/rand"
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
		msg.DeliveryAttempts++

		if msg.DeliveryAttempts == 1 {
			s.messageQueue <- msg
			return
		}

		waitTime := delay(msg.DeliveryAttempts)
		time.Sleep(waitTime)

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

// delay calculates the amount of time to wait before
// publishing a message back into the queue
func delay(deliveryAttempts int) time.Duration {
	rand.Seed(time.Now().UnixNano())

	// Maximum 3 second jitter
	// nolint:gosec // crypto/rand not necessary for jitter
	jitter := time.Duration(rand.Intn(3000)) * time.Millisecond
	minDelay := (time.Duration(deliveryAttempts) * time.Second) * 2
	countdown := jitter + minDelay
	maxCountdown := 30 * time.Second

	if countdown < maxCountdown {
		return countdown
	}

	return maxCountdown
}
