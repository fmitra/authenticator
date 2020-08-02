// Package msgpublisher publishes outgoing SMS/Email messages.
package msgpublisher

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/contactchecker"
)

// service is an implementation of auth.MessagingService.
type service struct {
	logger      log.Logger
	messageRepo auth.MessageRepository
	expireAfter time.Duration
}

// Send sends a message to a User. Behind the scenes, a message is stored
// in the MessageRepository to be consumed by a separate service.
func (s *service) Send(ctx context.Context, content, addr string, method auth.DeliveryMethod) error {
	if !contactchecker.Validator(method)(addr) {
		return fmt.Errorf("invalid message delivery method")
	}

	msg := auth.Message{
		Delivery:  method,
		Content:   content,
		Address:   addr,
		ExpiresAt: time.Now().Add(s.expireAfter),
	}

	if err := s.messageRepo.Publish(ctx, &msg); err != nil {
		return fmt.Errorf("failed to publish to repository: %w", err)
	}

	return nil
}
