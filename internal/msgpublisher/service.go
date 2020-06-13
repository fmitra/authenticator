// Package msgpublisher writes SMS/Email messages to Kafka.
package msgpublisher

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// service is an implementation of auth.MessagingService.
// It uses the Twilio API to send messages.
type service struct {
	logger      log.Logger
	messageRepo auth.MessageRepository
	expireAfter time.Duration
}

// Send sends a message to a User. Behind the scenes, it publishes a message
// to a Kafka topic with all the relevant user details for delivery (e.g. phone/email).
func (s *service) Send(ctx context.Context, user *auth.User, content string) error {
	deliveryMethod := auth.Phone
	if !user.Phone.Valid {
		deliveryMethod = auth.Email
	}

	msg := auth.Message{
		Delivery:  deliveryMethod,
		Content:   content,
		Address:   user.Phone.String,
		ExpiresAt: time.Now().Add(s.expireAfter),
	}

	if err := s.messageRepo.Publish(ctx, &msg); err != nil {
		return fmt.Errorf("failed to publish to repository: %w", err)
	}

	return nil
}
