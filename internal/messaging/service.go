package messaging

import (
	"context"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// SMSer exposes an API to send SMS messages.
type SMSer interface {
	SMS(ctx context.Context, phoneNumber string, message string) error
}

// Emailer exposes an API to send email messages.
type Emailer interface {
	Email(ctx context.Context, email string, message string)
}

// service is an implementation of auth.MessagingService.
// It uses the Twilio API to send messages.
type service struct {
	logger   log.Logger
	smsLib   SMSer
	emailLib Emailer
}

// Queue queues a message to be delivered to a User.
func (s *service) Queue(ctx context.Context, user *auth.User, message string) {
}

// Send sends a message to a User.
func (s *service) Send(ctx context.Context, user *auth.User, message string) {
}
