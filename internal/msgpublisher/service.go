// Package msgpublisher publishes outgoing SMS/Email messages.
package msgpublisher

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/contactchecker"
)

// service is an implementation of auth.MessagingService.
type service struct {
	logger         log.Logger
	messageRepo    auth.MessageRepository
	expireAfter    time.Duration
	smsTemplates   map[auth.MessageType]string
	emailTemplates map[auth.MessageType]string
	subjects       map[auth.MessageType]string
}

// Send sends a message to a User. Behind the scenes, a message is stored
// in the MessageRepository to be consumed by a separate service.
func (s *service) Send(ctx context.Context, msg *auth.Message) error {
	if !contactchecker.Validator(msg.Delivery)(msg.Address) {
		return fmt.Errorf("invalid message delivery method")
	}

	if err := s.setMessageFields(msg); err != nil {
		return err
	}

	if err := s.messageRepo.Publish(ctx, msg); err != nil {
		return fmt.Errorf("failed to publish to repository: %w", err)
	}

	return nil
}

func (s *service) setMessageFields(msg *auth.Message) error {
	msg.ExpiresAt = time.Now().Add(s.expireAfter)

	// Message content was set by caller. Do not overwrite.
	if msg.Content != "" {
		return nil
	}

	template := s.template(msg.Type, msg.Delivery)
	if template == "" {
		return fmt.Errorf("no template set for %s", msg.Type)
	}

	for k, v := range msg.Vars {
		k = fmt.Sprintf("{{%s}}", k)
		template = strings.Replace(template, k, v, -1)
	}

	if strings.Contains(template, "{{") || strings.Contains(template, "}}") {
		return fmt.Errorf("all variables not set for template: %s", template)
	}

	msg.Content = template
	msg.Subject = s.subjects[msg.Type]
	return nil
}

func (s *service) template(t auth.MessageType, d auth.DeliveryMethod) string {
	if d == auth.Phone {
		return s.smsTemplates[t]
	}

	if d == auth.Email {
		return s.emailTemplates[t]
	}

	return ""
}

func (s *service) createTemplates() {
	s.smsTemplates = map[auth.MessageType]string{
		auth.OTPLogin:   "Your login code is {{code}}",
		auth.OTPSignup:  "Your signup code is {{code}}",
		auth.OTPResend:  "Youre new code is {{code}}",
		auth.OTPAddress: "Use the code {{code}} to verify your new contact address",
	}

	s.emailTemplates = map[auth.MessageType]string{
		auth.OTPLogin: `
			<span>Code: <strong>{{code}}</strong></span>
			<p>Enter the code above to login</p>
		`,
		auth.OTPSignup: `
			<span>Code: <strong>{{code}}</strong></span>
			<p>Enter the code above to signup</p>
		`,
		auth.OTPResend: `
			<span>Here's your new code</span>
			<p>Code: <strong>{{code}}</strong></p>
		`,
		auth.OTPAddress: `
			<span>Code: <strong>{{code}}</strong></span>
			<p>Enter the code above to verify your new contact address</p>
		`,
	}

	s.subjects = map[auth.MessageType]string{
		auth.OTPAddress: "Verify your contact details",
		auth.OTPLogin:   "Your login verification code",
		auth.OTPResend:  "You've requested a new verification code",
		auth.OTPSignup:  "Your signup verification code",
	}
}
