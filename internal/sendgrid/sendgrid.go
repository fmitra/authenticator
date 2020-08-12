// Package sendgrid adapts sendgrid-go to our Email interface.
package sendgrid

import (
	"context"
	"fmt"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"

	auth "github.com/fmitra/authenticator"
)

type service struct {
	apiKey   string
	fromAddr string
	fromName string
}

// Email delivers an email to an email address.
func (s *service) Email(ctx context.Context, email, subject, message string) error {
	from := mail.NewEmail(s.fromName, s.fromAddr)
	to := mail.NewEmail("", email)
	msg := mail.NewSingleEmail(from, subject, to, message, message)
	client := sendgrid.NewSendClient(s.apiKey)
	resp, err := client.Send(msg)
	if err != nil {
		return fmt.Errorf("sendgrid client failed: %w", err)
	}

	ok := 202
	if resp.StatusCode != ok {
		return fmt.Errorf("sendgrid failure received: %s", resp.Body)
	}

	return nil
}

// NewClient returns a new Sendgrid client
func NewClient(apiKey, fromAddr, fromName string) auth.Emailer {
	return &service{
		apiKey:   apiKey,
		fromAddr: fromAddr,
		fromName: fromName,
	}
}
