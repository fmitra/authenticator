package mail

import (
	"context"
	"net/smtp"
)

// Emailer exposes an API to send email messages.
type Emailer interface {
	Email(ctx context.Context, email string, message string) error
}

type service struct {
	serverAddr string
	fromAddr   string
	auth       smtp.Auth
	mailFn     func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// Email delivers an email to an email address.
func (s *service) Email(ctx context.Context, email string, message string) error {
	content := []byte(message)
	return s.mailFn(s.serverAddr, s.auth, s.fromAddr, []string{email}, content)
}
