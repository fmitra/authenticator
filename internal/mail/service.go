package mail

import (
	"context"
	"fmt"
	"net/smtp"
)

type service struct {
	serverAddr string
	fromAddr   string
	auth       smtp.Auth
	mailFn     func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// Email delivers an email to an email address.
func (s *service) Email(ctx context.Context, email, subject, message string) error {
	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";"
	content := []byte(
		fmt.Sprintf("To: %s\r\n", email) +
			fmt.Sprintf("Subject: %s\r\n", subject) +
			fmt.Sprintf("%s\n\n", mimeHeaders) +
			message,
	)
	return s.mailFn(s.serverAddr, s.auth, s.fromAddr, []string{email}, content)
}
