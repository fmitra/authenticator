package mail

import (
	"context"
	"net/smtp"
	"testing"
)

func TestMail_SendsEmail(t *testing.T) {
	mailSvc := NewService(WithConfig(Config{
		serverAddr: "localhost:8000",
		fromAddr:   "test@test.com",
		auth:       smtp.PlainAuth("identity", "username", "password", "host"),
		mailFn: func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
			return nil
		},
	}))
	ctx := context.Background()
	if err := mailSvc.Email(ctx, "jane@example.com", "hello world"); err != nil {
		t.Error("expected nil error, received:", err)
	}
}
