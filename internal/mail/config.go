package mail

import (
	"net/smtp"

	auth "github.com/fmitra/authenticator"
)

// NewService returns a new mailing service.
func NewService(configuration ConfigOption) auth.Emailer {
	s := service{}
	configuration(&s)
	return &s
}

// Config holds configuration options for the service.
type Config struct {
	serverAddr string
	fromAddr   string
	auth       smtp.Auth
	mailFn     func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// ConfigOption configures the service.
type ConfigOption func(*service)

// WithConfig configures the service with a Config.
func WithConfig(config Config) ConfigOption {
	return func(s *service) {
		s.serverAddr = config.serverAddr
		s.fromAddr = config.fromAddr
		s.auth = config.auth
		s.mailFn = config.mailFn
	}
}

// WithDefaults configures the service with a default
// mailer (net/smtp)
func WithDefaults(serverAddr, fromAddr string, auth smtp.Auth) ConfigOption {
	return func(s *service) {
		s.serverAddr = serverAddr
		s.fromAddr = fromAddr
		s.auth = auth
		s.mailFn = smtp.SendMail
	}
}
