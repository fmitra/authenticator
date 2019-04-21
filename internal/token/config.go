package token

import (
	"io"
	"time"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

const defaultTokenExpiry = time.Minute * 20

// NewService returns a new TokenService.
func NewService(options ...ConfigOption) auth.TokenService {
	s := service{
		logger:      log.NewNopLogger(),
		tokenExpiry: defaultTokenExpiry,
		issuer:      auth.Issuer,
	}

	for _, opt := range options {
		opt(&s)
	}

	return &s
}

// ConfigOption configures the service.
type ConfigOption func(*service)

// WithLogger configures the service with a logger.
func WithLogger(l log.Logger) ConfigOption {
	return func(s *service) {
		s.logger = l
	}
}

// WithDB configures the service with a redis DB
func WithDB(db Rediser) ConfigOption {
	return func(s *service) {
		s.db = db
	}
}

// WithTokenExpiry defines how long tokens are valid for.
// The default value is 20 minutes.
func WithTokenExpiry(expiresIn time.Duration) ConfigOption {
	return func(s *service) {
		s.tokenExpiry = expiresIn
	}
}

// WithEntropy configures the client with random entropy
// for generating ULIDs.
func WithEntropy(entropy io.Reader) ConfigOption {
	return func(s *service) {
		s.entropy = entropy
	}
}

// WithSecret configures the client with a secret value
// for signing functions.
func WithSecret(secret string) ConfigOption {
	return func(s *service) {
		s.secret = []byte(secret)
	}
}

// WithIssuer is the issuer identity for the JWT
// token.
func WithIssuer(issuer string) ConfigOption {
	return func(s *service) {
		s.issuer = issuer
	}
}
