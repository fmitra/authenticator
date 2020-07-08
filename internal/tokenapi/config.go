package tokenapi

import (
	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

// NewService returns a new implementation of auth.TokenAPI
func NewService(options ...ConfigOption) auth.TokenAPI {
	s := service{
		logger: log.NewNopLogger(),
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

// WithRepoManager configures the service with a new RepositoryManager.
func WithRepoManager(repoMngr auth.RepositoryManager) ConfigOption {
	return func(s *service) {
		s.repoMngr = repoMngr
	}
}

// WithTokenService configures the service with a TokenService.
func WithTokenService(t auth.TokenService) ConfigOption {
	return func(s *service) {
		s.token = t
	}
}
