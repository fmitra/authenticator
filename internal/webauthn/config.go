package webauthn

import (
	webauthnLib "github.com/duo-labs/webauthn/webauthn"

	auth "github.com/fmitra/authenticator"
)

// NewService returns a new WebAuthn validator.
func NewService(options ...ConfigOption) (auth.WebAuthnService, error) {
	s := WebAuthn{}

	for _, opt := range options {
		opt(&s)
	}

	lib, err := webauthnLib.New(&webauthnLib.Config{
		RPDisplayName: s.displayName,
		RPID:          s.domain,
		RPOrigin:      s.requestOrigin,
	})
	if err != nil {
		return nil, err
	}

	s.lib = lib

	return &s, nil
}

// ConfigOption configures the validator.
type ConfigOption func(*WebAuthn)

// WithDB configures the service with a redis DB
func WithDB(db rediser) ConfigOption {
	return func(s *WebAuthn) {
		s.db = db
	}
}

// WithDisplayName configures the validator with a display name.
func WithDisplayName(name string) ConfigOption {
	return func(s *WebAuthn) {
		s.displayName = name
	}
}

// WithDomain configures the validator with a domain name.
func WithDomain(domain string) ConfigOption {
	return func(s *WebAuthn) {
		s.domain = domain
	}
}

// WithRequestOrigin configures the validator with a request origin.
func WithRequestOrigin(origin string) ConfigOption {
	return func(s *WebAuthn) {
		s.requestOrigin = origin
	}
}

// WithRepoManager configures the service with a new RepositoryManager.
func WithRepoManager(repoMngr auth.RepositoryManager) ConfigOption {
	return func(s *WebAuthn) {
		s.repoMngr = repoMngr
	}
}
