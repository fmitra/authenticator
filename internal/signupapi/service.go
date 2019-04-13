// Package signupapi provides an HTTP API for user registration.
package signupapi

import (
	"context"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

type service struct {
	logger   log.Logger
	token    auth.TokenService
	repoMngr auth.RepositoryManager
}

func (s *service) BeginSignUp(ctx context.Context, user *auth.User) error {
	return nil
}

func (s *service) FinishSignUp(ctx context.Context, crednetial auth.Credential) error {
	return nil
}
