// Package deviceapi provides an HTTP API for device registration.
package deviceapi

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

type service struct {
	logger   log.Logger
	webauthn auth.WebAuthnService
	repoMngr auth.RepositoryManager
}

// Create is an initial request to add a new Device for a User.
func (s *service) Create(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID, err := httpapi.GetUserID(r)
	if err != nil {
		return nil, err
	}

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	return s.webauthn.BeginSignUp(ctx, user)
}

// Verify validates ownership of a new Device for a User.
func (s *service) Verify(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID, err := httpapi.GetUserID(r)
	if err != nil {
		return nil, err
	}

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	err = s.webauthn.FinishLogin(ctx, user, r)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// Remove removes a Device associated with a User.
func (s *service) Remove(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	// TODO Implement this in device repo. While you're at it
	// it makes sense to allow querying by client ID for updates
	return nil, errors.New("not implemented")
}
