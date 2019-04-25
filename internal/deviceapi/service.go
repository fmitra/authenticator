// Package deviceapi provides an HTTP API for device registration.
package deviceapi

import (
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/log"

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
	userID := httpapi.GetUserID(r)

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	return s.webauthn.BeginSignUp(ctx, user)
}

// Verify validates ownership of a new Device for a User.
func (s *service) Verify(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	_, err = s.webauthn.FinishSignUp(ctx, user, r)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// Remove removes a Device associated with a User.
func (s *service) Remove(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	var request map[string]string
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		return nil, auth.ErrBadRequest("invalid request format")
	}

	deviceID := request["deviceID"]
	if deviceID == "" {
		return nil, auth.ErrInvalidField("missing deviceID")
	}

	err = s.repoMngr.Device().Remove(ctx, deviceID, userID)
	if err != nil {
		return nil, err
	}

	return nil, nil
}
