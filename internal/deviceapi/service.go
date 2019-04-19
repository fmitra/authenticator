// Package deviceapi provides an HTTP API for device registration.
package deviceapi

import (
	"net/http"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

type service struct {
	logger   log.Logger
	webauthn auth.WebAuthnService
	repoMngr auth.RepositoryManager
}

// Create is an initial request to add a new Device for a User.
func (s *service) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := ctx.Value("userID").(string)
	if !ok {
		// TODO Internal error response. User ID should
		// have been set in authentication middleware
		return
	}

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		// TODO Bad request domain error
		return
	}

	// NOTE The webauthn serviec will manage persisting the session. We
	// dont want to worry about it in the device api.
	_, err = s.webauthn.BeginSignUp(ctx, user)
	if err != nil {
		// TODO new domain error for webauthn registration
		return
	}

	// TODO Parse bytes to json and return to user
	// { token: "", publicKey: "" }
}

// Verify validates ownership of a new Device for a User.
func (s *service) Verify(w http.ResponseWriter, r *http.Request) {
}

// Remove removes a Device associated with a User.
func (s *service) Remove(w http.ResponseWriter, r *http.Request) {
}
