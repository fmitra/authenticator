// Package tokenapi provides an HTTP API for managing JWT tokens.
package tokenapi

import (
	"net/http"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

type service struct {
	logger   log.Logger
	token    auth.TokenService
	repoMngr auth.RepositoryManager
}

// Revoke revokes a User's token for a logged in session. Revoked tokens may not be
// refreshed.
func (s *service) Revoke(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, nil
}

// Verify check's if a User's header credentials (token and matching client ID) are valid.
func (s *service) Verify(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, nil
}

// Refresh refreshes an expired token with a new expiry time. Refresh tokens share
// a token's original ID and client ID.
func (s *service) Refresh(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, nil
}
