// Package signupapi provides an HTTP API for user registration.
package signupapi

import (
	"database/sql"
	"net/http"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

type service struct {
	logger   log.Logger
	token    auth.TokenService
	repoMngr auth.RepositoryManager
}

func (s *service) SignUp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, err := decodeSignupRequest(r)
	if err != nil {
		// TODO Internal or domain error response
		return
	}

	user, err := s.repoMngr.User().ByIdentity(ctx, req.UserAttribute(), req.Identity)
	if err == nil && user.IsVerified {
		// A verified user has been found
		// TODO To prevent user enumeration this should trigger
		// a password reset flow on the client. Until paassword reset
		// has been implemented, we will just return a general error
		return
	}

	if err == sql.ErrNoRows {
		// Safe to proceed
		// TODO Trigger SMS/Phone notification
		return
	}

	// In any other case we shoud raise an internal error
}

func (s *service) Verify(w http.ResponseWriter, r *http.Request) {
}
