// Package signupapi provides an HTTP API for user registration.
package signupapi

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

func (s *service) SignUp(w http.ResponseWriter, r * http.Request) {
}

func (s *service) Verify(w http.ResponseWriter, r *http.Request) {
}
