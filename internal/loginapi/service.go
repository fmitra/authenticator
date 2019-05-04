// Package loginapi provides an HTTP API for user authentication.
package loginapi

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
)

type service struct {
	logger   log.Logger
	token    auth.TokenService
	repoMngr auth.RepositoryManager
	otp      auth.OTPService
	webauthn auth.WebAuthnService
	message  auth.MessagingService
}

// Login is the initial login step to identify a User.
func (s *service) Login(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, errors.New("not implemented")
}

// VerifyDevice verifies a User's authenticity through a signing device.
func (s *service) VerifyDevice(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, errors.New("not implemented")
}

// VerifyCode verifies a User's authenticity through a validating TOTP or
// randomly generated code.
func (s *service) VerifyCode(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, errors.New("not implemented")
}
