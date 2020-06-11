// Package loginapi provides an HTTP API for user authentication.
package loginapi

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

type service struct {
	logger   log.Logger
	token    auth.TokenService
	repoMngr auth.RepositoryManager
	otp      auth.OTPService
	password auth.PasswordService
	webauthn auth.WebAuthnService
	message  auth.MessagingService
}

// Login is the initial login step to identify a User.
func (s *service) Login(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()

	req, err := decodeLoginRequest(r)
	if err != nil {
		return nil, err
	}

	user, err := s.repoMngr.User().ByIdentity(ctx, req.UserAttribute(), req.Identity)
	if err == sql.ErrNoRows {
		return nil, errors.Wrap(auth.ErrBadRequest("invalid username or password"), err.Error())
	}
	if err != nil {
		return nil, err
	}

	if err = s.password.Validate(user, req.Password); err != nil {
		return nil, errors.Wrap(auth.ErrBadRequest("invalid username or password"), err.Error())
	}

	jwtToken, err := s.token.Create(ctx, user, auth.JWTPreAuthorized)
	if err != nil {
		return nil, err
	}

	return s.respond(ctx, w, user, jwtToken)
}

// DeviceChallenge requests a challenge to be signed by the client.
// This is a pre step in order to verify a User's Device.
func (s *service) DeviceChallenge(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	return s.webauthn.BeginLogin(ctx, user)
}

// VerifyDevice verifies a User's authenticity through a signing device.
func (s *service) VerifyDevice(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	err = s.webauthn.FinishLogin(ctx, user, r)
	if err != nil {
		return nil, err
	}

	jwtToken, err := s.token.Create(ctx, user, auth.JWTAuthorized)
	if err != nil {
		return nil, err
	}

	loginHistory := &auth.LoginHistory{
		UserID:    userID,
		TokenID:   jwtToken.Id,
		ExpiresAt: time.Unix(jwtToken.ExpiresAt, 0),
	}
	if err = s.repoMngr.LoginHistory().Create(ctx, loginHistory); err != nil {
		return nil, err
	}

	return s.respond(ctx, w, user, jwtToken)
}

// VerifyCode verifies a User's authenticity through a validating TOTP or
// randomly generated code.
func (s *service) VerifyCode(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)
	token := httpapi.GetToken(r)

	req, err := decodeVerifyCodeRequest(r)
	if err != nil {
		return nil, err
	}

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	if err = s.otp.Validate(user, req.Code, token.CodeHash); err != nil {
		return nil, err
	}

	jwtToken, err := s.token.Create(ctx, user, auth.JWTAuthorized)
	if err != nil {
		return nil, err
	}

	loginHistory := &auth.LoginHistory{
		UserID:    userID,
		TokenID:   jwtToken.Id,
		ExpiresAt: time.Unix(jwtToken.ExpiresAt, 0),
	}
	if err = s.repoMngr.LoginHistory().Create(ctx, loginHistory); err != nil {
		return nil, err
	}

	return s.respond(ctx, w, user, jwtToken)
}

// respond creates a JWT token response.
func (s *service) respond(ctx context.Context, w http.ResponseWriter, user *auth.User, jwtToken *auth.Token) ([]byte, error) {
	tokenStr, err := s.token.Sign(ctx, jwtToken)
	if err != nil {
		return nil, err
	}

	http.SetCookie(w, s.token.Cookie(ctx, jwtToken))

	if jwtToken.Code != "" {
		s.message.Queue(ctx, user, jwtToken.Code)
	}

	return []byte(fmt.Sprintf(`
		{"token": "%s", "clientID": "%s"}
	`, tokenStr, jwtToken.ClientID)), nil
}
