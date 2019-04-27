// Package signupapi provides an HTTP API for user registration.
package signupapi

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
)

type service struct {
	logger   log.Logger
	token    auth.TokenService
	repoMngr auth.RepositoryManager
}

func (s *service) SignUp(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()

	req, err := decodeSignupRequest(r)
	if err != nil {
		return nil, err
	}

	user, err := s.repoMngr.User().ByIdentity(ctx, req.UserAttribute(), req.Identity)
	if isUserVerified(user, err) {
		// TODO To prevent user enumeration this should trigger
		// the OTP step for password reset instead of the signup OTP
		// step. Until password reset has been implemented, we will just
		// return a general error.
		return nil, auth.ErrBadRequest("cannot register user")
	}

	if isUserNotVerified(user, err) {
		// A user may have started the registration process and fell off
		// before verifying ownership of the account. This user should
		// be reset (new credentials, timestamps, ID) and allowed to restart
		// the signup flow again.
		client, err := s.repoMngr.NewWithTransaction(ctx)
		if err != nil {
			return nil, err
		}

		entity, err := client.WithAtomic(func() (interface{}, error) {
			user, err := client.User().GetForUpdate(ctx, user.ID)
			if err != nil {
				return nil, err
			}

			if user.IsVerified {
				// Someone's manage the verify the account immediately
				// before we obtained a lock. When a password
				// reset flow is enabled, this should trigger OTP
				// to prevent user enumeration.
				return nil, auth.ErrBadRequest("cannot register user")
			}

			newUser := req.ToUser()
			user.Email = newUser.Email
			user.Phone = newUser.Phone
			user.Password = newUser.Password
			err = client.User().ReCreate(ctx, user)
			if err != nil {
				return nil, err
			}
			return user, nil
		})
		if err != nil {
			return nil, err
		}

		user = entity.(*auth.User)
	}

	if isUserNonExistent(user, err) {
		user = req.ToUser()
		err = s.repoMngr.User().Create(ctx, user)
		if err != nil {
			return nil, err
		}
	}

	if isOTPNotAllowed(err) {
		return nil, err
	}

	jwtToken, clientID, err := s.token.Create(ctx, user, auth.JWTPreAuthorized)
	if err != nil {
		return nil, err
	}

	tokenStr, err := s.token.Sign(ctx, jwtToken)
	if err != nil {
		return nil, err
	}

	// TODO Trigger OTP messaging
	return []byte(fmt.Sprintf(`
		{"token": "%s", "clientID": "%s"}
	`, tokenStr, clientID)), nil
}

func (s *service) Verify(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return nil, nil
}

func isUserVerified(user *auth.User, err error) bool {
	return err == nil && user.IsVerified
}

func isUserNotVerified(user *auth.User, err error) bool {
	return err == nil && !user.IsVerified
}

func isUserNonExistent(user *auth.User, err error) bool {
	return err == sql.ErrNoRows && user == nil
}

func isOTPNotAllowed(err error) bool {
	return err != nil && err != sql.ErrNoRows
}
