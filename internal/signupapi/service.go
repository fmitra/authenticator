// Package signupapi provides an HTTP API for user registration.
package signupapi

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

type service struct {
	logger   log.Logger
	token    auth.TokenService
	repoMngr auth.RepositoryManager
	message  auth.MessagingService
	otp      auth.OTPService
}

// SignUp is the initial registration step to create a new User.
func (s *service) SignUp(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()

	req, err := decodeSignupRequest(r)
	if err != nil {
		return nil, err
	}

	newUser := req.ToUser()
	user, err := s.repoMngr.User().ByIdentity(ctx, req.UserAttribute(), req.Identity)

	if isUserCheckFailed(err) {
		return nil, errors.Wrap(err, "failed to check user identity")
	}

	if isUserVerified(user, err) {
		// TODO To prevent user enumeration this should trigger
		// the OTP step for password reset instead of the signup OTP
		// step. Until password reset has been implemented, we will just
		// return a general error.
		return nil, auth.ErrBadRequest("cannot register user")
	}

	if isUserNotVerified(user, err) {
		err = s.reCreateUser(ctx, user.ID, newUser)
	}

	if isUserNonExistent(user, err) {
		err = s.createUser(ctx, newUser)
	}

	if err != nil {
		return nil, err
	}

	jwtToken, err := s.token.Create(ctx, newUser, auth.JWTPreAuthorized)
	if err != nil {
		return nil, err
	}

	return s.respond(ctx, w, newUser, jwtToken)
}

// Verify is the final registration step to validate a new User's authenticity.
func (s *service) Verify(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)
	token := httpapi.GetToken(r)

	req, err := decodeSignupVerifyRequest(r)
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

	if err = s.markUserVerified(ctx, user); err != nil {
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

// reCreateUser re-creates the account of a non verified user. A user
// may have started the registration process and fell off before verifying
// ownership of the account (eg user decided they did not want to input OTP
// and left). This user should be reset (rehash credentials, regenerate timestamp,
// and ID) and allowed to restart the signup flow again.
func (s *service) reCreateUser(ctx context.Context, userID string, newUser *auth.User) error {
	client, err := s.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return err
	}

	entity, err := client.WithAtomic(func() (interface{}, error) {
		user, err := client.User().GetForUpdate(ctx, userID)
		if err != nil {
			return nil, err
		}

		if user.IsVerified {
			return nil, auth.ErrBadRequest("cannot register user")
		}

		user.Email = newUser.Email
		user.Phone = newUser.Phone
		user.Password = newUser.Password

		if err = client.User().ReCreate(ctx, user); err != nil {
			return nil, errors.Wrap(err, "cannot re-create user")
		}

		return user, nil
	})
	if err != nil {
		return err
	}

	*newUser = *entity.(*auth.User)

	return nil
}

// createUser creates a new User based on details in a signupRequest.
func (s *service) createUser(ctx context.Context, newUser *auth.User) error {
	return s.repoMngr.User().Create(ctx, newUser)
}

// respond creates a JWT token response.
func (s *service) respond(ctx context.Context, w http.ResponseWriter, user *auth.User, jwtToken *auth.Token) ([]byte, error) {
	tokenStr, err := s.token.Sign(ctx, jwtToken)
	if err != nil {
		return nil, err
	}

	http.SetCookie(w, s.token.Cookie(ctx, jwtToken))

	if jwtToken.Code != "" {
		// Enable in config.json: api.debug
		level.Debug(s.logger).Log(
			"source", "SignUp.respond",
			"message", "signup code generated",
			"code", jwtToken.Code,
			"user_id", user.ID,
			"email", user.Email.String,
			"phone", user.Phone.String,
		)

		if err = s.message.Send(ctx, user, jwtToken.Code); err != nil {
			return nil, err
		}
	}

	return []byte(fmt.Sprintf(`
		{"token": "%s", "clientID": "%s"}
	`, tokenStr, jwtToken.ClientID)), nil
}

func (s *service) markUserVerified(ctx context.Context, user *auth.User) error {
	client, err := s.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to start transaction")
	}

	entity, err := client.WithAtomic(func() (interface{}, error) {
		user, err := client.User().GetForUpdate(ctx, user.ID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get user for update")
		}

		user.IsVerified = true
		if err = client.User().Update(ctx, user); err != nil {
			return nil, errors.Wrap(err, "failed to save verified user")
		}

		return user, nil
	})
	if err != nil {
		return err
	}
	user = entity.(*auth.User)
	return nil
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

func isUserCheckFailed(err error) bool {
	return err != nil && err != sql.ErrNoRows
}
