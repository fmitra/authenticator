// Package totpapi provides an HTTP API for TOTP management.
package totpapi

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
)

type service struct {
	logger   log.Logger
	otp      auth.OTPService
	repoMngr auth.RepositoryManager
}

func (s *service) Secret(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	if user.IsTOTPAllowed {
		return nil, auth.ErrBadRequest("totp is already configured")
	}

	client, err := s.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return nil, err
	}

	entity, err := client.WithAtomic(func() (interface{}, error) {
		user, err := client.User().GetForUpdate(ctx, userID)
		if err != nil {
			return nil, err
		}

		secret, err := s.otp.TOTPSecret(user)
		if err != nil {
			return nil, err
		}

		user.TFASecret = secret
		if err = client.User().Update(ctx, user); err != nil {
			return nil, errors.Wrap(err, "cannot set tfa secret")
		}

		return user, nil
	})
	if err != nil {
		return nil, err
	}

	*user = *entity.(*auth.User)

	totpQRStr := s.otp.TOTPQRString(user)
	return []byte(fmt.Sprintf(`
		{"totp": "%s"}
	`, totpQRStr)), nil
}

func (s *service) Verify(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	if user.IsTOTPAllowed {
		return nil, auth.ErrBadRequest("totp is already configured")
	}

	isEnabled := true
	return s.configureTOTP(ctx, r, user, isEnabled)
}

func (s *service) Remove(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

	if !user.IsTOTPAllowed {
		return nil, auth.ErrBadRequest("totp is not enabled")
	}

	isEnabled := false
	return s.configureTOTP(ctx, r, user, isEnabled)
}

func (s *service) configureTOTP(ctx context.Context, r *http.Request, user *auth.User, isEnabled bool) (interface{}, error) {
	req, err := decodeTOTPRequest(r)
	if err != nil {
		return nil, err
	}

	if err = s.otp.ValidateTOTP(user, req.Code); err != nil {
		return nil, err
	}

	client, err := s.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return nil, err
	}

	entity, err := client.WithAtomic(func() (interface{}, error) {
		user, err := client.User().GetForUpdate(ctx, user.ID)
		if err != nil {
			return nil, err
		}

		user.IsTOTPAllowed = isEnabled
		if err = client.User().Update(ctx, user); err != nil {
			return nil, errors.Wrap(err, "cannot update TOTP setting")
		}

		return user, nil
	})
	if err != nil {
		return nil, err
	}

	*user = *entity.(*auth.User)
	return []byte(`{}`), nil
}