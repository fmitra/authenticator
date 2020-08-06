// Package deviceapi provides an HTTP API for device registration.
package deviceapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-kit/kit/log"

	auth "github.com/fmitra/authenticator"
	"github.com/fmitra/authenticator/internal/httpapi"
	tokenLib "github.com/fmitra/authenticator/internal/token"
)

type service struct {
	logger   log.Logger
	webauthn auth.WebAuthnService
	repoMngr auth.RepositoryManager
	token    auth.TokenService
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

	token := httpapi.GetToken(r)
	token, err = s.token.Create(
		ctx,
		user,
		auth.JWTAuthorized,
		tokenLib.WithRefreshableToken(token),
	)
	if err != nil {
		return nil, err
	}

	signedToken, err := s.token.Sign(ctx, token)
	if err != nil {
		return nil, err
	}

	return &tokenLib.Response{Token: signedToken}, nil
}

// Remove removes a Device associated with a User.
func (s *service) Remove(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)
	deviceID := strings.TrimPrefix(r.URL.Path, "/api/v1/device/")

	devices, err := s.repoMngr.Device().ByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if len(devices) == 0 {
		return nil, auth.ErrBadRequest("no devices found")
	}

	txClient, err := s.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return nil, err
	}

	entity, err := txClient.WithAtomic(func() (interface{}, error) {
		user, err := txClient.User().GetForUpdate(ctx, userID)
		if err != nil {
			return nil, err
		}

		isDeviceAllowed := len(devices) > 1
		if err = txClient.Device().Remove(ctx, deviceID, userID); err != nil {
			return nil, err
		}

		user.IsDeviceAllowed = isDeviceAllowed
		if err = txClient.User().Update(ctx, user); err != nil {
			return nil, err
		}

		return user, err
	})
	if err != nil {
		return nil, err
	}

	user := entity.(*auth.User)
	token := httpapi.GetToken(r)

	token, err = s.token.Create(
		ctx,
		user,
		auth.JWTAuthorized,
		tokenLib.WithRefreshableToken(token),
	)
	if err != nil {
		return nil, err
	}

	signedToken, err := s.token.Sign(ctx, token)
	if err != nil {
		return nil, err
	}

	return &tokenLib.Response{Token: signedToken}, nil
}

// List returns all active devices for a user.
func (s *service) List(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	userID := httpapi.GetUserID(r)

	devices, err := s.repoMngr.Device().ByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user devices: %w", err)
	}

	resp := &listResponse{}
	resp.Create(devices)
	return resp, nil
}

// Rename renames a Device for a user.
func (s *service) Rename(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	deviceID := strings.TrimPrefix(r.URL.Path, "/api/v1/device/")

	req, err := decodeRenameRequest(r)
	if err != nil {
		return nil, err
	}

	_, err = s.repoMngr.Device().ByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, auth.ErrBadRequest("device does not exist"))
	}

	client, err := s.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot start txn: %w", err)
	}

	entity, err := client.WithAtomic(func() (interface{}, error) {
		device, err := client.Device().GetForUpdate(ctx, deviceID)
		if err != nil {
			return nil, fmt.Errorf("cannot retrieve device: %w", err)
		}

		device.Name = req.Name
		err = client.Device().Update(ctx, device)
		if err != nil {
			return nil, fmt.Errorf("device update failed: %w", err)
		}

		return device, nil
	})
	if err != nil {
		return nil, err
	}

	device := entity.(*auth.Device)
	resp := &singleResponse{}
	resp.Create(device)

	return resp, nil
}
