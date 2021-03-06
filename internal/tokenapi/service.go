// Package tokenapi provides an HTTP API for managing JWT tokens.
package tokenapi

import (
	"database/sql"
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
	token    auth.TokenService
	repoMngr auth.RepositoryManager
}

// Revoke revokes a User's token for a logged in session. Revoked tokens may not be
// refreshed.
func (s *service) Revoke(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	tokenID := strings.TrimPrefix(r.URL.Path, "/api/v1/token/")
	if err := s.token.Revoke(ctx, tokenID); err != nil {
		return nil, err
	}

	return &Response{Result: "success"}, nil
}

// Verify check's if a User's header credentials (token and matching client ID) are valid.
func (s *service) Verify(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return &Response{Result: "success"}, nil
}

// Refresh refreshes an expired token with a new expiry time. Refresh tokens share
// a token's original ID and client ID.
func (s *service) Refresh(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	ctx := r.Context()
	token := httpapi.GetToken(r)
	refreshToken := httpapi.GetRefreshToken(r)
	if err := s.token.Refreshable(ctx, token, refreshToken); err != nil {
		return nil, err
	}

	userID := httpapi.GetUserID(r)
	user, err := s.repoMngr.User().ByIdentity(ctx, "ID", userID)
	if err != nil {
		return nil, err
	}

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

	tx, err := s.repoMngr.NewWithTransaction(ctx)
	if err != nil {
		return nil, err
	}

	_, err = tx.WithAtomic(func() (interface{}, error) {
		lh, err := tx.LoginHistory().GetForUpdate(ctx, httpapi.GetToken(r).Id)
		if err != nil {
			return nil, err
		}

		lh.IPAddress = sql.NullString{
			String: httpapi.GetIP(r),
			Valid:  true,
		}
		if err = tx.LoginHistory().Update(ctx, lh); err != nil {
			return nil, err
		}

		return lh, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update login history record: %w", err)
	}

	return &tokenLib.Response{Token: signedToken}, nil
}
